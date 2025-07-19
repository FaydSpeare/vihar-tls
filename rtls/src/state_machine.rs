use std::collections::HashMap;

use enum_dispatch::enum_dispatch;
use log::{debug, info};
use sha2::{Digest, Sha256};

use crate::{
    alert::TLSAlert, ciphersuite::{get_cipher_suite, CipherSuiteMethods}, connection::{ConnState, InitialConnState, SecureConnState, SecurityParams}, messages::{
        handshake_bytes, ApplicationData, ChangeCipherSpec, ClientKeyExchange, Finished, TLSCiphertext, TLSHandshake, TLSHandshakeType, TlsMessage, ToBytes
    }, prf, TLSResult
};

fn client_verify_data(master_secret: &[u8], handshakes: &[u8]) -> Vec<u8> {
    let seed = Sha256::digest(handshakes).to_vec();
    prf::prf_sha256(&master_secret, b"client finished", &seed, 12)
}

fn server_verify_data(master_secret: &[u8], handshakes: &[u8]) -> Vec<u8> {
    let seed = Sha256::digest(handshakes).to_vec();
    prf::prf_sha256(&master_secret, b"server finished", &seed, 12)
}

#[derive(Debug, Clone)]
pub struct SessionInfo {
    cipher_suite: u16,
    master_secret: [u8; 48],
}

#[derive(Clone)]
pub struct TlsContext {
    pub sessions: HashMap<Vec<u8>, SessionInfo>,
}

pub struct TlsStateMachine {
    pub state: Option<TlsState>,
    pub ctx: TlsContext,
}

pub struct ConnStates {
    pub read: ConnState,
    pub write: ConnState,
}

impl ConnStates {
    pub fn new() -> Self {
        Self {
            read: ConnState::Initial(InitialConnState::default()),
            write: ConnState::Initial(InitialConnState::default()),
        }
    }
}

pub enum TlsAction {
    None,
    SendAlert(TLSAlert),
    SendCiphertexts(Vec<TLSCiphertext>),
}

impl TlsStateMachine {
    pub fn step(&mut self, cs: &mut ConnStates, msg: &TlsMessage) -> TLSResult<TlsAction> {
        let (new_state, action) = self.state.take().unwrap().handle(&mut self.ctx, cs, msg)?;
        self.state = Some(new_state);
        Ok(action)
    }

    pub fn new() -> Self {
        Self {
            ctx: TlsContext {
                sessions: HashMap::new(),
            },
            state: Some(AwaitingClientHelloState {}.into()),
        }
    }

    pub fn from_context(ctx: TlsContext) -> Self {
        Self {
            ctx,
            state: Some(AwaitingClientHelloState {}.into()),
        }
    }

    pub fn is_established(&self) -> bool {
        match self.state.as_ref().unwrap() {
            TlsState::Established(_) => true,
            _ => false,
        }
    }
}

// RequestCertificate optionally sent aftee ServerKeyExchange if present otherwise after ServerCeritificate
//

#[enum_dispatch]
#[derive(Debug)]
pub enum TlsState {
    AwaitingClientHello(AwaitingClientHelloState),
    AwaitingServerHello(AwaitingServerHelloState),
    AwaitingServerCertificate(AwaitingServerCertificateState),
    AwaitingServerHelloDone(AwaitingServerHelloDoneState),
    // AwaitingClientKeyExchange,
    // AwaitingClientChangeCipherSpec,
    // AwaitingClientFinished,
    AwaitingServerChangeCipher(AwaitingServerChangeCipherState),
    AwaitingServerFinished(AwaitingServerFinishedState),
    Established(EstablishedState),
    /*
    ServerHelloProcessed, // here we can accept any of the below 3
    // ServerCertificatesProcessed,
    // ServerKeyExchanged
    // ClientCertificateRequested
    ServerHelloDoneProcessed,
    // ClientCertificateProcessed
    ClientKeyExchanged, // this state would be skipped unless waiting for CertificateVerify
    // CeritificateVerifySent,
    //
    ReadyToChangeCipherSpec,

    ClientChangedCipherSpec,
    ClientFinished,
    ServerChangedCipherSpec,
    ServerFinished,

    ClientChangedCipherSpecAbbr,
    ClientFinishedAbbr,
    ServerChangedCipherSpecAbbr,
    ServerFinishedAbbr,

    Established
    */
}

impl TlsState {
    pub fn as_established(&self) -> TLSResult<&EstablishedState> {
        match self {
            Self::Established(s) => Ok(s),
            _ => Err("not in established state".into()),
        }
    }
}

#[enum_dispatch(TlsState)]
pub trait HandleRecord {
    fn handle(
        self,
        ctx: &mut TlsContext,
        cs: &mut ConnStates,
        msg: &TlsMessage,
    ) -> TLSResult<(TlsState, TlsAction)>;
}

#[derive(Debug)]
pub struct AwaitingClientHelloState {}

impl HandleRecord for AwaitingClientHelloState {
    fn handle(
        self,
        _ctx: &mut TlsContext,
        cs: &mut ConnStates,
        msg: &TlsMessage,
    ) -> TLSResult<(TlsState, TlsAction)> {
        if let TlsMessage::Handshake(TLSHandshake::ClientHello(hello)) = msg {
            info!("Sent ClientHello");

            let ch_ciphertext = cs.write.encrypt(hello.clone());

            return Ok((
                AwaitingServerHelloState {
                    handshakes: hello.to_bytes(),
                    client_random: hello.random.as_bytes(),
                    session_resumption: (!hello.session_id.is_empty()).then(|| {
                        let session_info = _ctx.sessions.get(&hello.session_id).unwrap();
                        ProposedSessionResumption {
                            master_secret: session_info.master_secret,
                            cipher_suite: session_info.cipher_suite,
                            session_id: hello.session_id.clone(),
                        }
                    }),
                }
                .into(),
                TlsAction::SendCiphertexts(vec![ch_ciphertext]),
            ));
        }
        panic!("invalid transition");
    }
}

#[derive(Debug)]
struct ProposedSessionResumption {
    master_secret: [u8; 48],
    session_id: Vec<u8>,
    cipher_suite: u16,
}

#[derive(Debug)]
struct AgreedSessionResumption {
    master_secret: [u8; 48],
    session_id: Vec<u8>,
    cipher_suite: u16,
    client_random: [u8; 32],
    server_random: [u8; 32],
}

#[derive(Debug)]
pub struct AwaitingServerHelloState {
    handshakes: Vec<u8>,
    client_random: [u8; 32],
    session_resumption: Option<ProposedSessionResumption>,
}

impl HandleRecord for AwaitingServerHelloState {
    fn handle(
        mut self,
        _ctx: &mut TlsContext,
        _cs: &mut ConnStates,
        msg: &TlsMessage,
    ) -> TLSResult<(TlsState, TlsAction)> {
        if let TlsMessage::Handshake(TLSHandshake::ServerHello(hello)) = msg {
            info!("Received ServerHello");
            self.handshakes.extend_from_slice(&hello.to_bytes());

            if self
                .session_resumption
                .as_ref()
                .map_or(false, |x| x.session_id == hello.session_id)
            {
                return Ok((
                    AwaitingServerChangeCipherState {
                        session_id: hello.session_id.clone(),
                        handshakes: self.handshakes,
                        secure_renegotiation: hello.supports_secure_renegotiation(),
                        client_verify_data: vec![],
                        session_resumption: Some(AgreedSessionResumption {
                            master_secret: self.session_resumption.as_ref().unwrap().master_secret,
                            cipher_suite: self.session_resumption.as_ref().unwrap().cipher_suite,
                            session_id: self.session_resumption.unwrap().session_id,
                            client_random: self.client_random,
                            server_random: hello.random.as_bytes(),
                        }),
                    }
                    .into(),
                    TlsAction::None,
                ));
            }

            debug!("Selected CipherSuite: {}", hello.cipher_suite.params().name);
            return Ok((
                AwaitingServerCertificateState {
                    session_id: hello.session_id.clone(),
                    handshakes: self.handshakes,
                    client_random: self.client_random,
                    server_random: hello.random.as_bytes(),
                    secure_renegotiation: hello.supports_secure_renegotiation(),
                    cipher_suite: hello.cipher_suite.encode(),
                }
                .into(),
                TlsAction::None,
            ));
        }
        panic!("invalid transition");
    }
}

#[derive(Debug)]
pub struct AwaitingServerCertificateState {
    session_id: Vec<u8>,
    handshakes: Vec<u8>,
    client_random: [u8; 32],
    server_random: [u8; 32],
    cipher_suite: [u8; 2],
    secure_renegotiation: bool,
}

impl HandleRecord for AwaitingServerCertificateState {
    fn handle(
        mut self,
        _ctx: &mut TlsContext,
        _cs: &mut ConnStates,
        msg: &TlsMessage,
    ) -> TLSResult<(TlsState, TlsAction)> {
        if let TlsMessage::Handshake(TLSHandshake::Certificates(certs)) = msg {
            info!("Received ServerCertificate");

            let (pre_master_secret, enc_pre_master_secret) =
                crate::encrypt_pre_master_secret(&certs.list[0].bytes)?;

            let master_secret: [u8; 48] = crate::prf::prf_sha256(
                &pre_master_secret,
                b"master secret",
                &[self.client_random.as_slice(), self.server_random.as_slice()].concat(),
                48,
            )
            .try_into()
            .unwrap();

            self.handshakes.extend_from_slice(&certs.to_bytes());
            return Ok((
                AwaitingServerHelloDoneState {
                    session_id: self.session_id,
                    handshakes: self.handshakes,
                    master_secret,
                    enc_pre_master_secret,
                    client_random: self.client_random,
                    server_random: self.server_random,
                    secure_renegotiation: self.secure_renegotiation,
                    cipher_suite: self.cipher_suite,
                }
                .into(),
                TlsAction::None,
            ));
        }
        panic!("invalid transition");
    }
}

#[derive(Debug)]
pub struct AwaitingServerHelloDoneState {
    session_id: Vec<u8>,
    handshakes: Vec<u8>,
    client_random: [u8; 32],
    server_random: [u8; 32],
    cipher_suite: [u8; 2],
    secure_renegotiation: bool,
    master_secret: [u8; 48],
    enc_pre_master_secret: Vec<u8>,
}

impl HandleRecord for AwaitingServerHelloDoneState {
    fn handle(
        mut self,
        _ctx: &mut TlsContext,
        cs: &mut ConnStates,
        msg: &TlsMessage,
    ) -> TLSResult<(TlsState, TlsAction)> {
        if let TlsMessage::Handshake(TLSHandshake::ServerHelloDone) = msg {
            info!("Received ServerHelloDone");

            self.handshakes
                .extend_from_slice(&handshake_bytes(TLSHandshakeType::ServerHelloDone, &[]));

            let client_key_exchange = ClientKeyExchange::new(&self.enc_pre_master_secret);
            self.handshakes
                .extend_from_slice(&client_key_exchange.to_bytes());
            let cke_ciphertext = cs.write.encrypt(client_key_exchange);

            let change_cipher_spec = ChangeCipherSpec::new();
            let ccs_ciphertext = cs.write.encrypt(change_cipher_spec);

            let ciphersuite = get_cipher_suite(u16::from_be_bytes(self.cipher_suite))?;
            let params = SecurityParams {
                cipher_suite_id: u16::from_be_bytes(self.cipher_suite),
                client_random: self.client_random,
                server_random: self.server_random,
                master_secret: self.master_secret,
                mac_algorithm: ciphersuite.params().mac_algorithm,
                enc_algorithm: ciphersuite.params().enc_algorithm,
            };
            let keys = params.derive_keys();
            cs.write = ConnState::Secure(SecureConnState::new(
                params,
                keys.client_enc_key,
                keys.client_mac_key,
            ));

            let verify_data = client_verify_data(&self.master_secret, &self.handshakes);
            let finished = Finished::new(verify_data.clone());
            self.handshakes.extend_from_slice(&finished.to_bytes());
            let f_ciphertext = cs.write.encrypt(finished);

            info!("Sent ClientKeyExchange");
            info!("Sent ChangeCipherSuite");
            info!("Sent ClientFinished");
            return Ok((
                AwaitingServerChangeCipherState {
                    session_id: self.session_id,
                    handshakes: self.handshakes,
                    secure_renegotiation: self.secure_renegotiation,
                    client_verify_data: verify_data,
                    session_resumption: None,
                }
                .into(),
                TlsAction::SendCiphertexts(vec![cke_ciphertext, ccs_ciphertext, f_ciphertext]),
            ));
        }
        panic!("invalid transition");
    }
}
#[derive(Debug)]
pub struct AwaitingServerChangeCipherState {
    session_id: Vec<u8>,
    handshakes: Vec<u8>,
    secure_renegotiation: bool,
    client_verify_data: Vec<u8>,
    session_resumption: Option<AgreedSessionResumption>,
}

impl HandleRecord for AwaitingServerChangeCipherState {
    fn handle(
        self,
        _ctx: &mut TlsContext,
        cs: &mut ConnStates,
        msg: &TlsMessage,
    ) -> TLSResult<(TlsState, TlsAction)> {
        if let TlsMessage::ChangeCipherSpec = msg {
            info!("Received ChangeCipherSpec");

            match &self.session_resumption {
                None => {
                    let write = cs.write.as_secure()?;
                    let keys = write.params.derive_keys();
                    cs.read = ConnState::Secure(SecureConnState::new(
                        write.params.clone(),
                        keys.server_enc_key,
                        keys.server_mac_key,
                    ));

                    return Ok((
                        AwaitingServerFinishedState {
                            session_id: self.session_id,
                            handshakes: self.handshakes,
                            secure_renegotiation: self.secure_renegotiation,
                            client_verify_data: self.client_verify_data,
                            session_resumption: None,
                        }
                        .into(),
                        TlsAction::None,
                    ));
                }
                Some(resumption) => {
                    let ciphersuite = get_cipher_suite(resumption.cipher_suite)?;
                    let params = SecurityParams {
                        cipher_suite_id: resumption.cipher_suite,
                        client_random: resumption.client_random,
                        server_random: resumption.server_random,
                        enc_algorithm: ciphersuite.params().enc_algorithm,
                        mac_algorithm: ciphersuite.params().mac_algorithm,
                        master_secret: resumption.master_secret,
                    };
                    let keys = params.derive_keys();

                    cs.read = ConnState::Secure(SecureConnState::new(
                        params.clone(),
                        keys.server_enc_key,
                        keys.server_mac_key,
                    ));

                    return Ok((
                        AwaitingServerFinishedState {
                            session_id: self.session_id,
                            handshakes: self.handshakes,
                            secure_renegotiation: self.secure_renegotiation,
                            client_verify_data: self.client_verify_data,
                            session_resumption: self.session_resumption,
                        }
                        .into(),
                        TlsAction::None,
                    ));
                }
            }
        }
        panic!("invalid transition");
    }
}

#[derive(Debug)]
pub struct AwaitingServerFinishedState {
    session_id: Vec<u8>,
    handshakes: Vec<u8>,
    secure_renegotiation: bool,
    client_verify_data: Vec<u8>,
    session_resumption: Option<AgreedSessionResumption>,
}

impl HandleRecord for AwaitingServerFinishedState {
    fn handle(
        mut self,
        ctx: &mut TlsContext,
        cs: &mut ConnStates,
        msg: &TlsMessage,
    ) -> TLSResult<(TlsState, TlsAction)> {
        if let TlsMessage::Handshake(TLSHandshake::Finished(finished)) = msg {
            info!("Received ServerFinished");
            let read = cs.read.as_secure()?;

            let verify_data = server_verify_data(&read.params.master_secret, &self.handshakes);
            assert_eq!(verify_data, finished.verify_data);
            self.handshakes.extend_from_slice(&finished.to_bytes());

            match self.session_resumption {
                None => {
                    info!("Handshake complete! (full)");

                    ctx.sessions.insert(
                        self.session_id.clone(),
                        SessionInfo {
                            master_secret: read.params.master_secret,
                            cipher_suite: read.params.cipher_suite_id,
                        },
                    );

                    return Ok((
                        EstablishedState {
                            session_id: self.session_id,
                            secure_renegotiation: self.secure_renegotiation,
                            client_verify_data: self.client_verify_data,
                        }
                        .into(),
                        TlsAction::None,
                    ));
                }
                Some(_) => {
                    let ccs_ciphertext = cs.write.encrypt(ChangeCipherSpec::new());

                    let params = &cs.read.as_secure()?.params;
                    let keys = params.derive_keys();
                    cs.write = ConnState::Secure(SecureConnState::new(
                        params.clone(),
                        keys.client_enc_key,
                        keys.client_mac_key,
                    ));

                    let verify_data = client_verify_data(&read.params.master_secret, &self.handshakes);
                    let finished = Finished::new(verify_data);
                    let cf_ciphertext = cs.write.encrypt(finished);

                    info!("Sent ChangeCipherSpec");
                    info!("Sent ClientFinished");
                    info!("Handshake complete! (abbreviated)");
                    return Ok((
                        EstablishedState {
                            session_id: self.session_id,
                            secure_renegotiation: self.secure_renegotiation,
                            client_verify_data: self.client_verify_data,
                        }
                        .into(),
                        TlsAction::SendCiphertexts(vec![ccs_ciphertext, cf_ciphertext]),
                    ));
                }
            }
        }
        panic!("invalid transition");
    }
}

#[derive(Debug)]
pub struct EstablishedState {
    pub session_id: Vec<u8>,
    secure_renegotiation: bool,
    pub client_verify_data: Vec<u8>,
}

impl HandleRecord for EstablishedState {
    fn handle(
        self,
        _ctx: &mut TlsContext,
        cs: &mut ConnStates,
        msg: &TlsMessage,
    ) -> TLSResult<(TlsState, TlsAction)> {
        // if let TlsMessage::ApplicationData(bytes) = msg {
        //     let app_data = ApplicationData::new(bytes.clone());
        //     let ciphertext = cs.write.encrypt(app_data);
        //     return Ok((self.into(), TlsAction::SendCiphertexts(vec![ciphertext])));
        // }

        if let TlsMessage::Handshake(TLSHandshake::ClientHello(hello)) = msg {
            let ch_ciphertext = cs.write.encrypt(hello.clone());
            return Ok((
                AwaitingServerHelloState {
                    handshakes: hello.to_bytes(),
                    client_random: hello.random.as_bytes(),
                    session_resumption: None,
                }
                .into(),
                TlsAction::SendCiphertexts(vec![ch_ciphertext])
            ));
        }
        panic!("invalid transition");
    }
}
