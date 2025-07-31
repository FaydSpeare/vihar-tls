use rsa::{RsaPublicKey, pkcs8::DecodePublicKey};
use std::collections::HashMap;

use enum_dispatch::enum_dispatch;
use log::{debug, info};

use crate::ciphersuite::PrfAlgorithm;
use crate::extensions::{HashAlgo, SigAlgo};
use crate::signature::{
    dsa_verify, get_dhe_pre_master_secret, get_rsa_pre_master_secret, public_key_from_cert,
    rsa_verify,
};
use crate::{
    TLSResult,
    alert::TLSAlert,
    ciphersuite::{CipherSuite, CipherSuiteMethods, KeyExchangeAlgorithm},
    connection::{ConnState, InitialConnState, SecureConnState, SecurityParams},
    messages::{
        ChangeCipherSpec, ClientKeyExchange, Finished, TLSHandshake, TLSHandshakeType,
        TLSPlaintext, TlsMessage, ToBytes, handshake_bytes,
    },
};

#[derive(Debug, Clone)]
pub struct SessionInfo {
    cipher_suite: u16,
    master_secret: [u8; 48],
}

#[derive(Debug, Clone)]
pub struct SessionTicketInfo {
    cipher_suite: u16,
    master_secret: [u8; 48],
}

#[derive(Debug, Clone)]
pub struct TlsContext {
    pub sessions: HashMap<Vec<u8>, SessionInfo>,
    pub session_tickets: HashMap<Vec<u8>, SessionTicketInfo>,
}

pub struct TlsHandshakeStateMachine {
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

pub enum TlsEntity {
    Client,
    Server,
}

pub enum TlsAction {
    SendAlert(TLSAlert),
    ChangeCipherSpec(TlsEntity, ConnState),
    SendPlaintext(TLSPlaintext),
}

impl TlsHandshakeStateMachine {
    pub fn transition(&mut self, msg: &TlsMessage) -> TLSResult<Vec<TlsAction>> {
        let (new_state, action) = self.state.take().unwrap().handle(&mut self.ctx, msg)?;
        self.state = Some(new_state);
        Ok(action)
    }

    pub fn new() -> Self {
        Self {
            ctx: TlsContext {
                sessions: HashMap::new(),
                session_tickets: HashMap::new(),
            },
            state: Some(AwaitClientHello {}.into()),
        }
    }

    pub fn from_context(ctx: TlsContext) -> Self {
        Self {
            ctx,
            state: Some(AwaitClientHello {}.into()),
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
    AwaitClientHello,
    AwaitServerHello(AwaitServerHello),
    AwaitServerCertificate(AwaitServerCertificate),
    AwaitServerKeyExchange(AwaitServerKeyExchange),
    AwaitServerHelloDone(AwaitServerHelloDone),
    AwaitNewSessionTicket(AwaitNewSessionTicket),
    AwaitNewSessionTicketOrCertificate,
    AwaitServerChangeCipherOrCertificate,
    AwaitServerChangeCipher(AwaitServerChangeCipher),
    AwaitServerFinished(AwaitServerFinished),
    Established(EstablishedState),
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
        msg: &TlsMessage,
    ) -> TLSResult<(TlsState, Vec<TlsAction>)>;
}

#[derive(Debug)]
pub struct AwaitClientHello {}

impl HandleRecord for AwaitClientHello {
    fn handle(
        self,
        _ctx: &mut TlsContext,
        msg: &TlsMessage,
    ) -> TLSResult<(TlsState, Vec<TlsAction>)> {
        if let TlsMessage::Handshake(TLSHandshake::ClientHello(hello)) = msg {
            info!("Sent ClientHello");

            return Ok((
                AwaitServerHello {
                    handshakes: hello.to_bytes(),
                    client_random: hello.random.as_bytes(),
                    session_id_resumption: (!hello.session_id.is_empty()).then(|| {
                        let session_info = _ctx.sessions.get(&hello.session_id).unwrap();
                        SessionIdResumption {
                            master_secret: session_info.master_secret,
                            cipher_suite: session_info.cipher_suite,
                            session_id: hello.session_id.clone(),
                        }
                    }),
                    session_ticket_resumption: hello
                        .session_ticket()
                        .and_then(|ticket| _ctx.session_tickets.get(&ticket).cloned()),
                }
                .into(),
                vec![TlsAction::SendPlaintext(hello.clone().into())],
            ));
        }
        panic!("invalid transition");
    }
}

#[derive(Debug)]
struct SessionIdResumption {
    session_id: Vec<u8>,
    master_secret: [u8; 48],
    cipher_suite: u16,
}

#[derive(Debug)]
struct SupportedExtensions {
    extended_master_secret: bool,
    secure_renegotiation: bool,
    session_ticket: bool,
}

#[derive(Debug)]
pub struct AwaitServerHello {
    handshakes: Vec<u8>,
    client_random: [u8; 32],
    session_id_resumption: Option<SessionIdResumption>,
    session_ticket_resumption: Option<SessionTicketInfo>,
}

impl HandleRecord for AwaitServerHello {
    fn handle(
        mut self,
        _ctx: &mut TlsContext,
        msg: &TlsMessage,
    ) -> TLSResult<(TlsState, Vec<TlsAction>)> {
        if let TlsMessage::Handshake(TLSHandshake::ServerHello(hello)) = msg {
            info!("Received ServerHello");
            self.handshakes.extend_from_slice(&hello.to_bytes());

            let selected_cipher_suite_id = hello.cipher_suite.encode();
            let supported_extensions = SupportedExtensions {
                secure_renegotiation: hello.supports_secure_renegotiation(),
                extended_master_secret: hello.supports_extended_master_secret(),
                session_ticket: hello.supports_session_ticket(),
            };

            // If the server echoed back the session-id sent by the client we're
            // now doing an abbreviated handshake.
            if self
                .session_id_resumption
                .as_ref()
                .map_or(false, |x| x.session_id == hello.session_id)
            {
                let resumption = self.session_id_resumption.unwrap();
                let ciphersuite = CipherSuite::from_u16(resumption.cipher_suite)?;
                let params = SecurityParams {
                    cipher_suite_id: resumption.cipher_suite,
                    client_random: self.client_random,
                    server_random: hello.random.as_bytes(),
                    enc_algorithm: ciphersuite.params().enc_algorithm,
                    mac_algorithm: ciphersuite.params().mac_algorithm,
                    prf_algorithm: ciphersuite.params().prf_algorithm,
                    master_secret: resumption.master_secret,
                };

                return Ok((
                    AwaitServerChangeCipher {
                        session_id: hello.session_id.clone(),
                        handshakes: self.handshakes,
                        supported_extensions,
                        params,
                        client_verify_data: None,
                        is_session_resumption: true,
                    }
                    .into(),
                    vec![],
                ));
            }

            // Attempting session resumption with session-ticket
            if let Some(resumption) = self.session_ticket_resumption {
                // Server will issue a new ticket, but did it accept the session ticket we sent?
                if hello.supports_session_ticket() {
                    // We can only tell if the session ticket was accepted by the
                    // server based on what it sends next. It either:
                    //
                    // (1) rejects the session ticket, but will issue a new session ticket
                    // later. For now it will proceed with a full handshake.
                    //
                    // (2) accepts the session ticket, as well as issue a new session ticket.
                    //
                    return Ok((
                        AwaitNewSessionTicketOrCertificate {
                            session_id: hello.session_id.clone(),
                            handshakes: self.handshakes,
                            client_random: self.client_random,
                            server_random: hello.random.as_bytes(),
                            selected_cipher_suite_id,
                            supported_extensions,
                            session_ticket_resumption: resumption,
                        }
                        .into(),
                        vec![],
                    ));
                }

                // We can only tell if the session ticket was accepted by the
                // server based on what it sends next. It either:
                //
                // (1) rejects the session ticket, and won't issue a new session ticket
                // and thus will proceed with a full handshake.
                //
                // (2) accepts the session ticket, and won't issue a new session ticket.
                //
                return Ok((
                    AwaitServerChangeCipherOrCertificate {
                        session_id: hello.session_id.clone(),
                        client_random: self.client_random,
                        server_random: hello.random.as_bytes(),
                        selected_cipher_suite_id,
                        supported_extensions,
                        handshakes: self.handshakes,
                        session_ticket_resumption: resumption,
                    }
                    .into(),
                    vec![],
                ));
            }

            // Boring... no session resumption, we're doing a full handshake.
            debug!("Selected CipherSuite: {}", hello.cipher_suite.params().name);
            return Ok((
                AwaitServerCertificate {
                    session_id: hello.session_id.clone(),
                    handshakes: self.handshakes,
                    client_random: self.client_random,
                    server_random: hello.random.as_bytes(),
                    selected_cipher_suite_id,
                    supported_extensions,
                }
                .into(),
                vec![],
            ));
        }
        panic!("invalid transition");
    }
}

#[derive(Debug)]
pub struct AwaitServerCertificate {
    session_id: Vec<u8>,
    handshakes: Vec<u8>,
    client_random: [u8; 32],
    server_random: [u8; 32],
    selected_cipher_suite_id: u16,
    supported_extensions: SupportedExtensions,
}

impl HandleRecord for AwaitServerCertificate {
    fn handle(
        mut self,
        _ctx: &mut TlsContext,
        msg: &TlsMessage,
    ) -> TLSResult<(TlsState, Vec<TlsAction>)> {
        if let TlsMessage::Handshake(TLSHandshake::Certificates(certs)) = msg {
            info!("Received ServerCertificate");

            let server_public_key = public_key_from_cert(&certs.list[0].bytes)?;
            self.handshakes.extend_from_slice(&certs.to_bytes());

            let cipher_suite = CipherSuite::from_u16(self.selected_cipher_suite_id)?;
            match cipher_suite.params().key_exchange_algorithm {
                KeyExchangeAlgorithm::DheRsa | KeyExchangeAlgorithm::DheDss => {
                    return Ok((
                        AwaitServerKeyExchange {
                            session_id: self.session_id,
                            handshakes: self.handshakes,
                            client_random: self.client_random,
                            server_random: self.server_random,
                            selected_cipher_suite_id: self.selected_cipher_suite_id,
                            supported_extensions: self.supported_extensions,
                            server_public_key,
                        }
                        .into(),
                        vec![],
                    ));
                }
                _ => {}
            }

            return Ok((
                AwaitServerHelloDone {
                    session_id: self.session_id,
                    handshakes: self.handshakes,
                    client_random: self.client_random,
                    server_random: self.server_random,
                    selected_cipher_suite_id: self.selected_cipher_suite_id,
                    supported_extensions: self.supported_extensions,
                    server_public_key,
                    secrets: None,
                }
                .into(),
                vec![],
            ));
        }
        panic!("invalid transition");
    }
}

#[derive(Debug)]
pub struct AwaitServerKeyExchange {
    session_id: Vec<u8>,
    handshakes: Vec<u8>,
    client_random: [u8; 32],
    server_random: [u8; 32],
    selected_cipher_suite_id: u16,
    supported_extensions: SupportedExtensions,
    server_public_key: Vec<u8>,
}

impl HandleRecord for AwaitServerKeyExchange {
    fn handle(
        mut self,
        _ctx: &mut TlsContext,
        msg: &TlsMessage,
    ) -> TLSResult<(TlsState, Vec<TlsAction>)> {
        if let TlsMessage::Handshake(TLSHandshake::ServerKeyExchange(kx)) = msg {
            info!("Received ServerKeyExchange");

            let verified = match kx.sig_algo {
                SigAlgo::Rsa => {
                    let rsa_public_key =
                        RsaPublicKey::from_public_key_der(&self.server_public_key)?;
                    rsa_verify(
                        &rsa_public_key,
                        &[
                            self.client_random.as_ref(),
                            self.server_random.as_ref(),
                            &kx.dh_params_bytes(),
                        ]
                        .concat(),
                        &kx.signature,
                    )?
                }
                SigAlgo::Dsa => {
                    assert_eq!(kx.hash_algo, HashAlgo::Sha256);
                    dsa_verify(
                        &self.server_public_key,
                        &[
                            self.client_random.as_ref(),
                            self.server_random.as_ref(),
                            &kx.dh_params_bytes(),
                        ]
                        .concat(),
                        &kx.signature,
                    )?
                }
                _ => unimplemented!(),
            };
            assert!(verified, "Invalid ServerKeyExchange signature");

            self.handshakes.extend_from_slice(&kx.to_bytes());
            return Ok((
                AwaitServerHelloDone {
                    session_id: self.session_id,
                    handshakes: self.handshakes,
                    client_random: self.client_random,
                    server_random: self.server_random,
                    selected_cipher_suite_id: self.selected_cipher_suite_id,
                    supported_extensions: self.supported_extensions,
                    server_public_key: self.server_public_key,
                    secrets: Some(DheParams {
                        p: kx.p.clone(),
                        g: kx.g.clone(),
                        public_key: kx.server_pubkey.clone(),
                    }),
                }
                .into(),
                vec![],
            ));
        }
        panic!("invalid transition");
    }
}

#[derive(Debug)]
struct DheParams {
    p: Vec<u8>,
    g: Vec<u8>,
    public_key: Vec<u8>,
}

#[derive(Debug)]
pub struct AwaitServerHelloDone {
    session_id: Vec<u8>,
    handshakes: Vec<u8>,
    client_random: [u8; 32],
    server_random: [u8; 32],
    selected_cipher_suite_id: u16,
    supported_extensions: SupportedExtensions,
    server_public_key: Vec<u8>,
    secrets: Option<DheParams>,
}

impl HandleRecord for AwaitServerHelloDone {
    fn handle(
        mut self,
        _ctx: &mut TlsContext,
        msg: &TlsMessage,
    ) -> TLSResult<(TlsState, Vec<TlsAction>)> {
        if let TlsMessage::Handshake(TLSHandshake::ServerHelloDone) = msg {
            info!("Received ServerHelloDone");

            self.handshakes
                .extend_from_slice(&handshake_bytes(TLSHandshakeType::ServerHelloDone, &[]));

            let ciphersuite = CipherSuite::from_u16(self.selected_cipher_suite_id)?;
            let (pre_master_secret, key_exchange_data) =
                match ciphersuite.params().key_exchange_algorithm {
                    KeyExchangeAlgorithm::Rsa => {
                        let rsa_public_key =
                            RsaPublicKey::from_public_key_der(&self.server_public_key)?;
                        get_rsa_pre_master_secret(&rsa_public_key)?
                    }
                    KeyExchangeAlgorithm::DheRsa | KeyExchangeAlgorithm::DheDss => {
                        let DheParams { p, g, public_key } = self.secrets.as_ref().unwrap();
                        get_dhe_pre_master_secret(p, g, public_key)
                    },
                    KeyExchangeAlgorithm::EcdheRsa => unimplemented!(),
                };

            let client_key_exchange = ClientKeyExchange::new(&key_exchange_data);
            self.handshakes
                .extend_from_slice(&client_key_exchange.to_bytes());

            let change_cipher_spec = ChangeCipherSpec::new();

            let master_secret = self
                .calculate_master_secret(&pre_master_secret, ciphersuite.params().prf_algorithm);
            let params = SecurityParams {
                cipher_suite_id: self.selected_cipher_suite_id,
                client_random: self.client_random,
                server_random: self.server_random,
                master_secret,
                mac_algorithm: ciphersuite.params().mac_algorithm,
                enc_algorithm: ciphersuite.params().enc_algorithm,
                prf_algorithm: ciphersuite.params().prf_algorithm,
            };
            let keys = params.derive_keys();
            let write = ConnState::Secure(SecureConnState::new(
                params.clone(),
                keys.client_enc_key,
                keys.client_mac_key,
                keys.client_write_iv,
            ));

            let verify_data = params.client_verify_data(&self.handshakes);
            let client_finished = Finished::new(verify_data.clone());
            self.handshakes
                .extend_from_slice(&client_finished.to_bytes());

            info!("Sent ClientKeyExchange");
            info!("Sent ChangeCipherSuite");
            info!("Sent ClientFinished");
            let actions = vec![
                TlsAction::SendPlaintext(client_key_exchange.into()),
                TlsAction::SendPlaintext(change_cipher_spec.into()),
                TlsAction::ChangeCipherSpec(TlsEntity::Client, write),
                TlsAction::SendPlaintext(client_finished.into()),
            ];

            if self.supported_extensions.session_ticket {
                return Ok((
                    AwaitNewSessionTicket {
                        session_id: self.session_id,
                        handshakes: self.handshakes,
                        supported_extensions: self.supported_extensions,
                        client_verify_data: Some(verify_data),
                        params,
                        is_session_resumption: false,
                    }
                    .into(),
                    actions,
                ));
            }

            return Ok((
                AwaitServerChangeCipher {
                    session_id: self.session_id,
                    handshakes: self.handshakes,
                    supported_extensions: self.supported_extensions,
                    client_verify_data: Some(verify_data),
                    params,
                    is_session_resumption: false,
                }
                .into(),
                actions,
            ));
        }
        panic!("invalid transition");
    }
}

impl AwaitServerHelloDone {
    fn calculate_master_secret(&self, pre_master_secret: &[u8], prf: PrfAlgorithm) -> [u8; 48] {
        let (label, seed): (&[u8], Vec<u8>) = if self.supported_extensions.extended_master_secret {
            (b"extended master secret", prf.hash(&self.handshakes))
        } else {
            (
                b"master secret",
                [self.client_random.as_slice(), self.server_random.as_slice()].concat(),
            )
        };

        let master_secret: [u8; 48] = prf.prf(pre_master_secret, label, &seed, 48)
            .try_into()
            .unwrap();
        master_secret
    }
}

#[derive(Debug)]
pub struct AwaitNewSessionTicket {
    session_id: Vec<u8>,
    handshakes: Vec<u8>,
    supported_extensions: SupportedExtensions,
    params: SecurityParams,
    is_session_resumption: bool,

    client_verify_data: Option<Vec<u8>>,
}

impl HandleRecord for AwaitNewSessionTicket {
    fn handle(
        mut self,
        _ctx: &mut TlsContext,
        msg: &TlsMessage,
    ) -> TLSResult<(TlsState, Vec<TlsAction>)> {
        if let TlsMessage::Handshake(TLSHandshake::NewSessionTicket(ticket)) = msg {
            info!("Received NewSessionTicket");
            self.handshakes.extend_from_slice(&ticket.to_bytes());

            _ctx.session_tickets.insert(
                ticket.ticket.clone(),
                SessionTicketInfo {
                    cipher_suite: self.params.cipher_suite_id,
                    master_secret: self.params.master_secret,
                },
            );

            return Ok((
                AwaitServerChangeCipher {
                    session_id: self.session_id,
                    handshakes: self.handshakes,
                    supported_extensions: self.supported_extensions,
                    client_verify_data: self.client_verify_data,
                    params: self.params,
                    is_session_resumption: self.is_session_resumption,
                }
                .into(),
                vec![],
            ));
        }
        panic!("invalid transition");
    }
}

#[derive(Debug)]
pub struct AwaitNewSessionTicketOrCertificate {
    session_id: Vec<u8>,
    handshakes: Vec<u8>,
    client_random: [u8; 32],
    server_random: [u8; 32],
    selected_cipher_suite_id: u16,
    supported_extensions: SupportedExtensions,
    session_ticket_resumption: SessionTicketInfo,
}

impl HandleRecord for AwaitNewSessionTicketOrCertificate {
    fn handle(
        self,
        ctx: &mut TlsContext,
        msg: &TlsMessage,
    ) -> TLSResult<(TlsState, Vec<TlsAction>)> {
        if let TlsMessage::Handshake(TLSHandshake::NewSessionTicket(_)) = msg {
            let ciphersuite = CipherSuite::from_u16(self.session_ticket_resumption.cipher_suite)?;
            let params = SecurityParams {
                cipher_suite_id: self.session_ticket_resumption.cipher_suite,
                client_random: self.client_random,
                server_random: self.server_random,
                enc_algorithm: ciphersuite.params().enc_algorithm,
                mac_algorithm: ciphersuite.params().mac_algorithm,
                prf_algorithm: ciphersuite.params().prf_algorithm,
                master_secret: self.session_ticket_resumption.master_secret,
            };

            return AwaitNewSessionTicket {
                session_id: self.session_id,
                handshakes: self.handshakes,
                supported_extensions: self.supported_extensions,
                client_verify_data: None,
                is_session_resumption: true,
                params,
            }
            .handle(ctx, msg);
        } else if let TlsMessage::Handshake(TLSHandshake::Certificates(_)) = msg {
            return AwaitServerCertificate {
                session_id: self.session_id,
                handshakes: self.handshakes,
                client_random: self.client_random,
                server_random: self.server_random,
                selected_cipher_suite_id: self.selected_cipher_suite_id,
                supported_extensions: self.supported_extensions,
            }
            .handle(ctx, msg);
        }
        panic!("invalid transition");
    }
}

#[derive(Debug)]
pub struct AwaitServerChangeCipherOrCertificate {
    session_id: Vec<u8>,
    handshakes: Vec<u8>,
    client_random: [u8; 32],
    server_random: [u8; 32],
    selected_cipher_suite_id: u16,
    supported_extensions: SupportedExtensions,
    session_ticket_resumption: SessionTicketInfo,
}

impl HandleRecord for AwaitServerChangeCipherOrCertificate {
    fn handle(
        self,
        ctx: &mut TlsContext,
        msg: &TlsMessage,
    ) -> TLSResult<(TlsState, Vec<TlsAction>)> {
        if let TlsMessage::ChangeCipherSpec = msg {
            let ciphersuite = CipherSuite::from_u16(self.session_ticket_resumption.cipher_suite)?;
            let params = SecurityParams {
                cipher_suite_id: self.session_ticket_resumption.cipher_suite,
                client_random: self.client_random,
                server_random: self.server_random,
                enc_algorithm: ciphersuite.params().enc_algorithm,
                mac_algorithm: ciphersuite.params().mac_algorithm,
                prf_algorithm: ciphersuite.params().prf_algorithm,
                master_secret: self.session_ticket_resumption.master_secret,
            };

            return AwaitServerChangeCipher {
                session_id: self.session_id,
                handshakes: self.handshakes,
                supported_extensions: self.supported_extensions,
                params,
                client_verify_data: None,
                is_session_resumption: true,
            }
            .handle(ctx, msg);
        } else if let TlsMessage::Handshake(TLSHandshake::Certificates(_)) = msg {
            return AwaitServerCertificate {
                session_id: self.session_id,
                handshakes: self.handshakes,
                client_random: self.client_random,
                server_random: self.server_random,
                selected_cipher_suite_id: self.selected_cipher_suite_id,
                supported_extensions: self.supported_extensions,
            }
            .handle(ctx, msg);
        }
        panic!("invalid transition");
    }
}

#[derive(Debug)]
pub struct AwaitServerChangeCipher {
    session_id: Vec<u8>,
    handshakes: Vec<u8>,
    supported_extensions: SupportedExtensions,

    // For secure renegotiation, but not available when server changes cipher first
    client_verify_data: Option<Vec<u8>>,

    // Tells us whether ClientChangeCipher must follow
    is_session_resumption: bool,

    // Params to change to
    params: SecurityParams,
}

impl HandleRecord for AwaitServerChangeCipher {
    fn handle(
        self,
        _ctx: &mut TlsContext,
        msg: &TlsMessage,
    ) -> TLSResult<(TlsState, Vec<TlsAction>)> {
        if let TlsMessage::ChangeCipherSpec = msg {
            info!("Received ChangeCipherSpec");

            let keys = self.params.derive_keys();
            let read = ConnState::Secure(SecureConnState::new(
                self.params.clone(),
                keys.server_enc_key,
                keys.server_mac_key,
                keys.server_write_iv,
            ));

            return Ok((
                AwaitServerFinished {
                    session_id: self.session_id,
                    handshakes: self.handshakes,
                    supported_extensions: self.supported_extensions,
                    client_verify_data: self.client_verify_data,
                    params: self.params,
                    is_session_resumption: self.is_session_resumption,
                }
                .into(),
                vec![TlsAction::ChangeCipherSpec(TlsEntity::Server, read)],
            ));
        }
        panic!("invalid transition");
    }
}

#[derive(Debug)]
pub struct AwaitServerFinished {
    session_id: Vec<u8>,
    handshakes: Vec<u8>,
    supported_extensions: SupportedExtensions,
    params: SecurityParams,
    client_verify_data: Option<Vec<u8>>,
    is_session_resumption: bool,
}

impl HandleRecord for AwaitServerFinished {
    fn handle(
        mut self,
        ctx: &mut TlsContext,
        msg: &TlsMessage,
    ) -> TLSResult<(TlsState, Vec<TlsAction>)> {
        if let TlsMessage::Handshake(TLSHandshake::Finished(finished)) = msg {
            info!("Received ServerFinished");

            let verify_data = self.params.server_verify_data(&self.handshakes);
            assert_eq!(verify_data, finished.verify_data);
            self.handshakes.extend_from_slice(&finished.to_bytes());

            if !self.is_session_resumption {
                info!("Handshake complete! (full)");

                ctx.sessions.insert(
                    self.session_id.clone(),
                    SessionInfo {
                        master_secret: self.params.master_secret,
                        cipher_suite: self.params.cipher_suite_id,
                    },
                );

                return Ok((
                    EstablishedState {
                        session_id: self.session_id,
                        supported_extensions: self.supported_extensions,
                        client_verify_data: self.client_verify_data.unwrap(),
                    }
                    .into(),
                    vec![],
                ));
            } else {
                let change_cipher_spec = ChangeCipherSpec::new();

                let keys = self.params.derive_keys();
                let write = ConnState::Secure(SecureConnState::new(
                    self.params.clone(),
                    keys.client_enc_key,
                    keys.client_mac_key,
                    keys.client_write_iv,
                ));

                let verify_data = self.params.client_verify_data(&self.handshakes);
                let client_finished = Finished::new(verify_data.clone());

                info!("Sent ChangeCipherSpec");
                info!("Sent ClientFinished");
                info!("Handshake complete! (abbreviated)");
                return Ok((
                    EstablishedState {
                        session_id: self.session_id,
                        supported_extensions: self.supported_extensions,
                        client_verify_data: verify_data,
                    }
                    .into(),
                    vec![
                        TlsAction::SendPlaintext(change_cipher_spec.into()),
                        TlsAction::ChangeCipherSpec(TlsEntity::Client, write),
                        TlsAction::SendPlaintext(client_finished.into()),
                    ],
                ));
            }
        }
        panic!("invalid transition");
    }
}

#[derive(Debug)]
pub struct EstablishedState {
    pub session_id: Vec<u8>,
    pub supported_extensions: SupportedExtensions,
    pub client_verify_data: Vec<u8>,
}

impl HandleRecord for EstablishedState {
    fn handle(
        self,
        _ctx: &mut TlsContext,
        msg: &TlsMessage,
    ) -> TLSResult<(TlsState, Vec<TlsAction>)> {
        if let TlsMessage::Handshake(TLSHandshake::ClientHello(hello)) = msg {
            return Ok((
                AwaitServerHello {
                    handshakes: hello.to_bytes(),
                    client_random: hello.random.as_bytes(),
                    session_id_resumption: None,
                    session_ticket_resumption: None,
                }
                .into(),
                vec![TlsAction::SendPlaintext(hello.clone().into())],
            ));
        }
        panic!("invalid transition");
    }
}
