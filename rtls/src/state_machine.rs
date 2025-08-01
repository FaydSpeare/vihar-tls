use rsa::{RsaPublicKey, pkcs8::DecodePublicKey};
use std::collections::HashMap;

use enum_dispatch::enum_dispatch;
use log::{debug, info};

use crate::ciphersuite::{CipherSuiteId, PrfAlgorithm};
use crate::extensions::{HashAlgo, SigAlgo};
use crate::messages::SessionId;
use crate::signature::{
    dsa_verify, get_dhe_pre_master_secret, get_rsa_pre_master_secret, public_key_from_cert,
    rsa_verify,
};
use crate::{
    TLSResult,
    alert::TLSAlert,
    ciphersuite::{CipherSuite, CipherSuiteMethods, KeyExchangeAlgorithm},
    connection::{ConnState, InitialConnState, SecureConnState, SecurityParams},
    encoding::TlsCodable,
    messages::{ClientKeyExchange, Finished, TlsHandshake, TlsMessage},
};

#[derive(Debug, Clone)]
pub struct SessionInfo {
    cipher_suite: CipherSuiteId,
    master_secret: [u8; 48],
}

#[derive(Debug, Clone)]
pub struct SessionTicketInfo {
    cipher_suite: CipherSuiteId,
    master_secret: [u8; 48],
}

#[derive(Debug, Clone)]
pub struct TlsContext {
    pub sessions: HashMap<SessionId, SessionInfo>,
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

#[derive(Debug)]
pub enum TlsEntity {
    Client,
    Server,
}

#[derive(Debug)]
pub enum TlsAction {
    SendAlert(TLSAlert),
    ChangeCipherSpec(TlsEntity, ConnState),
    SendHandshakeMsg(TlsHandshake),
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
        let TlsMessage::Handshake(handshake) = msg else {
            panic!("invalid transition");
        };

        let TlsHandshake::ClientHello(hello) = handshake else {
            panic!("invalid transition");
        };

        info!("Sent ClientHello");
        return Ok((
            AwaitServerHello {
                handshakes: handshake.get_encoding(),
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
                    .extensions
                    .get_session_ticket()
                    .and_then(|ticket| _ctx.session_tickets.get(&ticket).cloned()),
            }
            .into(),
            vec![TlsAction::SendHandshakeMsg(handshake.clone())],
        ));
    }
}

#[derive(Debug)]
struct SessionIdResumption {
    session_id: SessionId,
    master_secret: [u8; 48],
    cipher_suite: CipherSuiteId,
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
        let TlsMessage::Handshake(handshake) = msg else {
            panic!("invalid transition");
        };

        let TlsHandshake::ServerHello(hello) = handshake else {
            panic!("invalid transition");
        };

        info!("Received ServerHello");
        handshake.write_to(&mut self.handshakes);

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
            let params = SecurityParams::new(
                self.client_random,
                hello.random.as_bytes(),
                resumption.master_secret,
                resumption.cipher_suite,
            );

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
                        selected_cipher_suite_id: hello.cipher_suite,
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
                    selected_cipher_suite_id: hello.cipher_suite,
                    supported_extensions,
                    handshakes: self.handshakes,
                    session_ticket_resumption: resumption,
                }
                .into(),
                vec![],
            ));
        }

        // Boring... no session resumption, we're doing a full handshake.
        let cipher_suite = CipherSuite::from(hello.cipher_suite);
        debug!("Selected CipherSuite: {}", cipher_suite.params().name);
        return Ok((
            AwaitServerCertificate {
                session_id: hello.session_id.clone(),
                handshakes: self.handshakes,
                client_random: self.client_random,
                server_random: hello.random.as_bytes(),
                selected_cipher_suite_id: hello.cipher_suite,
                supported_extensions,
            }
            .into(),
            vec![],
        ));
    }
}

#[derive(Debug)]
pub struct AwaitServerCertificate {
    session_id: SessionId,
    handshakes: Vec<u8>,
    client_random: [u8; 32],
    server_random: [u8; 32],
    selected_cipher_suite_id: CipherSuiteId,
    supported_extensions: SupportedExtensions,
}

impl HandleRecord for AwaitServerCertificate {
    fn handle(
        mut self,
        _ctx: &mut TlsContext,
        msg: &TlsMessage,
    ) -> TLSResult<(TlsState, Vec<TlsAction>)> {
        let TlsMessage::Handshake(handshake) = msg else {
            panic!("invalid transition");
        };

        let TlsHandshake::Certificates(certs) = handshake else {
            panic!("invalid transition");
        };

        handshake.write_to(&mut self.handshakes);
        let server_public_key = public_key_from_cert(&certs.list[0])?;

        let cipher_suite = CipherSuite::from(self.selected_cipher_suite_id);
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
}

#[derive(Debug)]
pub struct AwaitServerKeyExchange {
    session_id: SessionId,
    handshakes: Vec<u8>,
    client_random: [u8; 32],
    server_random: [u8; 32],
    selected_cipher_suite_id: CipherSuiteId,
    supported_extensions: SupportedExtensions,
    server_public_key: Vec<u8>,
}

impl HandleRecord for AwaitServerKeyExchange {
    fn handle(
        mut self,
        _ctx: &mut TlsContext,
        msg: &TlsMessage,
    ) -> TLSResult<(TlsState, Vec<TlsAction>)> {
        let TlsMessage::Handshake(handshake) = msg else {
            panic!("invalid transition");
        };

        let TlsHandshake::ServerKeyExchange(kx) = handshake else {
            panic!("invalid transition");
        };
        info!("Received ServerKeyExchange");

        let verified = match kx.sig_algo {
            SigAlgo::Rsa => {
                let rsa_public_key = RsaPublicKey::from_public_key_der(&self.server_public_key)?;
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
        handshake.write_to(&mut self.handshakes);

        Ok((
            AwaitServerHelloDone {
                session_id: self.session_id,
                handshakes: self.handshakes,
                client_random: self.client_random,
                server_random: self.server_random,
                selected_cipher_suite_id: self.selected_cipher_suite_id,
                supported_extensions: self.supported_extensions,
                server_public_key: self.server_public_key,
                secrets: Some(DheParams {
                    p: kx.p.to_vec(),
                    g: kx.g.to_vec(),
                    public_key: kx.server_pubkey.to_vec(),
                }),
            }
            .into(),
            vec![],
        ))
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
    session_id: SessionId,
    handshakes: Vec<u8>,
    client_random: [u8; 32],
    server_random: [u8; 32],
    selected_cipher_suite_id: CipherSuiteId,
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
        let TlsMessage::Handshake(handshake) = msg else {
            panic!("invalid transition");
        };

        let TlsHandshake::ServerHelloDone = handshake else {
            panic!("invalid transition");
        };

        info!("Received ServerHelloDone");
        handshake.write_to(&mut self.handshakes);

        let ciphersuite = CipherSuite::from(self.selected_cipher_suite_id);
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
                }
                KeyExchangeAlgorithm::EcdheRsa => unimplemented!(),
            };

        let client_kx = ClientKeyExchange::new(&key_exchange_data);
        TlsHandshake::ClientKeyExchange(client_kx.clone()).write_to(&mut self.handshakes);

        let master_secret =
            self.calculate_master_secret(&pre_master_secret, ciphersuite.params().prf_algorithm);
        let params = SecurityParams::new(
            self.client_random,
            self.server_random,
            master_secret,
            self.selected_cipher_suite_id,
        );
        let keys = params.derive_keys();
        let write = ConnState::Secure(SecureConnState::new(
            params.clone(),
            keys.client_enc_key,
            keys.client_mac_key,
            keys.client_write_iv,
        ));

        let verify_data = params.client_verify_data(&self.handshakes);
        let client_finished = Finished::new(verify_data.clone());
        TlsHandshake::Finished(client_finished.clone()).write_to(&mut self.handshakes);

        info!("Sent ClientKeyExchange");
        info!("Sent ChangeCipherSuite");
        info!("Sent ClientFinished");
        let actions = vec![
            TlsAction::SendHandshakeMsg(client_kx.into()),
            TlsAction::ChangeCipherSpec(TlsEntity::Client, write),
            TlsAction::SendHandshakeMsg(client_finished.into()),
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

        Ok((
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
        ))
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

        let master_secret: [u8; 48] = prf
            .prf(pre_master_secret, label, &seed, 48)
            .try_into()
            .unwrap();
        master_secret
    }
}

#[derive(Debug)]
pub struct AwaitNewSessionTicket {
    session_id: SessionId,
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
        let TlsMessage::Handshake(handshake) = msg else {
            panic!("invalid transition");
        };

        let TlsHandshake::NewSessionTicket(ticket) = handshake else {
            panic!("invalid transition");
        };

        info!("Received NewSessionTicket");
        handshake.write_to(&mut self.handshakes);

        _ctx.session_tickets.insert(
            ticket.ticket.to_vec(),
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
}

#[derive(Debug)]
pub struct AwaitNewSessionTicketOrCertificate {
    session_id: SessionId,
    handshakes: Vec<u8>,
    client_random: [u8; 32],
    server_random: [u8; 32],
    selected_cipher_suite_id: CipherSuiteId,
    supported_extensions: SupportedExtensions,
    session_ticket_resumption: SessionTicketInfo,
}

impl HandleRecord for AwaitNewSessionTicketOrCertificate {
    fn handle(
        self,
        ctx: &mut TlsContext,
        msg: &TlsMessage,
    ) -> TLSResult<(TlsState, Vec<TlsAction>)> {
        if let TlsMessage::Handshake(TlsHandshake::NewSessionTicket(_)) = msg {
            let params = SecurityParams::new(
                self.client_random,
                self.server_random,
                self.session_ticket_resumption.master_secret,
                self.session_ticket_resumption.cipher_suite,
            );

            return AwaitNewSessionTicket {
                session_id: self.session_id,
                handshakes: self.handshakes,
                supported_extensions: self.supported_extensions,
                client_verify_data: None,
                is_session_resumption: true,
                params,
            }
            .handle(ctx, msg);
        } else if let TlsMessage::Handshake(TlsHandshake::Certificates(_)) = msg {
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
    session_id: SessionId,
    handshakes: Vec<u8>,
    client_random: [u8; 32],
    server_random: [u8; 32],
    selected_cipher_suite_id: CipherSuiteId,
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
            let params = SecurityParams::new(
                self.client_random,
                self.server_random,
                self.session_ticket_resumption.master_secret,
                self.session_ticket_resumption.cipher_suite,
            );

            return AwaitServerChangeCipher {
                session_id: self.session_id,
                handshakes: self.handshakes,
                supported_extensions: self.supported_extensions,
                params,
                client_verify_data: None,
                is_session_resumption: true,
            }
            .handle(ctx, msg);
        } else if let TlsMessage::Handshake(TlsHandshake::Certificates(_)) = msg {
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
    session_id: SessionId,
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
        let TlsMessage::ChangeCipherSpec = msg else {
            panic!("invalid transition");
        };

        info!("Received ChangeCipherSpec");
        let keys = self.params.derive_keys();
        let read = ConnState::Secure(SecureConnState::new(
            self.params.clone(),
            keys.server_enc_key,
            keys.server_mac_key,
            keys.server_write_iv,
        ));

        Ok((
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
        ))
    }
}

#[derive(Debug)]
pub struct AwaitServerFinished {
    session_id: SessionId,
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
        let TlsMessage::Handshake(handshake) = msg else {
            panic!("invalid transition");
        };

        let TlsHandshake::Finished(finished) = handshake else {
            panic!("invalid transition");
        };

        info!("Received ServerFinished");
        let verify_data = self.params.server_verify_data(&self.handshakes);
        assert_eq!(verify_data, finished.verify_data);
        handshake.write_to(&mut self.handshakes);

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
        }

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
        Ok((
            EstablishedState {
                session_id: self.session_id,
                supported_extensions: self.supported_extensions,
                client_verify_data: verify_data,
            }
            .into(),
            vec![
                TlsAction::ChangeCipherSpec(TlsEntity::Client, write),
                TlsAction::SendHandshakeMsg(client_finished.into()),
            ],
        ))
    }
}

#[derive(Debug)]
pub struct EstablishedState {
    pub session_id: SessionId,
    pub supported_extensions: SupportedExtensions,
    pub client_verify_data: Vec<u8>,
}

impl HandleRecord for EstablishedState {
    fn handle(
        self,
        _ctx: &mut TlsContext,
        msg: &TlsMessage,
    ) -> TLSResult<(TlsState, Vec<TlsAction>)> {
        let TlsMessage::Handshake(handshake) = msg else {
            panic!("invalid transition");
        };

        let TlsHandshake::ClientHello(hello) = handshake else {
            panic!("invalid transition");
        };

        Ok((
            AwaitServerHello {
                handshakes: handshake.get_encoding(),
                client_random: hello.random.as_bytes(),
                session_id_resumption: None,
                session_ticket_resumption: None,
            }
            .into(),
            vec![TlsAction::SendHandshakeMsg(hello.clone().into())],
        ))
    }
}
