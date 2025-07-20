use std::collections::HashMap;

use enum_dispatch::enum_dispatch;
use log::{debug, info};
use sha2::{Digest, Sha256};

use crate::{
    TLSResult,
    alert::TLSAlert,
    ciphersuite::{CipherSuiteMethods, get_cipher_suite},
    connection::{ConnState, InitialConnState, SecureConnState, SecurityParams},
    messages::{
        ChangeCipherSpec, ClientKeyExchange, Finished, NewSessionTicket, TLSHandshake,
        TLSHandshakeType, TLSPlaintext, TlsMessage, ToBytes, handshake_bytes,
    },
    prf,
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
    AwaitingNewSessionTicket(AwaitingNewSessionTicketState),
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
        msg: &TlsMessage,
    ) -> TLSResult<(TlsState, Vec<TlsAction>)>;
}

#[derive(Debug)]
pub struct AwaitingClientHelloState {}

impl HandleRecord for AwaitingClientHelloState {
    fn handle(
        self,
        _ctx: &mut TlsContext,
        msg: &TlsMessage,
    ) -> TLSResult<(TlsState, Vec<TlsAction>)> {
        if let TlsMessage::Handshake(TLSHandshake::ClientHello(hello)) = msg {
            info!("Sent ClientHello");

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
                    session_ticket: hello
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
    session_ticket: Option<SessionTicketInfo>,
}

impl HandleRecord for AwaitingServerHelloState {
    fn handle(
        mut self,
        _ctx: &mut TlsContext,
        msg: &TlsMessage,
    ) -> TLSResult<(TlsState, Vec<TlsAction>)> {
        if let TlsMessage::Handshake(TLSHandshake::ServerHello(hello)) = msg {
            info!("Received ServerHello");
            self.handshakes.extend_from_slice(&hello.to_bytes());

            if self
                .session_resumption
                .as_ref()
                .map_or(false, |x| x.session_id == hello.session_id)
            {
                let resumption = self.session_resumption.unwrap();
                let ciphersuite = get_cipher_suite(resumption.cipher_suite)?;
                let params = SecurityParams {
                    cipher_suite_id: resumption.cipher_suite,
                    client_random: self.client_random,
                    server_random: hello.random.as_bytes(),
                    enc_algorithm: ciphersuite.params().enc_algorithm,
                    mac_algorithm: ciphersuite.params().mac_algorithm,
                    master_secret: resumption.master_secret,
                };

                return Ok((
                    AwaitingServerChangeCipherState {
                        session_id: hello.session_id.clone(),
                        handshakes: self.handshakes,
                        secure_renegotiation: hello.supports_secure_renegotiation(),
                        client_verify_data: vec![],
                        params,
                        is_session_resumption: true,
                    }
                    .into(),
                    vec![],
                ));
            }

            if self.session_ticket.is_some() {
                let resumption = self.session_ticket.unwrap();
                let ciphersuite = get_cipher_suite(resumption.cipher_suite)?;
                let params = SecurityParams {
                    cipher_suite_id: resumption.cipher_suite,
                    client_random: self.client_random,
                    server_random: hello.random.as_bytes(),
                    enc_algorithm: ciphersuite.params().enc_algorithm,
                    mac_algorithm: ciphersuite.params().mac_algorithm,
                    master_secret: resumption.master_secret,
                };

                if hello.supports_session_ticket() {
                    // TODO: server could still have rejected our ticket and simply be
                    // signaling a new ticket issuance by show session ticket support
                    //
                    // So we could get NewSessionTicket OR ServerCertificate next.
                    return Ok((
                        AwaitingNewSessionTicketState {
                            session_id: hello.session_id.clone(),
                            handshakes: self.handshakes,
                            secure_renegotiation: hello.supports_secure_renegotiation(),
                            client_verify_data: vec![],
                            params,
                            is_session_resumption: true,
                        }
                        .into(),
                        vec![],
                    ));
                }

                // TODO: server could still have rejected our ticket and simply be
                // signaling that it will not issue a new ticket either.
                //
                // So we could get ChangeCipherSpec OR ServerCertificate next.
                return Ok((
                    AwaitingServerChangeCipherState {
                        session_id: hello.session_id.clone(),
                        handshakes: self.handshakes,
                        secure_renegotiation: hello.supports_secure_renegotiation(),
                        client_verify_data: vec![],
                        params,
                        is_session_resumption: true,
                    }
                    .into(),
                    vec![],
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
                    session_ticket: hello.supports_session_ticket(),
                    cipher_suite: hello.cipher_suite.encode(),
                }
                .into(),
                vec![],
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
    session_ticket: bool,
}

impl HandleRecord for AwaitingServerCertificateState {
    fn handle(
        mut self,
        _ctx: &mut TlsContext,
        msg: &TlsMessage,
    ) -> TLSResult<(TlsState, Vec<TlsAction>)> {
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
                    session_ticket: self.session_ticket,
                    cipher_suite: self.cipher_suite,
                }
                .into(),
                vec![],
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
    session_ticket: bool,
    master_secret: [u8; 48],
    enc_pre_master_secret: Vec<u8>,
}

impl HandleRecord for AwaitingServerHelloDoneState {
    fn handle(
        mut self,
        _ctx: &mut TlsContext,
        msg: &TlsMessage,
    ) -> TLSResult<(TlsState, Vec<TlsAction>)> {
        if let TlsMessage::Handshake(TLSHandshake::ServerHelloDone) = msg {
            info!("Received ServerHelloDone");

            self.handshakes
                .extend_from_slice(&handshake_bytes(TLSHandshakeType::ServerHelloDone, &[]));

            let client_key_exchange = ClientKeyExchange::new(&self.enc_pre_master_secret);
            self.handshakes
                .extend_from_slice(&client_key_exchange.to_bytes());

            let change_cipher_spec = ChangeCipherSpec::new();

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
            let write = ConnState::Secure(SecureConnState::new(
                params.clone(),
                keys.client_enc_key,
                keys.client_mac_key,
            ));

            let verify_data = client_verify_data(&self.master_secret, &self.handshakes);
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

            if self.session_ticket {
                return Ok((
                    AwaitingNewSessionTicketState {
                        session_id: self.session_id,
                        handshakes: self.handshakes,
                        secure_renegotiation: self.secure_renegotiation,
                        client_verify_data: verify_data,
                        params,
                        is_session_resumption: false,
                    }
                    .into(),
                    actions,
                ));
            }

            return Ok((
                AwaitingServerChangeCipherState {
                    session_id: self.session_id,
                    handshakes: self.handshakes,
                    secure_renegotiation: self.secure_renegotiation,
                    client_verify_data: verify_data,
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

#[derive(Debug)]
pub struct AwaitingNewSessionTicketState {
    session_id: Vec<u8>,
    handshakes: Vec<u8>,
    secure_renegotiation: bool,
    client_verify_data: Vec<u8>,
    params: SecurityParams,
    is_session_resumption: bool,
}

impl HandleRecord for AwaitingNewSessionTicketState {
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
                AwaitingServerChangeCipherState {
                    session_id: self.session_id,
                    handshakes: self.handshakes,
                    secure_renegotiation: self.secure_renegotiation,
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
pub struct AwaitingServerChangeCipherState {
    session_id: Vec<u8>,
    handshakes: Vec<u8>,
    secure_renegotiation: bool,
    client_verify_data: Vec<u8>,
    params: SecurityParams,
    is_session_resumption: bool,
}

impl HandleRecord for AwaitingServerChangeCipherState {
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
            ));

            return Ok((
                AwaitingServerFinishedState {
                    session_id: self.session_id,
                    handshakes: self.handshakes,
                    secure_renegotiation: self.secure_renegotiation,
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
pub struct AwaitingServerFinishedState {
    session_id: Vec<u8>,
    handshakes: Vec<u8>,
    secure_renegotiation: bool,
    client_verify_data: Vec<u8>,
    params: SecurityParams,
    is_session_resumption: bool,
}

impl HandleRecord for AwaitingServerFinishedState {
    fn handle(
        mut self,
        ctx: &mut TlsContext,
        msg: &TlsMessage,
    ) -> TLSResult<(TlsState, Vec<TlsAction>)> {
        if let TlsMessage::Handshake(TLSHandshake::Finished(finished)) = msg {
            info!("Received ServerFinished");

            let verify_data = server_verify_data(&self.params.master_secret, &self.handshakes);
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
                        secure_renegotiation: self.secure_renegotiation,
                        client_verify_data: self.client_verify_data,
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
                ));

                let verify_data = client_verify_data(&self.params.master_secret, &self.handshakes);
                let client_finished = Finished::new(verify_data);

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
    secure_renegotiation: bool,
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
                AwaitingServerHelloState {
                    handshakes: hello.to_bytes(),
                    client_random: hello.random.as_bytes(),
                    session_resumption: None,
                    session_ticket: None,
                }
                .into(),
                vec![TlsAction::SendPlaintext(hello.clone().into())],
            ));
        }
        panic!("invalid transition");
    }
}
