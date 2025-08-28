use crate::MaxFragmentLength;
use crate::alert::AlertDesc;
use crate::ciphersuite::{CipherSuiteId, PrfAlgorithm};
use crate::client::TlsClientConfig;
use crate::server::TlsServerConfig;
use crate::storage::{SessionInfo, StekInfo};
use crate::{
    alert::Alert,
    connection::ConnState,
    messages::{TlsHandshake, TlsMessage},
};
use client::{
    ClientAttemptedRenegotiationState, ClientEstablished, ExpectClientInitiateState,
    ExpectNewSessionTicket, ExpectNewSessionTicketAbbr, ExpectNewSessionTicketOrCertificate,
    ExpectServerCertificate, ExpectServerChangeCipher, ExpectServerChangeCipherAbbr,
    ExpectServerChangeCipherOrCertificate, ExpectServerFinished, ExpectServerFinishedAbbr,
    ExpectServerHello, ExpectServerHelloDone, ExpectServerHelloDoneOrCertificateRequest,
    ExpectServerKeyExchange, ExpectServerKeyExchangeOrCertificateRequest,
};
use server::{
    ExpectCertificateVerify, ExpectClientCertificate, ExpectClientChangeCipher,
    ExpectClientChangeCipherAbbr, ExpectClientFinished, ExpectClientFinishedAbbr,
    ExpectClientHello, ExpectClientKeyExchange, ExpectSessionValidation, ExpectStekInfo,
    ServerEstablished,
};
use std::rc::Rc;

mod client;
mod server;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsEntity {
    Client,
    Server,
}

#[derive(Debug)]
pub struct SessionIdResumption {
    pub session_id: Vec<u8>,
    pub master_secret: [u8; 48],
    pub cipher_suite_id: CipherSuiteId,
    pub max_fragment_len: Option<MaxFragmentLength>,
    pub extended_master_secret: bool,
}

#[derive(Debug)]
pub struct SessionTicketResumption {
    pub session_ticket: Vec<u8>,
    pub master_secret: [u8; 48],
    pub cipher_suite_id: CipherSuiteId,
    pub max_fragment_len: Option<MaxFragmentLength>,
    pub extended_master_secret: bool,
}

#[derive(Debug)]
pub enum SessionResumption {
    None,
    SessionId(SessionIdResumption),
    SessionTicket(SessionTicketResumption),
}

#[derive(Debug)]
pub enum SessionValidation {
    Invalid,
    Valid(SessionInfo),
}

#[derive(Debug)]
pub enum TlsEvent<'a> {
    ClientInitiate {
        cipher_suites: Vec<CipherSuiteId>,
        session_resumption: SessionResumption,
        server_name: String,
        support_session_ticket: bool,
        support_extended_master_secret: bool,
        support_secure_renegotiation: bool,
        max_fragment_len: Option<MaxFragmentLength>,
    },
    IncomingMessage(&'a TlsMessage),
    SessionValidation(SessionValidation),
    StekInfo(Option<StekInfo>),
}

#[derive(Debug)]
pub enum TlsAction {
    SendAlert(Alert),
    ChangeCipherSpec(TlsEntity, ConnState),
    SendHandshakeMsg(TlsHandshake),
    GetStekInfo(Vec<u8>),
    ValidateSessionId(Vec<u8>),
    StoreSessionTicketInfo(Vec<u8>, SessionInfo),
    StoreSessionIdInfo(Vec<u8>, SessionInfo),
    InvalidateSessionId(Vec<u8>),
    InvalidateSessionTicket(Vec<u8>),
    CloseConnection(AlertDesc),
    UpdateMaxFragmentLen(MaxFragmentLength),
}

#[derive(Debug, Clone)]
pub struct ServerContext {
    pub config: Rc<TlsServerConfig>,
    pub stek: Option<StekInfo>,
}

#[derive(Debug, Clone)]
pub struct ClientContext {
    pub config: Rc<TlsClientConfig>,
}

pub trait StateMachine {
    fn handle(&mut self, event: TlsEvent) -> Vec<TlsAction>;
    fn is_established(&self) -> bool;
}

pub struct TlsStateMachine<T: TlsState<C>, C> {
    pub state: Option<T>,
    pub ctx: C,
}

pub type ClientStateMachine = TlsStateMachine<ClientState, ClientContext>;
pub type ServerStateMachine = TlsStateMachine<ServerState, ServerContext>;

impl ClientStateMachine {
    pub fn new(config: Rc<TlsClientConfig>) -> Self {
        Self {
            ctx: ClientContext { config },
            state: Some(
                ExpectClientInitiateState {
                    previous_verify_data: None,
                }
                .into(),
            ),
        }
    }
}

impl ServerStateMachine {
    pub fn new(config: Rc<TlsServerConfig>) -> Self {
        let stek = config.session_store.as_ref().map(|store| {
            let new_stek = StekInfo::new();
            store
                .insert_stek(&new_stek.key_name.to_vec(), new_stek.clone())
                .expect("failed to create new STEK");
            new_stek
        });
        Self {
            ctx: ServerContext { config, stek },
            state: Some(
                ExpectClientHello {
                    previous_verify_data: None,
                }
                .into(),
            ),
        }
    }
}

impl<T: TlsState<C>, C> StateMachine for TlsStateMachine<T, C> {
    fn handle(&mut self, event: TlsEvent) -> Vec<TlsAction> {
        // Fatal alerts are handled the same for all states
        if let TlsEvent::IncomingMessage(TlsMessage::Alert(alert)) = event {
            if alert.is_fatal() {
                let mut actions = vec![];

                // Must reply with close_notify if we receive one
                if alert.is_close_notification() {
                    actions.push(TlsAction::SendAlert(Alert::fatal(AlertDesc::CloseNotify)));
                }

                // Must invalidate session for fatal alerts
                if let Some(session_id) = self.state.as_ref().unwrap().session_id() {
                    actions.push(TlsAction::InvalidateSessionId(session_id));
                }

                actions.push(TlsAction::CloseConnection(alert.description));
                self.state = Some(T::new_closed_state());
                return actions;
            }
        }

        match self.state.take().unwrap().handle(&mut self.ctx, event) {
            Err(alert_desc) => {
                self.state = Some(T::new_closed_state());
                vec![
                    TlsAction::SendAlert(Alert::fatal(alert_desc)),
                    TlsAction::CloseConnection(alert_desc),
                ]
            }
            Ok((new_state, actions)) => {
                self.state = Some(new_state);
                actions
            }
        }
    }

    fn is_established(&self) -> bool {
        self.state.as_ref().unwrap().is_established()
    }
}

type HandleResult<S> = Result<(S, Vec<TlsAction>), AlertDesc>;

pub trait HandleEvent<C, S> {
    fn handle(self, ctx: &mut C, event: TlsEvent) -> HandleResult<S>;
}

pub trait TlsState<C>: Sized {
    fn handle(self, ctx: &mut C, event: TlsEvent) -> HandleResult<Self>;
    fn is_established(&self) -> bool;
    fn new_closed_state() -> Self;
    fn session_id(&self) -> Option<Vec<u8>>;
}

impl_state_dispatch! {
    #[context = ClientContext]
    #[established = ClientEstablished]
    #[closed = ClientClosed]
    pub enum ClientState {
        ExpectClientInitiate(ExpectClientInitiateState),
        ExpectServerHello(ExpectServerHello),
        ExpectServerCertificate(ExpectServerCertificate),
        ExpectServerKeyExchangeOrCertificateRequest(ExpectServerKeyExchangeOrCertificateRequest),
        ExpectServerKeyExchange(ExpectServerKeyExchange),
        ExpectServerHelloDoneOrCertificateRequest(ExpectServerHelloDoneOrCertificateRequest),
        ExpectServerHelloDone(ExpectServerHelloDone),
        ExpectNewSessionTicket(ExpectNewSessionTicket),
        ExpectNewSessionTicketOrCertificate(ExpectNewSessionTicketOrCertificate),
        ExpectServerChangeCipherOrCertificate(ExpectServerChangeCipherOrCertificate),
        ExpectServerChangeCipher(ExpectServerChangeCipher),
        ExpectServerFinished(ExpectServerFinished),
        ExpectNewSessionTicketAbbr(ExpectNewSessionTicketAbbr),
        ExpectServerChangeCipherAbbr(ExpectServerChangeCipherAbbr),
        ExpectServerFinishedAbbr(ExpectServerFinishedAbbr),
        ClientEstablished(ClientEstablished),
        ClientClosed(ClosedState),
        AttemptedRenegotiation(ClientAttemptedRenegotiationState),
    }
}

impl_state_dispatch! {
    #[context = ServerContext]
    #[established = ServerEstablished]
    #[closed = ServerClosed]
    pub enum ServerState {
        ExpectClientHello(ExpectClientHello),
        ExpectStekInfo(ExpectStekInfo),
        ExpectSessionValidation(ExpectSessionValidation),
        ExpectClientCertificate(ExpectClientCertificate),
        ExpectClientKeyExchange(ExpectClientKeyExchange),
        ExpectCertificateVerify(ExpectCertificateVerify),
        ExpectClientChangeCipher(ExpectClientChangeCipher),
        ExpectClientFinished(ExpectClientFinished),
        ExpectClientChangeCipherAbbr(ExpectClientChangeCipherAbbr),
        ExpectClientFinishedAbbr(ExpectClientFinishedAbbr),
        ServerEstablished(ServerEstablished),
        ServerClosed(ClosedState),
    }
}

#[derive(Debug)]
pub struct PreviousVerifyData {
    client: Vec<u8>,
    server: Vec<u8>,
}

#[allow(unused)]
#[derive(Debug)]
struct NegotiatedExtensions {
    extended_master_secret: bool,
    secure_renegotiation: bool,
    session_ticket: bool,
    max_fragment_length: Option<MaxFragmentLength>,
}

fn calculate_master_secret(
    handshakes: &[u8],
    client_random: &[u8],
    server_random: &[u8],
    pre_master_secret: &[u8],
    prf: PrfAlgorithm,
    use_extended_master_secret: bool,
) -> [u8; 48] {
    let (label, seed): (&[u8], Vec<u8>) = if use_extended_master_secret {
        (b"extended master secret", prf.hash(handshakes))
    } else {
        (b"master secret", [client_random, server_random].concat())
    };
    let master_secret: [u8; 48] = prf
        .prf(pre_master_secret, label, &seed, 48)
        .try_into()
        .unwrap();
    master_secret
}

#[derive(Debug)]
pub struct ClosedState {}

impl HandleEvent<ServerContext, ServerState> for ClosedState {
    fn handle(self, _ctx: &mut ServerContext, event: TlsEvent) -> HandleResult<ServerState> {
        println!("{:?}", event);
        // Maybe get server hello
        // Maybe get alert
        // Maybe get nothing...
        unimplemented!()
    }
}

impl HandleEvent<ClientContext, ClientState> for ClosedState {
    fn handle(self, _ctx: &mut ClientContext, event: TlsEvent) -> HandleResult<ClientState> {
        println!("{:?}", event);
        // Maybe get server hello
        // Maybe get alert
        // Maybe get nothing...
        unimplemented!()
    }
}
