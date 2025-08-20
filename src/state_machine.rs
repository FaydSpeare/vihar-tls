use crate::MaxFragmentLength;
use crate::alert::TlsAlertDesc;
use crate::ciphersuite::{CipherSuiteId, PrfAlgorithm};
use crate::client::TlsConfig;
use crate::errors::TlsError;
use crate::storage::{SessionInfo, StekInfo};
use crate::{
    TlsResult,
    alert::TlsAlert,
    connection::ConnState,
    messages::{TlsHandshake, TlsMessage},
};
use client::{
    AwaitClientInitiateState, AwaitNewSessionTicket, AwaitNewSessionTicketOrCertificate,
    AwaitServerCertificate, AwaitServerChangeCipher, AwaitServerChangeCipherOrCertificate,
    AwaitServerFinished, AwaitServerHello, AwaitServerHelloDone,
    AwaitServerHelloDoneOrCertificateRequest, AwaitServerKeyExchange,
    AwaitServerKeyExchangeOrCertificateRequest, ClientAttemptedRenegotiationState,
    ClientEstablished, ExpectNewSessionTicketAbbr, ExpectServerChangeCipherAbbr,
    ExpectServerFinishedAbbr,
};
use server::{
    AwaitCertificateVerify, AwaitClientCertificate, AwaitClientChangeCipher,
    AwaitClientChangeCipherAbbr, AwaitClientFinished, AwaitClientFinishedAbbr, AwaitClientHello,
    AwaitClientKeyExchange, AwaitSessionValidation, AwaitStekInfo, ServerEstablished,
};
use std::sync::Arc;

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
    pub cipher_suite: CipherSuiteId,
    pub max_fragment_len: Option<MaxFragmentLength>,
    pub extended_master_secret: bool,
}

#[derive(Debug)]
pub struct SessionTicketResumption {
    pub session_ticket: Vec<u8>,
    pub master_secret: [u8; 48],
    pub cipher_suite: CipherSuiteId,
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
        server_name: Option<String>,
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
    SendAlert(TlsAlert),
    ChangeCipherSpec(TlsEntity, ConnState),
    SendHandshakeMsg(TlsHandshake),
    GetStekInfo(Vec<u8>),
    ValidateSessionId(Vec<u8>),
    StoreSessionTicketInfo(Vec<u8>, SessionInfo),
    StoreSessionIdInfo(Vec<u8>, SessionInfo),
    InvalidateSessionId(Vec<u8>),
    InvalidateSessionTicket(Vec<u8>),
    CloseConnection(TlsAlertDesc),
    UpdateMaxFragmentLen(MaxFragmentLength),
}

#[derive(Debug, Clone)]
pub struct TlsContext {
    pub side: TlsEntity,
    pub config: Arc<TlsConfig>,
    pub stek: Option<StekInfo>,
}

pub struct TlsStateMachine {
    pub state: Option<TlsState>,
    pub ctx: TlsContext,
}

impl TlsStateMachine {
    pub fn handle(&mut self, event: TlsEvent) -> TlsResult<Vec<TlsAction>> {
        // Fatal alerts are handled the same for all states
        if let TlsEvent::IncomingMessage(TlsMessage::Alert(alert)) = event {
            if alert.is_fatal() {
                let mut actions = vec![];

                // Must reply with close_notify if we receive one
                if alert.is_close_notification() {
                    actions.push(TlsAction::SendAlert(TlsAlert::fatal(
                        TlsAlertDesc::CloseNotify,
                    )));
                }

                // Must invalidate session for fatal alerts
                if let Some(session_id) = self.established_session_id() {
                    actions.push(TlsAction::InvalidateSessionId(session_id));
                }

                actions.push(TlsAction::CloseConnection(alert.description));
                self.state = Some(ClosedState {}.into());
                return Ok(actions);
            }
        }

        let (new_state, actions) = self.state.take().unwrap().handle(&mut self.ctx, event)?;
        self.state = Some(new_state);
        Ok(actions)
    }

    pub fn new(side: TlsEntity, config: Arc<TlsConfig>) -> Self {
        let state: TlsState = match side {
            TlsEntity::Client => AwaitClientInitiateState {
                previous_verify_data: None,
            }
            .into(),
            TlsEntity::Server => AwaitClientHello {
                previous_verify_data: None,
            }
            .into(),
        };

        let stek = config.session_store.as_ref().map(|store| {
            let new_stek = StekInfo::new();
            store
                .insert_stek(&new_stek.key_name.to_vec(), new_stek.clone())
                .expect("failed to create new STEK");
            new_stek
        });

        Self {
            ctx: TlsContext { side, config, stek },
            state: Some(state),
        }
    }

    pub fn is_established(&self) -> bool {
        matches!(
            self.state.as_ref().unwrap(),
            TlsState::ClientEstablished(_) | TlsState::ServerEstablished(_)
        )
    }

    pub fn established_session_id(&self) -> Option<Vec<u8>> {
        match self.state.as_ref().unwrap() {
            TlsState::ClientEstablished(state) => Some(state.session_id.to_vec()),
            TlsState::ServerEstablished(state) => Some(state.session_id.to_vec()),
            _ => None,
        }
    }
}

impl_state_dispatch! {
    pub enum TlsState {
        AwaitClientHello(AwaitClientHello),
        AwaitStekInfo(AwaitStekInfo),
        AwaitSessionValidation(AwaitSessionValidation),
        AwaitClientCertificate(AwaitClientCertificate),
        AwaitClientKeyExchange(AwaitClientKeyExchange),
        AwaitCertificateVerify(AwaitCertificateVerify),
        AwaitClientChangeCipher(AwaitClientChangeCipher),
        AwaitClientFinished(AwaitClientFinished),
        AwaitClientChangeCipherAbbr(AwaitClientChangeCipherAbbr),
        AwaitClientFinishedAbbr(AwaitClientFinishedAbbr),

        AwaitClientInitiate(AwaitClientInitiateState),
        AwaitServerHello(AwaitServerHello),
        AwaitServerCertificate(AwaitServerCertificate),
        AwaitServerKeyExchangeOrCertificateRequest(AwaitServerKeyExchangeOrCertificateRequest),
        AwaitServerKeyExchange(AwaitServerKeyExchange),
        AwaitServerHelloDoneOrCertificateRequest(AwaitServerHelloDoneOrCertificateRequest),
        AwaitServerHelloDone(AwaitServerHelloDone),
        AwaitNewSessionTicket(AwaitNewSessionTicket),
        AwaitNewSessionTicketOrCertificate(AwaitNewSessionTicketOrCertificate),
        AwaitServerChangeCipherOrCertificate(AwaitServerChangeCipherOrCertificate),
        AwaitServerChangeCipher(AwaitServerChangeCipher),
        AwaitServerFinished(AwaitServerFinished),

        ExpectNewSessionTicketAbbr(ExpectNewSessionTicketAbbr),
        ExpectServerChangeCipherAbbr(ExpectServerChangeCipherAbbr),
        ExpectServerFinishedAbbr(ExpectServerFinishedAbbr),

        ClientEstablished(ClientEstablished),
        ServerEstablished(ServerEstablished),
        Closed(ClosedState),

        ClientAttemptedRenegotiation(ClientAttemptedRenegotiationState),
    }
}

type HandleResult<T> = Result<(T, Vec<TlsAction>), TlsError>;

pub trait HandleRecord<T> {
    fn handle(self, ctx: &mut TlsContext, event: TlsEvent) -> HandleResult<T>;
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

pub fn close_with_unexpected_message() -> HandleResult<TlsState> {
    Ok((
        ClosedState {}.into(),
        vec![
            TlsAction::SendAlert(TlsAlert::fatal(TlsAlertDesc::UnexpectedMessage)),
            TlsAction::CloseConnection(TlsAlertDesc::UnexpectedMessage),
        ],
    ))
}

pub fn close_connection(desc: TlsAlertDesc) -> HandleResult<TlsState> {
    Ok((
        ClosedState {}.into(),
        vec![
            TlsAction::SendAlert(TlsAlert::fatal(desc)),
            TlsAction::CloseConnection(desc),
        ],
    ))
}

#[derive(Debug)]
pub struct ClosedState {}

impl HandleRecord<TlsState> for ClosedState {
    fn handle(self, _ctx: &mut TlsContext, event: TlsEvent) -> HandleResult<TlsState> {
        println!("{:?}", event);
        // Maybe get server hello
        // Maybe get alert
        // Maybe get nothing...
        unimplemented!()
    }
}
