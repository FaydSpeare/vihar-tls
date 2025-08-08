use client::{
    AwaitClientInitiateState, AwaitNewSessionTicket, AwaitNewSessionTicketOrCertificate,
    AwaitServerCertificate, AwaitServerChangeCipher, AwaitServerChangeCipherOrCertificate,
    AwaitServerFinished, AwaitServerHello, AwaitServerHelloDone, AwaitServerKeyExchange,
    ClientAttemptedRenegotiationState, ExpectNewSessionTicketAbbr, ExpectServerChangeCipherAbbr,
    ExpectServerFinishedAbbr,
};
use server::{
    AwaitClientChangeCipher, AwaitClientFinished, AwaitClientHello, AwaitClientKeyExchange,
};
use std::sync::Arc;

use enum_dispatch::enum_dispatch;

use crate::alert::TlsAlertDesc;
use crate::ciphersuite::{CipherSuiteId, PrfAlgorithm};
use crate::client::TlsConfig;
use crate::errors::TlsError;
use crate::messages::SessionId;
use crate::storage::SessionInfo;
use crate::{MaxFragmentLength, RenegotiationPolicy};
use crate::{
    TlsResult,
    alert::TlsAlert,
    connection::ConnState,
    messages::{TlsHandshake, TlsMessage},
};

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
}

#[derive(Debug)]
pub struct SessionTicketResumption {
    pub session_ticket: Vec<u8>,
    pub master_secret: [u8; 48],
    pub cipher_suite: CipherSuiteId,
    pub max_fragment_len: Option<MaxFragmentLength>,
}

#[derive(Debug)]
pub enum SessionResumption {
    None,
    SessionId(SessionIdResumption),
    SessionTicket(SessionTicketResumption),
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
    SessionValidation,
}

#[derive(Debug)]
pub enum TlsAction {
    SendAlert(TlsAlert),
    ChangeCipherSpec(TlsEntity, ConnState),
    SendHandshakeMsg(TlsHandshake),
    ValidateSession,
    StoreSessionTicketInfo(Vec<u8>, SessionInfo),
    StoreSessionIdInfo(Vec<u8>, SessionInfo),
    CloseConnection(TlsAlertDesc),
    UpdateMaxFragmentLen(MaxFragmentLength),
}

#[derive(Debug, Clone)]
pub struct TlsContext {
    pub side: TlsEntity,
    pub config: Arc<TlsConfig>,
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
                self.state = Some(ClosedState {}.into());
                return Ok(vec![TlsAction::CloseConnection(alert.description)]);
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
        Self {
            ctx: TlsContext { side, config },
            state: Some(state),
        }
    }

    pub fn is_established(&self) -> bool {
        match self.state.as_ref().unwrap() {
            TlsState::Established(_) => true,
            _ => false,
        }
    }
}

#[enum_dispatch]
#[derive(Debug)]
pub enum TlsState {
    AwaitClientHello,
    AwaitClientKeyExchange(AwaitClientKeyExchange),
    AwaitClientChangeCipher(AwaitClientChangeCipher),
    AwaitClientFinished(AwaitClientFinished),

    AwaitClientInitiate(AwaitClientInitiateState),
    AwaitServerHello(AwaitServerHello),
    AwaitServerCertificate(AwaitServerCertificate),
    AwaitServerKeyExchange(AwaitServerKeyExchange),
    AwaitServerHelloDone(AwaitServerHelloDone),
    AwaitNewSessionTicket(AwaitNewSessionTicket),
    AwaitNewSessionTicketOrCertificate,
    AwaitServerChangeCipherOrCertificate,
    AwaitServerChangeCipher(AwaitServerChangeCipher),
    AwaitServerFinished(AwaitServerFinished),

    ExpectNewSessionTicketAbbr,
    ExpectServerChangeCipherAbbr,
    ExpectServerFinishedAbbr,

    Established(EstablishedState),
    Closed(ClosedState),

    ClientAttemptedRenegotiation(ClientAttemptedRenegotiationState),
}

impl TlsState {
    pub fn as_established(&self) -> TlsResult<&EstablishedState> {
        match self {
            Self::Established(s) => Ok(s),
            _ => Err("not in established state".into()),
        }
    }
}

type HandleResult = Result<(TlsState, Vec<TlsAction>), TlsError>;

#[enum_dispatch(TlsState)]
pub trait HandleRecord {
    fn handle(self, ctx: &mut TlsContext, event: TlsEvent) -> HandleResult;
}

#[derive(Debug)]
pub struct PreviousVerifyData {
    client: Vec<u8>,
    server: Vec<u8>,
}

#[derive(Debug)]
struct SupportedExtensions {
    extended_master_secret: bool,

    #[allow(unused)]
    secure_renegotiation: bool,
    session_ticket: bool,
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
pub struct EstablishedState {
    pub session_id: SessionId,
    #[allow(unused)]
    supported_extensions: SupportedExtensions,
    pub server_verify_data: Vec<u8>,
    pub client_verify_data: Vec<u8>,
}

impl HandleRecord for EstablishedState {
    fn handle(self, ctx: &mut TlsContext, event: TlsEvent) -> HandleResult {
        if let TlsEvent::IncomingMessage(TlsMessage::ApplicationData(data)) = event {
            println!("{:?}", String::from_utf8_lossy(data));
            return Ok((self.into(), vec![]));
        }

        if ctx.side == TlsEntity::Client {
            // TODO:
            // The server may choose to ignore a renegotiation or simply
            // send a warning alert in which case it will remain in the established
            // state. The client needs to transition back to the established state
            // if it sees the server isn't willing to renegotiate, but doesn't want
            // to close the connection either.
            return AwaitClientInitiateState {
                previous_verify_data: Some(PreviousVerifyData {
                    client: self.client_verify_data,
                    server: self.server_verify_data,
                }),
            }
            .handle(ctx, event);
        }

        let (_, client_hello) = require_handshake_msg!(event, TlsHandshake::ClientHello);

        // TODO:
        // Add options to simply ignore client renegotiation or simply send a warning.
        match ctx.config.policy.renegotiation {
            RenegotiationPolicy::None => {
                return close_connection(TlsAlertDesc::NoRenegotiation);
            }
            RenegotiationPolicy::OnlyLegacy => {
                if client_hello.extensions.includes_secure_renegotiation() {
                    return close_connection(TlsAlertDesc::HandshakeFailure);
                }
                return AwaitClientHello {
                    previous_verify_data: None,
                }
                .handle(ctx, event);
            }
            RenegotiationPolicy::OnlySecure => {
                if let Some(info) = client_hello.extensions.get_renegotiation_info() {
                    if info != self.client_verify_data {
                        return close_connection(TlsAlertDesc::NoRenegotiation);
                    }

                    return AwaitClientHello {
                        previous_verify_data: Some(PreviousVerifyData {
                            client: self.client_verify_data,
                            server: self.server_verify_data,
                        }),
                    }
                    .handle(ctx, event);
                }
                return close_connection(TlsAlertDesc::NoRenegotiation);
            }
        }
    }
}

pub fn close_with_unexpected_message() -> HandleResult {
    Ok((
        ClosedState {}.into(),
        vec![
            TlsAction::SendAlert(TlsAlert::fatal(TlsAlertDesc::UnexpectedMessage)),
            TlsAction::CloseConnection(TlsAlertDesc::UnexpectedMessage),
        ],
    ))
}

pub fn close_connection(desc: TlsAlertDesc) -> HandleResult {
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

impl HandleRecord for ClosedState {
    fn handle(self, _ctx: &mut TlsContext, event: TlsEvent) -> HandleResult {
        println!("{:?}", event);
        // Maybe get server hello
        // Maybe get alert
        // Maybe get nothing...
        unimplemented!()
    }
}
