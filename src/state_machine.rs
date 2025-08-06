use rsa::{RsaPublicKey, pkcs8::DecodePublicKey};
use std::collections::HashMap;
use std::sync::Arc;

use enum_dispatch::enum_dispatch;
use log::{debug, info};

use crate::alert::TlsAlertDesc;
use crate::ciphersuite::{CipherSuiteId, PrfAlgorithm};
use crate::client::{PrioritisedCipherSuite, TlsConfig};
use crate::errors::TlsError;
use crate::extensions::{
    ExtendedMasterSecretExt, HashAlgo, MaxFragmentLenExt, MaxFragmentLength, RenegotiationInfoExt,
    ServerNameExt, SessionTicketExt, SigAlgo,
};
use crate::messages::{Certificate, ClientHello, ServerHello, SessionId};
use crate::signature::{
    decrypt_rsa_master_secret, dsa_verify, get_dhe_pre_master_secret, get_rsa_pre_master_secret,
    public_key_from_cert, rsa_verify,
};
use crate::storage::SessionInfo;
use crate::{MaxFragmentLengthNegotiationPolicy, RenegotiationPolicy};
use crate::{
    TlsResult,
    alert::TlsAlert,
    ciphersuite::{CipherSuite, CipherSuiteMethods, KeyExchangeAlgorithm},
    connection::{ConnState, InitialConnState, SecureConnState, SecurityParams},
    encoding::TlsCodable,
    messages::{ClientKeyExchange, Finished, TlsHandshake, TlsMessage},
};

#[derive(Debug, Clone)]
pub struct TlsContext {
    pub side: TlsEntity,
    pub config: Arc<TlsConfig>,
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
struct PreviousVerifyData {
    client: Vec<u8>,
    server: Vec<u8>,
}

#[derive(Debug)]
pub struct AwaitClientInitiateState {
    previous_verify_data: Option<PreviousVerifyData>,
}

impl HandleRecord for AwaitClientInitiateState {
    fn handle(self, ctx: &mut TlsContext, event: TlsEvent) -> HandleResult {
        debug_assert_eq!(ctx.side, TlsEntity::Client);

        let TlsEvent::ClientInitiate {
            cipher_suites,
            session_resumption,
            server_name,
            support_session_ticket,
            support_extended_master_secret,
            support_secure_renegotiation,
            max_fragment_len,
        } = event
        else {
            panic!("Expected ClientInitiate event!");
        };

        let mut extensions = vec![];

        // If this is a session resumption we need to send the same max_fragment_length
        // as was previously agreed upon for the session.
        let max_fragment_len_override = match session_resumption {
            SessionResumption::None => max_fragment_len,
            SessionResumption::SessionId(ref info) => info.max_fragment_len,
            SessionResumption::SessionTicket(ref info) => info.max_fragment_len,
        };
        if let Some(len) = max_fragment_len_override {
            extensions.push(MaxFragmentLenExt::new(len).into());
        }

        if support_extended_master_secret {
            extensions.push(ExtendedMasterSecretExt::indicate_support().into());
        }

        if support_secure_renegotiation {
            match &self.previous_verify_data {
                None => extensions.push(RenegotiationInfoExt::indicate_support().into()),
                Some(data) => extensions.push(
                    RenegotiationInfoExt::renegotiation(&data.client)
                        .unwrap()
                        .into(),
                ),
            }
        }

        if let SessionResumption::SessionTicket(info) = &session_resumption {
            extensions.push(SessionTicketExt::resume(info.session_ticket.clone()).into())
        } else if support_session_ticket {
            extensions.push(SessionTicketExt::new().into())
        }

        if let Some(server_name) = &server_name {
            extensions.push(ServerNameExt::new(server_name).into());
        }

        let session_id = match &session_resumption {
            SessionResumption::SessionId(info) => Some(info.session_id.clone()),
            _ => None,
        };

        let client_hello = ClientHello::new(
            cipher_suites.as_ref(),
            extensions,
            session_id.map(|x| SessionId::new(&x).unwrap()),
        )
        .unwrap();

        info!("Sent ClientHello");

        let client_random = client_hello.random.as_bytes();
        let handshake = TlsHandshake::ClientHello(client_hello);
        return Ok((
            AwaitServerHello {
                handshakes: handshake.get_encoding(),
                client_random,
                session_resumption,
                previous_verify_data: self.previous_verify_data,
                proposed_max_fragment_len: max_fragment_len,
            }
            .into(),
            vec![TlsAction::SendHandshakeMsg(handshake)],
        ));
    }
}

fn choose_cipher_suite(
    prioritised: &[PrioritisedCipherSuite],
    offered: &[CipherSuiteId],
) -> CipherSuiteId {
    let mut map: HashMap<CipherSuiteId, u32> = HashMap::new();
    for pcs in prioritised {
        map.insert(pcs.id, pcs.priority);
    }
    let item = offered.iter().max_by_key(|id| map.get(id).unwrap_or(&0u32));
    *item.unwrap()
}

#[derive(Debug)]
pub struct AwaitClientHello {
    previous_verify_data: Option<PreviousVerifyData>,
}

impl HandleRecord for AwaitClientHello {
    fn handle(self, ctx: &mut TlsContext, event: TlsEvent) -> HandleResult {
        let (handshake, client_hello) = require_handshake_msg!(event, TlsHandshake::ClientHello);

        info!("Received ClientHello");
        let mut handshakes = handshake.get_encoding();

        let suites: Vec<_> = client_hello
            .cipher_suites
            .iter()
            .map(|x| CipherSuite::from(*x).params().name)
            .filter(|x| *x != "UNKNOWN")
            .collect();
        debug!("CipherSuites: {:#?}", suites);

        let selected_cipher_suite =
            choose_cipher_suite(&ctx.config.cipher_suites, &client_hello.cipher_suites);

        debug!(
            "Selected CipherSuite {}",
            CipherSuite::from(selected_cipher_suite).params().name
        );

        let max_fragment_len = client_hello.extensions.get_max_fragment_len().filter(|_| {
            ctx.config.policy.max_fragment_length_negotiation
                == MaxFragmentLengthNegotiationPolicy::Support
        });

        // If this is a secure renegotiation we need to send the right renegotation_info
        let renegotiation_info = self
            .previous_verify_data
            .map(|data| [data.client, data.server].concat());

        let server_hello = ServerHello::new(
            selected_cipher_suite,
            client_hello.extensions.includes_secure_renegotiation(),
            client_hello.extensions.includes_extended_master_secret(),
            renegotiation_info,
            max_fragment_len,
        );

        let server_random = server_hello.random.as_bytes();
        let server_hello: TlsHandshake = server_hello.into();
        server_hello.write_to(&mut handshakes);

        let certificate: TlsHandshake = Certificate::new(
            ctx.config
                .certificate
                .as_ref()
                .expect("Server certificate not configured")
                .certificate_der
                .clone(),
        )
        .into();
        certificate.write_to(&mut handshakes);

        let server_hello_done = TlsHandshake::ServerHelloDone;
        server_hello_done.write_to(&mut handshakes);

        info!("Sent ServerHello");
        info!("Sent Certificate");
        info!("Sent ServerHelloDone");
        Ok((
            AwaitClientKeyExchange {
                handshakes,
                client_random: client_hello.random.as_bytes(),
                server_random,
                selected_cipher_suite,
                supported_extensions: SupportedExtensions {
                    session_ticket: false,
                    extended_master_secret: client_hello
                        .extensions
                        .includes_extended_master_secret(),
                    secure_renegotiation: client_hello.extensions.includes_secure_renegotiation(),
                },
            }
            .into(),
            vec![
                TlsAction::SendHandshakeMsg(server_hello),
                TlsAction::SendHandshakeMsg(certificate),
                TlsAction::SendHandshakeMsg(server_hello_done),
            ],
        ))
    }
}

#[derive(Debug)]
struct SupportedExtensions {
    extended_master_secret: bool,

    #[allow(unused)]
    secure_renegotiation: bool,
    session_ticket: bool,
}

#[derive(Debug)]
pub struct AwaitServerHello {
    handshakes: Vec<u8>,
    client_random: [u8; 32],
    session_resumption: SessionResumption,
    previous_verify_data: Option<PreviousVerifyData>,
    proposed_max_fragment_len: Option<MaxFragmentLength>,
}

impl HandleRecord for AwaitServerHello {
    fn handle(mut self, _ctx: &mut TlsContext, event: TlsEvent) -> HandleResult {
        let (handshake, server_hello) = require_handshake_msg!(event, TlsHandshake::ServerHello);

        info!("Received ServerHello");
        handshake.write_to(&mut self.handshakes);

        // For secure renegotiations we need to verify the renegotiation_info
        if let Some(previous_verify_data) = self.previous_verify_data {
            let Some(renegotiation_info) = server_hello.extensions.get_renegotiation_info() else {
                return close_connection(TlsAlertDesc::HandshakeFailure);
            };

            let expected = [previous_verify_data.client, previous_verify_data.server].concat();
            if !(renegotiation_info == expected) {
                return close_connection(TlsAlertDesc::HandshakeFailure);
            }
        }

        let supported_extensions = SupportedExtensions {
            secure_renegotiation: server_hello.supports_secure_renegotiation(),
            extended_master_secret: server_hello.supports_extended_master_secret(),
            session_ticket: server_hello.supports_session_ticket(),
        };

        let mut actions = vec![];
        // Regardless of whether this is a session_resumption or not, we know whether the
        // max_fragment_length needs to be updated for the next message based on whether
        // the server_hello mirrored the client_hello's max_fragment_length.
        let max_fragment_length = match self.proposed_max_fragment_len {
            None => None,
            Some(client_len) => match server_hello.extensions.get_max_fragment_len() {
                None => None,
                Some(server_len) => {
                    if client_len != server_len {
                        return close_connection(TlsAlertDesc::IllegalParameter);
                    }

                    actions.push(TlsAction::UpdateMaxFragmentLen(client_len));
                    Some(client_len)
                }
            },
        };

        // If the server echoed back the session_id sent by the client we're
        // now doing an abbreviated handshake.
        if let SessionResumption::SessionId(info) = &self.session_resumption {
            if info.session_id == server_hello.session_id.to_vec() {
                let params = SecurityParams::new(
                    self.client_random,
                    server_hello.random.as_bytes(),
                    info.master_secret,
                    info.cipher_suite,
                );

                // The server must correctly remember the session's max_fragment_length
                if server_hello.extensions.get_max_fragment_len() != info.max_fragment_len {
                    return close_connection(TlsAlertDesc::IllegalParameter);
                }

                return Ok((
                    AwaitServerChangeCipher {
                        session_id: server_hello.session_id.clone(),
                        handshakes: self.handshakes,
                        supported_extensions,
                        params,
                        client_verify_data: None,
                        is_session_resumption: true,
                        max_fragment_length: info.max_fragment_len,
                    }
                    .into(),
                    actions,
                ));
            }
        }

        // Attempting session resumption with session ticket
        if let SessionResumption::SessionTicket(info) = self.session_resumption {
            // Server will issue a new ticket, but did it accept the session ticket we sent?
            if server_hello.supports_session_ticket() {
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
                        session_id: server_hello.session_id.clone(),
                        handshakes: self.handshakes,
                        client_random: self.client_random,
                        server_random: server_hello.random.as_bytes(),
                        selected_cipher_suite_id: server_hello.cipher_suite,
                        supported_extensions,
                        session_ticket_resumption: info,
                        max_fragment_length,
                    }
                    .into(),
                    actions,
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
                    session_id: server_hello.session_id.clone(),
                    client_random: self.client_random,
                    server_random: server_hello.random.as_bytes(),
                    selected_cipher_suite_id: server_hello.cipher_suite,
                    supported_extensions,
                    handshakes: self.handshakes,
                    session_ticket_resumption: info,
                    max_fragment_length,
                }
                .into(),
                actions,
            ));
        }

        // Boring... no session resumption, we're doing a full handshake.
        let cipher_suite = CipherSuite::from(server_hello.cipher_suite);
        debug!("Selected CipherSuite: {}", cipher_suite.params().name);
        return Ok((
            AwaitServerCertificate {
                session_id: server_hello.session_id.clone(),
                handshakes: self.handshakes,
                client_random: self.client_random,
                server_random: server_hello.random.as_bytes(),
                selected_cipher_suite_id: server_hello.cipher_suite,
                supported_extensions,
                max_fragment_length,
            }
            .into(),
            actions,
        ));
    }
}

#[derive(Debug)]
pub struct AwaitClientKeyExchange {
    handshakes: Vec<u8>,
    client_random: [u8; 32],
    server_random: [u8; 32],
    selected_cipher_suite: CipherSuiteId,
    supported_extensions: SupportedExtensions,
}

impl HandleRecord for AwaitClientKeyExchange {
    fn handle(mut self, ctx: &mut TlsContext, event: TlsEvent) -> HandleResult {
        let (handshake, client_kx) = require_handshake_msg!(event, TlsHandshake::ClientKeyExchange);

        info!("Received ClientKeyExchange");
        handshake.write_to(&mut self.handshakes);

        let Ok(pre_master_secret) = decrypt_rsa_master_secret(
            &ctx.config
                .certificate
                .as_ref()
                .expect("Server private key not configured")
                .private_key,
            &client_kx.enc_pre_master_secret,
        ) else {
            return close_connection(TlsAlertDesc::DecryptError);
        };

        let ciphersuite = CipherSuite::from(self.selected_cipher_suite);
        info!(
            "Using extended master secret: {}",
            self.supported_extensions.extended_master_secret
        );
        let master_secret = calculate_master_secret(
            &self.handshakes,
            &self.client_random,
            &self.server_random,
            &pre_master_secret,
            ciphersuite.params().prf_algorithm,
            self.supported_extensions.extended_master_secret,
        );

        let params = SecurityParams::new(
            self.client_random,
            self.server_random,
            master_secret,
            self.selected_cipher_suite,
        );

        Ok((
            AwaitClientChangeCipher {
                handshakes: self.handshakes,
                params,
                supported_extensions: self.supported_extensions,
            }
            .into(),
            vec![],
        ))
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
    max_fragment_length: Option<MaxFragmentLength>,
}

impl HandleRecord for AwaitServerCertificate {
    fn handle(mut self, _ctx: &mut TlsContext, event: TlsEvent) -> HandleResult {
        let (handshake, certs) = require_handshake_msg!(event, TlsHandshake::Certificates);

        handshake.write_to(&mut self.handshakes);

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
                        server_certificate_der: certs.list[0].to_vec(),
                        max_fragment_length: self.max_fragment_length,
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
                server_certificate_der: certs.list[0].to_vec(),
                secrets: None,
                max_fragment_length: self.max_fragment_length,
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
    server_certificate_der: Vec<u8>,
    max_fragment_length: Option<MaxFragmentLength>,
}

impl HandleRecord for AwaitServerKeyExchange {
    fn handle(mut self, _ctx: &mut TlsContext, event: TlsEvent) -> HandleResult {
        let (handshake, server_kx) = require_handshake_msg!(event, TlsHandshake::ServerKeyExchange);

        info!("Received ServerKeyExchange");

        let Ok(server_public_key_der) = public_key_from_cert(&self.server_certificate_der) else {
            return close_connection(TlsAlertDesc::IllegalParameter);
        };

        let verified = match server_kx.sig_algo {
            SigAlgo::Rsa => {
                let Ok(rsa_public_key) = RsaPublicKey::from_public_key_der(&server_public_key_der)
                else {
                    return close_connection(TlsAlertDesc::IllegalParameter);
                };

                let Ok(verified) = rsa_verify(
                    &rsa_public_key,
                    &[
                        self.client_random.as_ref(),
                        self.server_random.as_ref(),
                        &server_kx.dh_params_bytes(),
                    ]
                    .concat(),
                    &server_kx.signature,
                ) else {
                    return close_connection(TlsAlertDesc::IllegalParameter);
                };

                verified
            }
            SigAlgo::Dsa => {
                assert_eq!(server_kx.hash_algo, HashAlgo::Sha256);
                let Ok(verified) = dsa_verify(
                    &server_public_key_der,
                    &[
                        self.client_random.as_ref(),
                        self.server_random.as_ref(),
                        &server_kx.dh_params_bytes(),
                    ]
                    .concat(),
                    &server_kx.signature,
                ) else {
                    return close_connection(TlsAlertDesc::IllegalParameter);
                };

                verified
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
                server_certificate_der: self.server_certificate_der,
                secrets: Some(DheParams {
                    p: server_kx.p.to_vec(),
                    g: server_kx.g.to_vec(),
                    public_key: server_kx.server_pubkey.to_vec(),
                }),
                max_fragment_length: self.max_fragment_length,
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
    server_certificate_der: Vec<u8>,
    secrets: Option<DheParams>,
    max_fragment_length: Option<MaxFragmentLength>,
}

impl HandleRecord for AwaitServerHelloDone {
    fn handle(mut self, _ctx: &mut TlsContext, event: TlsEvent) -> HandleResult {
        let handshake = require_handshake_msg!(event, TlsHandshake::ServerHelloDone, *);

        info!("Received ServerHelloDone");
        handshake.write_to(&mut self.handshakes);

        let ciphersuite = CipherSuite::from(self.selected_cipher_suite_id);
        let (pre_master_secret, key_exchange_data) = match ciphersuite
            .params()
            .key_exchange_algorithm
        {
            KeyExchangeAlgorithm::Rsa => {
                let Ok(server_public_key_der) = public_key_from_cert(&self.server_certificate_der)
                else {
                    return close_connection(TlsAlertDesc::IllegalParameter);
                };

                let Ok(rsa_public_key) = RsaPublicKey::from_public_key_der(&server_public_key_der)
                else {
                    return close_connection(TlsAlertDesc::IllegalParameter);
                };

                let Ok((secret, enc_secret)) = get_rsa_pre_master_secret(&rsa_public_key) else {
                    return close_connection(TlsAlertDesc::DecryptError);
                };

                (secret, enc_secret)
            }
            KeyExchangeAlgorithm::DheRsa | KeyExchangeAlgorithm::DheDss => {
                let DheParams { p, g, public_key } = self.secrets.as_ref().unwrap();
                get_dhe_pre_master_secret(p, g, public_key)
            }
            KeyExchangeAlgorithm::EcdheRsa => unimplemented!(),
        };

        let client_kx = ClientKeyExchange::new(&key_exchange_data);
        TlsHandshake::ClientKeyExchange(client_kx.clone()).write_to(&mut self.handshakes);

        let master_secret = calculate_master_secret(
            &self.handshakes,
            &self.client_random,
            &self.server_random,
            &pre_master_secret,
            ciphersuite.params().prf_algorithm,
            self.supported_extensions.extended_master_secret,
        );
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
                    max_fragment_length: self.max_fragment_length,
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
                max_fragment_length: self.max_fragment_length,
            }
            .into(),
            actions,
        ))
    }
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
pub struct AwaitNewSessionTicket {
    session_id: SessionId,
    handshakes: Vec<u8>,
    supported_extensions: SupportedExtensions,
    params: SecurityParams,
    is_session_resumption: bool,
    client_verify_data: Option<Vec<u8>>,
    max_fragment_length: Option<MaxFragmentLength>,
}

impl HandleRecord for AwaitNewSessionTicket {
    fn handle(mut self, _: &mut TlsContext, event: TlsEvent) -> HandleResult {
        let (handshake, new_session_ticket) =
            require_handshake_msg!(event, TlsHandshake::NewSessionTicket);

        info!("Received NewSessionTicket");
        handshake.write_to(&mut self.handshakes);

        let action = TlsAction::StoreSessionTicketInfo(
            new_session_ticket.ticket.to_vec(),
            SessionInfo::new(
                self.params.master_secret,
                self.params.cipher_suite_id,
                self.max_fragment_length,
            ),
        );

        return Ok((
            AwaitServerChangeCipher {
                session_id: self.session_id,
                handshakes: self.handshakes,
                supported_extensions: self.supported_extensions,
                client_verify_data: self.client_verify_data,
                params: self.params,
                is_session_resumption: self.is_session_resumption,
                max_fragment_length: self.max_fragment_length,
            }
            .into(),
            vec![action],
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
    session_ticket_resumption: SessionTicketResumption,
    max_fragment_length: Option<MaxFragmentLength>,
}

impl HandleRecord for AwaitNewSessionTicketOrCertificate {
    fn handle(self, ctx: &mut TlsContext, event: TlsEvent) -> HandleResult {
        // Session resumption accepted
        if let TlsEvent::IncomingMessage(TlsMessage::Handshake(TlsHandshake::NewSessionTicket(_))) =
            event
        {
            let params = SecurityParams::new(
                self.client_random,
                self.server_random,
                self.session_ticket_resumption.master_secret,
                self.session_ticket_resumption.cipher_suite,
            );

            // The ClientHello and ServerHello resulted in a different max_fragment_length
            // from what was decided for this session.
            if self.session_ticket_resumption.max_fragment_len != self.max_fragment_length {
                return close_connection(TlsAlertDesc::IllegalParameter);
            }

            return AwaitNewSessionTicket {
                session_id: self.session_id,
                handshakes: self.handshakes,
                supported_extensions: self.supported_extensions,
                client_verify_data: None,
                is_session_resumption: true,
                params,
                max_fragment_length: self.session_ticket_resumption.max_fragment_len,
            }
            .handle(ctx, event);
        } else if let TlsEvent::IncomingMessage(TlsMessage::Handshake(
            TlsHandshake::Certificates(_),
        )) = event
        {
            return AwaitServerCertificate {
                session_id: self.session_id,
                handshakes: self.handshakes,
                client_random: self.client_random,
                server_random: self.server_random,
                selected_cipher_suite_id: self.selected_cipher_suite_id,
                supported_extensions: self.supported_extensions,
                max_fragment_length: self.max_fragment_length,
            }
            .handle(ctx, event);
        }

        return close_with_unexpected_message();
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
    session_ticket_resumption: SessionTicketResumption,
    max_fragment_length: Option<MaxFragmentLength>,
}

impl HandleRecord for AwaitServerChangeCipherOrCertificate {
    fn handle(self, ctx: &mut TlsContext, event: TlsEvent) -> HandleResult {
        if let TlsEvent::IncomingMessage(TlsMessage::ChangeCipherSpec) = event {
            let params = SecurityParams::new(
                self.client_random,
                self.server_random,
                self.session_ticket_resumption.master_secret,
                self.session_ticket_resumption.cipher_suite,
            );

            // The ClientHello and ServerHello resulted in a different max_fragment_length
            // from what was decided for this session.
            if self.session_ticket_resumption.max_fragment_len != self.max_fragment_length {
                return close_connection(TlsAlertDesc::IllegalParameter);
            }

            return AwaitServerChangeCipher {
                session_id: self.session_id,
                handshakes: self.handshakes,
                supported_extensions: self.supported_extensions,
                params,
                client_verify_data: None,
                is_session_resumption: true,
                max_fragment_length: self.max_fragment_length,
            }
            .handle(ctx, event);
        } else if let TlsEvent::IncomingMessage(TlsMessage::Handshake(
            TlsHandshake::Certificates(_),
        )) = event
        {
            return AwaitServerCertificate {
                session_id: self.session_id,
                handshakes: self.handshakes,
                client_random: self.client_random,
                server_random: self.server_random,
                selected_cipher_suite_id: self.selected_cipher_suite_id,
                supported_extensions: self.supported_extensions,
                max_fragment_length: self.max_fragment_length,
            }
            .handle(ctx, event);
        }
        panic!("invalid transition");
    }
}

#[derive(Debug)]
pub struct AwaitClientChangeCipher {
    handshakes: Vec<u8>,
    params: SecurityParams,
    supported_extensions: SupportedExtensions,
}

impl HandleRecord for AwaitClientChangeCipher {
    fn handle(self, _ctx: &mut TlsContext, event: TlsEvent) -> HandleResult {
        let TlsEvent::IncomingMessage(TlsMessage::ChangeCipherSpec) = event else {
            return close_with_unexpected_message();
        };

        info!("Received ChangeCipherSpec");
        let keys = self.params.derive_keys();
        let read = ConnState::Secure(SecureConnState::new(
            self.params.clone(),
            keys.client_enc_key,
            keys.client_mac_key,
            keys.client_write_iv,
        ));

        Ok((
            AwaitClientFinished {
                handshakes: self.handshakes,
                params: self.params,
                supported_extensions: self.supported_extensions,
            }
            .into(),
            vec![TlsAction::ChangeCipherSpec(TlsEntity::Client, read)],
        ))
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
    max_fragment_length: Option<MaxFragmentLength>,
}

impl HandleRecord for AwaitServerChangeCipher {
    fn handle(self, _ctx: &mut TlsContext, event: TlsEvent) -> HandleResult {
        let TlsEvent::IncomingMessage(TlsMessage::ChangeCipherSpec) = event else {
            return close_with_unexpected_message();
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
                max_fragment_length: self.max_fragment_length,
            }
            .into(),
            vec![TlsAction::ChangeCipherSpec(TlsEntity::Server, read)],
        ))
    }
}

#[derive(Debug)]
pub struct AwaitClientFinished {
    handshakes: Vec<u8>,
    params: SecurityParams,
    supported_extensions: SupportedExtensions,
}

impl HandleRecord for AwaitClientFinished {
    fn handle(mut self, _ctx: &mut TlsContext, event: TlsEvent) -> HandleResult {
        let (handshake, finished) = require_handshake_msg!(event, TlsHandshake::Finished);

        info!("Received ClientFinished");
        let client_verify_data = self.params.client_verify_data(&self.handshakes);
        assert_eq!(client_verify_data, finished.verify_data);
        handshake.write_to(&mut self.handshakes);

        let keys = self.params.derive_keys();
        let write = ConnState::Secure(SecureConnState::new(
            self.params.clone(),
            keys.server_enc_key,
            keys.server_mac_key,
            keys.server_write_iv,
        ));

        let server_verify_data = self.params.server_verify_data(&self.handshakes);
        let server_finished: TlsHandshake = Finished::new(server_verify_data.clone()).into();

        info!("Sent ChangeCipherSpec");
        info!("Sent ServerFinished");
        info!("Handshake complete! (full)");
        Ok((
            EstablishedState {
                session_id: SessionId::new(&[]).unwrap(),
                supported_extensions: self.supported_extensions,
                client_verify_data,
                server_verify_data,
            }
            .into(),
            vec![
                TlsAction::ChangeCipherSpec(TlsEntity::Server, write),
                TlsAction::SendHandshakeMsg(server_finished),
            ],
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
    max_fragment_length: Option<MaxFragmentLength>,
}

impl HandleRecord for AwaitServerFinished {
    fn handle(mut self, _: &mut TlsContext, event: TlsEvent) -> HandleResult {
        let (handshake, server_finished) = require_handshake_msg!(event, TlsHandshake::Finished);
        info!("Received ServerFinished");

        let server_verify_data = self.params.server_verify_data(&self.handshakes);
        assert_eq!(server_verify_data, server_finished.verify_data);
        handshake.write_to(&mut self.handshakes);

        if !self.is_session_resumption {
            info!("Handshake complete! (full)");

            let mut actions = vec![];
            if !self.session_id.is_empty() {
                actions.push(TlsAction::StoreSessionIdInfo(
                    self.session_id.to_vec(),
                    SessionInfo {
                        master_secret: self.params.master_secret,
                        cipher_suite: self.params.cipher_suite_id,
                        max_fragment_len: self.max_fragment_length,
                    },
                ));
            }

            return Ok((
                EstablishedState {
                    session_id: self.session_id,
                    supported_extensions: self.supported_extensions,
                    client_verify_data: self.client_verify_data.unwrap(),
                    server_verify_data,
                }
                .into(),
                actions,
            ));
        }

        let keys = self.params.derive_keys();
        let write = ConnState::Secure(SecureConnState::new(
            self.params.clone(),
            keys.client_enc_key,
            keys.client_mac_key,
            keys.client_write_iv,
        ));

        let client_verify_data = self.params.client_verify_data(&self.handshakes);
        let client_finished = Finished::new(client_verify_data.clone());

        info!("Sent ChangeCipherSpec");
        info!("Sent ClientFinished");
        info!("Handshake complete! (abbreviated)");
        Ok((
            EstablishedState {
                session_id: self.session_id,
                supported_extensions: self.supported_extensions,
                client_verify_data,
                server_verify_data,
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

fn close_with_unexpected_message() -> HandleResult {
    Ok((
        ClosedState {}.into(),
        vec![
            TlsAction::SendAlert(TlsAlert::fatal(TlsAlertDesc::UnexpectedMessage)),
            TlsAction::CloseConnection(TlsAlertDesc::UnexpectedMessage),
        ],
    ))
}

fn close_connection(desc: TlsAlertDesc) -> HandleResult {
    Ok((
        ClosedState {}.into(),
        vec![
            TlsAction::SendAlert(TlsAlert::fatal(desc)),
            TlsAction::CloseConnection(desc),
        ],
    ))
}

#[derive(Debug)]
pub struct ClientAttemptedRenegotiationState {}

impl HandleRecord for ClientAttemptedRenegotiationState {
    fn handle(self, _ctx: &mut TlsContext, _event: TlsEvent) -> HandleResult {
        // Maybe get server hello
        // Maybe get alert
        // Maybe get nothing...
        unimplemented!()
    }
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
