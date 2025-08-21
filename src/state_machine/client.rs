use log::{debug, error, info, trace};
use num_bigint::BigUint;
use rand::prelude::SliceRandom;
use rand::seq::IteratorRandom;
use rsa::{RsaPublicKey, pkcs8::DecodePublicKey};
use std::collections::HashSet;
use x509_parser::parse_x509_certificate;
use x509_parser::{prelude::FromDer, x509::X509Name};

use crate::alert::TlsAlertDesc;
use crate::ca::validate_certificate_chain;
use crate::ciphersuite::{CipherSuiteId, KeyExchangeAlgorithm, KeyExchangeType};
use crate::extensions::{
    ExtendedMasterSecretExt, ExtensionType, HashAlgo, MaxFragmentLenExt, MaxFragmentLength,
    RenegotiationInfoExt, ServerNameExt, SessionTicketExt, SignatureAlgorithm,
    SignatureAlgorithmsExt, sign, verify,
};
use crate::messages::{
    Certificate, CertificateRequest, CertificateVerify, ClientHello, DigitallySigned,
    ServerDHParams, ServerKeyExchangeInner, SessionId,
};
use crate::oid::extract_dh_params;
use crate::signature::{get_dh_pre_master_secret, get_rsa_pre_master_secret, public_key_from_cert};
use crate::state_machine::{
    NegotiatedExtensions, SessionResumption, TlsAction, TlsEntity, calculate_master_secret,
    close_connection,
};
use crate::storage::SessionInfo;
use crate::{
    alert::TlsAlert,
    ciphersuite::CipherSuite,
    connection::{ConnState, SecurityParams},
    encoding::TlsCodable,
    messages::{ClientKeyExchange, Finished, TlsHandshake, TlsMessage},
};

use super::{
    HandleRecord, HandleResult, PreviousVerifyData, SessionTicketResumption, TlsContext, TlsEvent,
    TlsState, close_with_unexpected_message,
};

#[derive(Debug)]
pub struct AwaitClientInitiateState {
    // The verify_data's from the previous handshake. This only has a
    // Some value in the case of a secure renegotiation.
    pub previous_verify_data: Option<PreviousVerifyData>,
}

impl HandleRecord<TlsState> for AwaitClientInitiateState {
    fn handle(self, ctx: &mut TlsContext, event: TlsEvent) -> HandleResult<TlsState> {
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

        extensions.push(SignatureAlgorithmsExt::new(&ctx.config.signature_algorithms).into());
        // println!("Client Extensions {:?}", extensions);

        let client_hello = ClientHello::new(
            cipher_suites.as_ref(),
            extensions,
            session_id.map(|x| SessionId::new(&x).unwrap()),
        )
        .unwrap();

        info!("Sent ClientHello");

        let client_random = client_hello.random.as_bytes();
        let client_extension_set = client_hello.extensions.extension_type_set();
        let handshake = TlsHandshake::ClientHello(client_hello);
        Ok((
            AwaitServerHello {
                handshakes: handshake.get_encoding(),
                client_random,
                session_resumption,
                previous_verify_data: self.previous_verify_data,
                proposed_max_fragment_len: max_fragment_len,
                client_extension_set,
            }
            .into(),
            vec![TlsAction::SendHandshakeMsg(handshake)],
        ))
    }
}

#[derive(Debug)]
pub struct AwaitServerHello {
    handshakes: Vec<u8>,
    client_random: [u8; 32],
    session_resumption: SessionResumption,
    previous_verify_data: Option<PreviousVerifyData>,
    proposed_max_fragment_len: Option<MaxFragmentLength>,
    client_extension_set: HashSet<ExtensionType>,
}

impl HandleRecord<TlsState> for AwaitServerHello {
    fn handle(mut self, _ctx: &mut TlsContext, event: TlsEvent) -> HandleResult<TlsState> {
        let (handshake, server_hello) = require_handshake_msg!(event, TlsHandshake::ServerHello);

        info!("Received ServerHello");

        if !server_hello.version.is_tls12() {
            return close_connection(TlsAlertDesc::ProtocolVersion);
        }

        handshake.write_to(&mut self.handshakes);

        // For secure renegotiations we need to verify the renegotiation_info
        if let Some(previous_verify_data) = self.previous_verify_data {
            let Some(renegotiation_info) = server_hello.extensions.get_renegotiation_info() else {
                return close_connection(TlsAlertDesc::HandshakeFailure);
            };

            let expected = [previous_verify_data.client, previous_verify_data.server].concat();
            if renegotiation_info != expected {
                return close_connection(TlsAlertDesc::HandshakeFailure);
            }
        }

        // Check that ServerHello only includes a subset of the extensions sent in ClientHello
        let server_extension_set = server_hello.extensions.extension_type_set();
        let server_only_extensions: HashSet<_> = server_extension_set
            .difference(&self.client_extension_set)
            .collect();
        if !server_only_extensions.is_empty() {
            trace!(
                "Server included extensions not sent by the Client: {:?}",
                server_only_extensions
            );
            return close_connection(TlsAlertDesc::UnsupportedExtension);
        }

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
        if let SessionResumption::SessionId(session) = &self.session_resumption {
            if session.session_id == server_hello.session_id.to_vec() {
                let params = SecurityParams::new(
                    self.client_random,
                    server_hello.random.as_bytes(),
                    session.master_secret,
                    session.cipher_suite,
                );

                // The server must correctly remember the session's max_fragment_length
                if server_hello.extensions.get_max_fragment_len() != session.max_fragment_len {
                    return close_connection(TlsAlertDesc::IllegalParameter);
                }

                // The server must correctly remember the session's ems use
                if server_hello.extensions.includes_extended_master_secret()
                    != session.extended_master_secret
                {
                    return close_connection(TlsAlertDesc::IllegalParameter);
                }

                let supported_extensions = NegotiatedExtensions {
                    secure_renegotiation: server_hello.supports_secure_renegotiation(),
                    extended_master_secret: server_hello.supports_extended_master_secret(),
                    session_ticket: server_hello.supports_session_ticket(),
                    max_fragment_length: session.max_fragment_len,
                };

                return Ok((
                    ExpectServerChangeCipherAbbr {
                        session_id: server_hello.session_id.clone(),
                        handshakes: self.handshakes,
                        negotiated_extensions: supported_extensions,
                        params,
                    }
                    .into(),
                    actions,
                ));
            } else {
                actions.push(TlsAction::InvalidateSessionId(session.session_id.clone()))
            }
        }

        let negotiated_extensions = NegotiatedExtensions {
            secure_renegotiation: server_hello.supports_secure_renegotiation(),
            extended_master_secret: server_hello.supports_extended_master_secret(),
            session_ticket: server_hello.supports_session_ticket(),
            max_fragment_length,
        };

        // Attempting session resumption with session ticket
        if let SessionResumption::SessionTicket(session) = self.session_resumption {
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
                        negotiated_extensions,
                        session_ticket_resumption: session,
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
                    negotiated_extensions,
                    handshakes: self.handshakes,
                    session_ticket_resumption: session,
                }
                .into(),
                actions,
            ));
        }

        // Boring... no session resumption, we're doing a full handshake.
        let cipher_suite = CipherSuite::from(server_hello.cipher_suite);
        debug!("Selected CipherSuite: {}", cipher_suite.name());

        if !cipher_suite.kx_algorithm().sends_server_certificate() {
            return Ok((
                AwaitServerKeyExchange {
                    session_id: server_hello.session_id.clone(),
                    handshakes: self.handshakes,
                    client_random: self.client_random,
                    server_random: server_hello.random.as_bytes(),
                    selected_cipher_suite_id: cipher_suite.id(),
                    negotiated_extensions,
                    server_certificate_der: None,
                    client_certificate_request: None,
                }
                .into(),
                vec![],
            ));
        }

        Ok((
            AwaitServerCertificate {
                session_id: server_hello.session_id.clone(),
                handshakes: self.handshakes,
                client_random: self.client_random,
                server_random: server_hello.random.as_bytes(),
                selected_cipher_suite_id: server_hello.cipher_suite,
                negotiated_extensions,
            }
            .into(),
            actions,
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
    negotiated_extensions: NegotiatedExtensions,
}

impl HandleRecord<TlsState> for AwaitServerCertificate {
    fn handle(mut self, ctx: &mut TlsContext, event: TlsEvent) -> HandleResult<TlsState> {
        let (handshake, certs) = require_handshake_msg!(event, TlsHandshake::Certificates);

        handshake.write_to(&mut self.handshakes);

        let mut chain = vec![];
        for x in certs.list.iter() {
            chain.push(x.to_vec());
        }

        if ctx.config.policy.verify_server {
            if let Err(e) =
                validate_certificate_chain(chain, ctx.config.server_name.clone().unwrap())
            {
                error!("{:?}", e);
                return close_connection(TlsAlertDesc::BadCertificate);
            }
        }

        let cipher_suite = CipherSuite::from(self.selected_cipher_suite_id);
        match cipher_suite.kx_algorithm().kx_type() {
            KeyExchangeType::Dhe => {
                return Ok((
                    AwaitServerKeyExchangeOrCertificateRequest {
                        session_id: self.session_id,
                        handshakes: self.handshakes,
                        client_random: self.client_random,
                        server_random: self.server_random,
                        selected_cipher_suite_id: self.selected_cipher_suite_id,
                        negotiated_extensions: self.negotiated_extensions,
                        server_certificate_der: certs.list[0].to_vec(),
                    }
                    .into(),
                    vec![],
                ));
            }
            KeyExchangeType::Rsa => {}
            KeyExchangeType::Dh => {}
            _ => unimplemented!(),
        }

        Ok((
            AwaitServerHelloDoneOrCertificateRequest {
                session_id: self.session_id,
                handshakes: self.handshakes,
                client_random: self.client_random,
                server_random: self.server_random,
                selected_cipher_suite_id: self.selected_cipher_suite_id,
                negotiated_extensions: self.negotiated_extensions,
                server_certificate_der: Some(certs.list[0].to_vec()),
                secrets: None,
            }
            .into(),
            vec![],
        ))
    }
}

#[derive(Debug)]
pub struct AwaitServerKeyExchangeOrCertificateRequest {
    session_id: SessionId,
    handshakes: Vec<u8>,
    client_random: [u8; 32],
    server_random: [u8; 32],
    selected_cipher_suite_id: CipherSuiteId,
    negotiated_extensions: NegotiatedExtensions,
    server_certificate_der: Vec<u8>,
}

impl HandleRecord<TlsState> for AwaitServerKeyExchangeOrCertificateRequest {
    fn handle(mut self, ctx: &mut TlsContext, event: TlsEvent) -> HandleResult<TlsState> {
        match event {
            // TODO: use certificate request contents
            TlsEvent::IncomingMessage(TlsMessage::Handshake(
                handshake @ TlsHandshake::CertificateRequest(certificate_request),
            )) => {
                handshake.write_to(&mut self.handshakes);
                Ok((
                    AwaitServerKeyExchange {
                        session_id: self.session_id,
                        handshakes: self.handshakes,
                        client_random: self.client_random,
                        server_random: self.server_random,
                        selected_cipher_suite_id: self.selected_cipher_suite_id,
                        negotiated_extensions: self.negotiated_extensions,
                        server_certificate_der: Some(self.server_certificate_der),
                        client_certificate_request: Some(CertificateRequestParams::new(
                            certificate_request,
                        )),
                    }
                    .into(),
                    vec![],
                ))
            }
            TlsEvent::IncomingMessage(TlsMessage::Handshake(TlsHandshake::ServerKeyExchange(
                _,
            ))) => AwaitServerKeyExchange {
                session_id: self.session_id,
                handshakes: self.handshakes,
                client_random: self.client_random,
                server_random: self.server_random,
                selected_cipher_suite_id: self.selected_cipher_suite_id,
                negotiated_extensions: self.negotiated_extensions,
                server_certificate_der: Some(self.server_certificate_der),
                client_certificate_request: None,
            }
            .handle(ctx, event),
            _ => close_with_unexpected_message(),
        }
    }
}

#[derive(Debug)]
struct CertificateRequestParams {
    supported_signature_algorithms: Vec<SignatureAlgorithm>,
    certificate_authorities: Vec<Vec<u8>>,
}

impl CertificateRequestParams {
    pub fn new(request: &CertificateRequest) -> Self {
        Self {
            supported_signature_algorithms: request.supported_signature_algorithms.to_vec(),
            certificate_authorities: request
                .certificate_authorities
                .iter()
                .map(|x| x.to_vec())
                .collect(),
        }
    }
}

#[derive(Debug)]
pub struct AwaitServerKeyExchange {
    session_id: SessionId,
    handshakes: Vec<u8>,
    client_random: [u8; 32],
    server_random: [u8; 32],
    selected_cipher_suite_id: CipherSuiteId,
    negotiated_extensions: NegotiatedExtensions,
    server_certificate_der: Option<Vec<u8>>,
    client_certificate_request: Option<CertificateRequestParams>,
}

impl HandleRecord<TlsState> for AwaitServerKeyExchange {
    fn handle(mut self, _ctx: &mut TlsContext, event: TlsEvent) -> HandleResult<TlsState> {
        let (handshake, server_kx) = require_handshake_msg!(event, TlsHandshake::ServerKeyExchange);

        info!("Received ServerKeyExchange");

        let cipher_suite = CipherSuite::from(self.selected_cipher_suite_id);
        let secrets = match server_kx.resolve(cipher_suite.kx_algorithm()) {
            ServerKeyExchangeInner::Dhe(server_kx) => {
                let Ok(server_public_key_der) =
                    public_key_from_cert(&self.server_certificate_der.as_ref().unwrap())
                else {
                    return close_connection(TlsAlertDesc::IllegalParameter);
                };
                let message = [
                    self.client_random.as_ref(),
                    self.server_random.as_ref(),
                    &server_kx.params.get_encoding(),
                ]
                .concat();

                let Ok(verified) = verify(
                    server_kx.signed_params.signature_algorithm,
                    server_kx.signed_params.hash_algorithm,
                    &server_public_key_der,
                    &message,
                    &server_kx.signed_params.signature,
                ) else {
                    return close_connection(TlsAlertDesc::IllegalParameter);
                };

                if !verified {
                    return close_connection(TlsAlertDesc::DecryptError);
                }
                server_kx.params.clone()
            }
            ServerKeyExchangeInner::DhAnon(params) => params.clone(),
        };

        handshake.write_to(&mut self.handshakes);

        Ok((
            AwaitServerHelloDone {
                session_id: self.session_id,
                handshakes: self.handshakes,
                client_random: self.client_random,
                server_random: self.server_random,
                selected_cipher_suite_id: self.selected_cipher_suite_id,
                negotiated_extensions: self.negotiated_extensions,
                server_certificate_der: self.server_certificate_der,
                secrets: Some(secrets),
                client_certificate_request: self.client_certificate_request,
            }
            .into(),
            vec![],
        ))
    }
}

#[derive(Debug)]
pub struct AwaitServerHelloDoneOrCertificateRequest {
    session_id: SessionId,
    handshakes: Vec<u8>,
    client_random: [u8; 32],
    server_random: [u8; 32],
    selected_cipher_suite_id: CipherSuiteId,
    negotiated_extensions: NegotiatedExtensions,
    server_certificate_der: Option<Vec<u8>>,
    secrets: Option<ServerDHParams>,
}

impl HandleRecord<TlsState> for AwaitServerHelloDoneOrCertificateRequest {
    fn handle(mut self, ctx: &mut TlsContext, event: TlsEvent) -> HandleResult<TlsState> {
        match event {
            // TODO: use certificate request contents
            TlsEvent::IncomingMessage(TlsMessage::Handshake(
                handshake @ TlsHandshake::CertificateRequest(certificate_request),
            )) => {
                handshake.write_to(&mut self.handshakes);
                Ok((
                    AwaitServerHelloDone {
                        session_id: self.session_id,
                        handshakes: self.handshakes,
                        client_random: self.client_random,
                        server_random: self.server_random,
                        selected_cipher_suite_id: self.selected_cipher_suite_id,
                        negotiated_extensions: self.negotiated_extensions,
                        server_certificate_der: self.server_certificate_der,
                        secrets: self.secrets,
                        client_certificate_request: Some(CertificateRequestParams::new(
                            certificate_request,
                        )),
                    }
                    .into(),
                    vec![],
                ))
            }
            TlsEvent::IncomingMessage(TlsMessage::Handshake(TlsHandshake::ServerHelloDone)) => {
                AwaitServerHelloDone {
                    session_id: self.session_id,
                    handshakes: self.handshakes,
                    client_random: self.client_random,
                    server_random: self.server_random,
                    selected_cipher_suite_id: self.selected_cipher_suite_id,
                    negotiated_extensions: self.negotiated_extensions,
                    server_certificate_der: self.server_certificate_der,
                    secrets: self.secrets,
                    client_certificate_request: None,
                }
                .handle(ctx, event)
            }
            _ => close_with_unexpected_message(),
        }
    }
}

#[derive(Debug)]
pub struct AwaitServerHelloDone {
    session_id: SessionId,
    handshakes: Vec<u8>,
    client_random: [u8; 32],
    server_random: [u8; 32],
    selected_cipher_suite_id: CipherSuiteId,
    negotiated_extensions: NegotiatedExtensions,
    server_certificate_der: Option<Vec<u8>>,
    secrets: Option<ServerDHParams>,
    client_certificate_request: Option<CertificateRequestParams>,
}

impl HandleRecord<TlsState> for AwaitServerHelloDone {
    fn handle(mut self, ctx: &mut TlsContext, event: TlsEvent) -> HandleResult<TlsState> {
        let handshake = require_handshake_msg!(event, TlsHandshake::ServerHelloDone, *);

        info!("Received ServerHelloDone");
        handshake.write_to(&mut self.handshakes);

        let mut actions = vec![];

        let mut verify_cert = None;
        let mut chosen_hash_algo = HashAlgo::Sha1;
        if let Some(cert_request) = &self.client_certificate_request {
            let sig_set: HashSet<_> = cert_request
                .supported_signature_algorithms
                .iter()
                .map(|item| item.signature)
                .collect();

            let dn_set: HashSet<_> = cert_request
                .certificate_authorities
                .iter()
                .cloned()
                .collect();

            let suitable_certs = ctx
                .config
                .certificates
                .certificates()
                .into_iter()
                .filter(|cert| sig_set.contains(&cert.signature_algorithm()))
                .collect::<Vec<_>>();

            let suitable_certs = suitable_certs
                .into_iter()
                .filter(|cert| dn_set.is_empty() || dn_set.contains(&cert.distinguished_name_der))
                .collect::<Vec<_>>();

            let client_certificate = TlsHandshake::Certificates(
                suitable_certs
                    .choose(&mut rand::thread_rng())
                    .map(|cert| {
                        println!("{:?}", cert_request.supported_signature_algorithms);
                        let signature_algorithm = cert_request
                            .supported_signature_algorithms
                            .iter()
                            .filter(|x| x.signature == cert.signature_algorithm())
                            .choose(&mut rand::thread_rng())
                            .unwrap();

                        trace!("Chose signature algorithm: {:?}", signature_algorithm);
                        trace!(
                            "Distinguished name: {}",
                            X509Name::from_der(&cert.distinguished_name_der).unwrap().1
                        );
                        verify_cert = Some((*cert).clone());
                        chosen_hash_algo = signature_algorithm.hash;

                        Certificate::new(cert.certificate_der.clone())
                    })
                    .unwrap_or_else(|| {
                        trace!("No client ceritificate matches certificate request");
                        Certificate::empty()
                    }),
            );

            client_certificate.write_to(&mut self.handshakes);
            actions.push(TlsAction::SendHandshakeMsg(client_certificate));
            info!("Sent ClientCertificate");
        }

        let ciphersuite = CipherSuite::from(self.selected_cipher_suite_id);
        let (pre_master_secret, client_kx) = match ciphersuite.kx_algorithm() {
            KeyExchangeAlgorithm::Rsa => {
                let Ok(server_public_key_der) =
                    public_key_from_cert(&self.server_certificate_der.unwrap())
                else {
                    return close_connection(TlsAlertDesc::IllegalParameter);
                };

                let Ok(rsa_public_key) = RsaPublicKey::from_public_key_der(&server_public_key_der)
                else {
                    return close_connection(TlsAlertDesc::IllegalParameter);
                };

                let Ok((pms, enc_pms)) = get_rsa_pre_master_secret(&rsa_public_key) else {
                    return close_connection(TlsAlertDesc::DecryptError);
                };

                (pms, ClientKeyExchange::new_rsa(&enc_pms))
            }
            KeyExchangeAlgorithm::DheDss
            | KeyExchangeAlgorithm::DheRsa
            | KeyExchangeAlgorithm::DhAnon => {
                let ServerDHParams {
                    p,
                    g,
                    server_public_key,
                } = self.secrets.as_ref().unwrap();

                let p = BigUint::from_bytes_be(p);
                let g = BigUint::from_bytes_be(g);
                let server_public_key = BigUint::from_bytes_be(server_public_key);
                let (pms, client_public_key) = get_dh_pre_master_secret(&p, &g, &server_public_key);
                (pms, ClientKeyExchange::new_dhe(&client_public_key))
            }
            KeyExchangeAlgorithm::DhDss | KeyExchangeAlgorithm::DhRsa => {
                let cert = parse_x509_certificate(&self.server_certificate_der.as_ref().unwrap())
                    .unwrap()
                    .1;
                let (p, g, public_key) = extract_dh_params(&cert).unwrap();
                let (pms, client_public_key) = get_dh_pre_master_secret(&p, &g, &public_key);
                (pms, ClientKeyExchange::new_dhe(&client_public_key))
            }
            KeyExchangeAlgorithm::EcdheRsa => unimplemented!(),
            KeyExchangeAlgorithm::Null => unimplemented!(),
        };

        let client_kx = TlsHandshake::ClientKeyExchange(client_kx);
        client_kx.write_to(&mut self.handshakes);
        actions.push(TlsAction::SendHandshakeMsg(client_kx));
        info!("Sent ClientKeyExchange");

        let master_secret = calculate_master_secret(
            &self.handshakes,
            &self.client_random,
            &self.server_random,
            &pre_master_secret,
            ciphersuite.prf_algorithm(),
            self.negotiated_extensions.extended_master_secret,
        );
        //println!("MS: {:?}", master_secret);

        if let Some(cert) = verify_cert {
            if self.client_certificate_request.is_some() {
                let signature = sign(
                    cert.signature_algorithm(),
                    chosen_hash_algo,
                    &cert.private_key_der,
                    &self.handshakes,
                )
                .unwrap();
                let certificate_verify = TlsHandshake::CertificateVerify(CertificateVerify {
                    signed: DigitallySigned {
                        hash_algorithm: chosen_hash_algo,
                        signature_algorithm: cert.signature_algorithm(),
                        signature: signature.try_into().unwrap(),
                    },
                });
                certificate_verify.write_to(&mut self.handshakes);
                actions.push(TlsAction::SendHandshakeMsg(certificate_verify));
                info!("Sent CertificateVerify");
            }
        }

        let params = SecurityParams::new(
            self.client_random,
            self.server_random,
            master_secret,
            self.selected_cipher_suite_id,
        );
        let write = ConnState::new(params.clone(), TlsEntity::Client);

        let verify_data = params.client_verify_data(&self.handshakes);
        let client_finished = Finished::new(verify_data.clone());
        let client_finished = TlsHandshake::Finished(client_finished);
        client_finished.write_to(&mut self.handshakes);

        actions.extend([
            TlsAction::ChangeCipherSpec(TlsEntity::Client, write),
            TlsAction::SendHandshakeMsg(client_finished),
        ]);
        info!("Sent ChangeCipherSuite");
        info!("Sent ClientFinished");

        if self.negotiated_extensions.session_ticket {
            return Ok((
                AwaitNewSessionTicket {
                    session_id: self.session_id,
                    handshakes: self.handshakes,
                    negotiated_extensions: self.negotiated_extensions,
                    client_verify_data: verify_data,
                    params,
                }
                .into(),
                actions,
            ));
        }

        Ok((
            AwaitServerChangeCipher {
                session_id: self.session_id,
                session_ticket: None,
                handshakes: self.handshakes,
                negotiated_extensions: self.negotiated_extensions,
                client_verify_data: verify_data,
                params,
            }
            .into(),
            actions,
        ))
    }
}
#[derive(Debug)]
pub struct AwaitNewSessionTicket {
    session_id: SessionId,
    handshakes: Vec<u8>,
    negotiated_extensions: NegotiatedExtensions,
    params: SecurityParams,
    client_verify_data: Vec<u8>,
}

impl HandleRecord<TlsState> for AwaitNewSessionTicket {
    fn handle(mut self, _: &mut TlsContext, event: TlsEvent) -> HandleResult<TlsState> {
        let (handshake, new_session_ticket) =
            require_handshake_msg!(event, TlsHandshake::NewSessionTicket);

        info!("Received NewSessionTicket");
        handshake.write_to(&mut self.handshakes);

        Ok((
            AwaitServerChangeCipher {
                session_id: self.session_id,
                session_ticket: Some(new_session_ticket.ticket.to_vec()),
                handshakes: self.handshakes,
                negotiated_extensions: self.negotiated_extensions,
                client_verify_data: self.client_verify_data,
                params: self.params,
            }
            .into(),
            vec![],
        ))
    }
}

#[derive(Debug)]
pub struct AwaitNewSessionTicketOrCertificate {
    session_id: SessionId,
    handshakes: Vec<u8>,
    client_random: [u8; 32],
    server_random: [u8; 32],
    selected_cipher_suite_id: CipherSuiteId,
    negotiated_extensions: NegotiatedExtensions,
    session_ticket_resumption: SessionTicketResumption,
}

impl HandleRecord<TlsState> for AwaitNewSessionTicketOrCertificate {
    fn handle(self, ctx: &mut TlsContext, event: TlsEvent) -> HandleResult<TlsState> {
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
            if self.session_ticket_resumption.max_fragment_len
                != self.negotiated_extensions.max_fragment_length
            {
                return close_connection(TlsAlertDesc::IllegalParameter);
            }

            if self.session_ticket_resumption.extended_master_secret
                != self.negotiated_extensions.extended_master_secret
            {
                return close_connection(TlsAlertDesc::IllegalParameter);
            }

            if self.session_ticket_resumption.cipher_suite != self.selected_cipher_suite_id {
                return close_connection(TlsAlertDesc::IllegalParameter);
            }

            return ExpectNewSessionTicketAbbr {
                session_id: self.session_id,
                handshakes: self.handshakes,
                negotiated_extensions: self.negotiated_extensions,
                params,
            }
            .handle(ctx, event);
        } else if let TlsEvent::IncomingMessage(TlsMessage::Handshake(
            TlsHandshake::Certificates(_),
        )) = event
        {
            let next_state = AwaitServerCertificate {
                session_id: self.session_id,
                handshakes: self.handshakes,
                client_random: self.client_random,
                server_random: self.server_random,
                selected_cipher_suite_id: self.selected_cipher_suite_id,
                negotiated_extensions: self.negotiated_extensions,
            }
            .handle(ctx, event);

            return prepend_action(
                next_state,
                TlsAction::InvalidateSessionTicket(self.session_ticket_resumption.session_ticket),
            );
        }

        close_with_unexpected_message()
    }
}

fn prepend_action(result: HandleResult<TlsState>, action: TlsAction) -> HandleResult<TlsState> {
    result.map(|(state, mut actions)| {
        actions.insert(0, action);
        (state, actions)
    })
}

#[derive(Debug)]
pub struct AwaitServerChangeCipherOrCertificate {
    session_id: SessionId,
    handshakes: Vec<u8>,
    client_random: [u8; 32],
    server_random: [u8; 32],
    selected_cipher_suite_id: CipherSuiteId,
    negotiated_extensions: NegotiatedExtensions,
    session_ticket_resumption: SessionTicketResumption,
}

impl HandleRecord<TlsState> for AwaitServerChangeCipherOrCertificate {
    fn handle(self, ctx: &mut TlsContext, event: TlsEvent) -> HandleResult<TlsState> {
        if let TlsEvent::IncomingMessage(TlsMessage::ChangeCipherSpec) = event {
            let params = SecurityParams::new(
                self.client_random,
                self.server_random,
                self.session_ticket_resumption.master_secret,
                self.session_ticket_resumption.cipher_suite,
            );

            // The ClientHello and ServerHello resulted in a different max_fragment_length
            // from what was decided for this session.
            if self.session_ticket_resumption.max_fragment_len
                != self.negotiated_extensions.max_fragment_length
            {
                return close_connection(TlsAlertDesc::IllegalParameter);
            }

            if self.session_ticket_resumption.extended_master_secret
                != self.negotiated_extensions.extended_master_secret
            {
                return close_connection(TlsAlertDesc::IllegalParameter);
            }

            if self.session_ticket_resumption.cipher_suite != self.selected_cipher_suite_id {
                return close_connection(TlsAlertDesc::IllegalParameter);
            }

            return ExpectServerChangeCipherAbbr {
                session_id: self.session_id,
                handshakes: self.handshakes,
                negotiated_extensions: self.negotiated_extensions,
                params,
            }
            .handle(ctx, event);
        } else if let TlsEvent::IncomingMessage(TlsMessage::Handshake(
            TlsHandshake::Certificates(_),
        )) = event
        {
            let next_state = AwaitServerCertificate {
                session_id: self.session_id,
                handshakes: self.handshakes,
                client_random: self.client_random,
                server_random: self.server_random,
                selected_cipher_suite_id: self.selected_cipher_suite_id,
                negotiated_extensions: self.negotiated_extensions,
            }
            .handle(ctx, event);

            return prepend_action(
                next_state,
                TlsAction::InvalidateSessionTicket(self.session_ticket_resumption.session_ticket),
            );
        }
        panic!("invalid transition");
    }
}

#[derive(Debug)]
pub struct AwaitServerChangeCipher {
    session_id: SessionId,
    session_ticket: Option<Vec<u8>>,
    handshakes: Vec<u8>,
    negotiated_extensions: NegotiatedExtensions,
    client_verify_data: Vec<u8>,
    params: SecurityParams,
}

impl HandleRecord<TlsState> for AwaitServerChangeCipher {
    fn handle(self, _ctx: &mut TlsContext, event: TlsEvent) -> HandleResult<TlsState> {
        let TlsEvent::IncomingMessage(TlsMessage::ChangeCipherSpec) = event else {
            return close_with_unexpected_message();
        };

        info!("Received ChangeCipherSpec");
        let read = ConnState::new(self.params.clone(), TlsEntity::Server);

        Ok((
            AwaitServerFinished {
                session_id: self.session_id,
                session_ticket: self.session_ticket,
                handshakes: self.handshakes,
                negotiated_extensions: self.negotiated_extensions,
                client_verify_data: self.client_verify_data,
                params: self.params,
            }
            .into(),
            vec![TlsAction::ChangeCipherSpec(TlsEntity::Server, read)],
        ))
    }
}

#[derive(Debug)]
pub struct AwaitServerFinished {
    session_id: SessionId,
    session_ticket: Option<Vec<u8>>,
    handshakes: Vec<u8>,
    negotiated_extensions: NegotiatedExtensions,
    params: SecurityParams,
    client_verify_data: Vec<u8>,
}

impl HandleRecord<TlsState> for AwaitServerFinished {
    fn handle(mut self, _: &mut TlsContext, event: TlsEvent) -> HandleResult<TlsState> {
        let (handshake, server_finished) = require_handshake_msg!(event, TlsHandshake::Finished);
        info!("Received ServerFinished");

        let server_verify_data = self.params.server_verify_data(&self.handshakes);
        if server_verify_data != server_finished.verify_data {
            return close_connection(TlsAlertDesc::DecryptError);
        }
        handshake.write_to(&mut self.handshakes);

        info!("Handshake complete! (full)");

        let mut actions = vec![];
        if let Some(session_ticket) = self.session_ticket {
            actions.push(TlsAction::StoreSessionTicketInfo(
                session_ticket,
                SessionInfo::new(
                    self.params.master_secret,
                    self.params.cipher_suite_id,
                    self.negotiated_extensions.max_fragment_length,
                    self.negotiated_extensions.extended_master_secret,
                ),
            ));
        }

        if !self.session_id.is_empty() {
            actions.push(TlsAction::StoreSessionIdInfo(
                self.session_id.to_vec(),
                SessionInfo {
                    master_secret: self.params.master_secret,
                    cipher_suite: self.params.cipher_suite_id,
                    max_fragment_len: self.negotiated_extensions.max_fragment_length,
                    extended_master_secret: self.negotiated_extensions.extended_master_secret,
                },
            ));
        }

        Ok((
            ClientEstablished {
                session_id: self.session_id,
                supported_extensions: self.negotiated_extensions,
                client_verify_data: self.client_verify_data,
                server_verify_data,
            }
            .into(),
            actions,
        ))
    }
}

#[derive(Debug)]
pub struct ExpectNewSessionTicketAbbr {
    session_id: SessionId,
    handshakes: Vec<u8>,
    negotiated_extensions: NegotiatedExtensions,
    params: SecurityParams,
}

impl HandleRecord<TlsState> for ExpectNewSessionTicketAbbr {
    fn handle(mut self, _: &mut TlsContext, event: TlsEvent) -> HandleResult<TlsState> {
        let (handshake, new_session_ticket) =
            require_handshake_msg!(event, TlsHandshake::NewSessionTicket);

        info!("Received NewSessionTicket ");
        handshake.write_to(&mut self.handshakes);

        let action = TlsAction::StoreSessionTicketInfo(
            new_session_ticket.ticket.to_vec(),
            SessionInfo::new(
                self.params.master_secret,
                self.params.cipher_suite_id,
                self.negotiated_extensions.max_fragment_length,
                self.negotiated_extensions.extended_master_secret,
            ),
        );

        Ok((
            ExpectServerChangeCipherAbbr {
                session_id: self.session_id,
                handshakes: self.handshakes,
                negotiated_extensions: self.negotiated_extensions,
                params: self.params,
            }
            .into(),
            vec![action],
        ))
    }
}

#[derive(Debug)]
pub struct ExpectServerChangeCipherAbbr {
    session_id: SessionId,
    handshakes: Vec<u8>,
    negotiated_extensions: NegotiatedExtensions,
    params: SecurityParams,
}

impl HandleRecord<TlsState> for ExpectServerChangeCipherAbbr {
    fn handle(self, _ctx: &mut TlsContext, event: TlsEvent) -> HandleResult<TlsState> {
        let TlsEvent::IncomingMessage(TlsMessage::ChangeCipherSpec) = event else {
            return close_with_unexpected_message();
        };

        info!("Received ChangeCipherSpec");
        let read = ConnState::new(self.params.clone(), TlsEntity::Server);

        Ok((
            ExpectServerFinishedAbbr {
                session_id: self.session_id,
                handshakes: self.handshakes,
                negotiated_extensions: self.negotiated_extensions,
                params: self.params,
            }
            .into(),
            vec![TlsAction::ChangeCipherSpec(TlsEntity::Server, read)],
        ))
    }
}

#[derive(Debug)]
pub struct ExpectServerFinishedAbbr {
    session_id: SessionId,
    handshakes: Vec<u8>,
    negotiated_extensions: NegotiatedExtensions,
    params: SecurityParams,
}

impl HandleRecord<TlsState> for ExpectServerFinishedAbbr {
    fn handle(mut self, _: &mut TlsContext, event: TlsEvent) -> HandleResult<TlsState> {
        let (handshake, server_finished) = require_handshake_msg!(event, TlsHandshake::Finished);
        info!("Received ServerFinished");

        let server_verify_data = self.params.server_verify_data(&self.handshakes);
        if server_verify_data != server_finished.verify_data {
            return close_connection(TlsAlertDesc::DecryptError);
        }
        handshake.write_to(&mut self.handshakes);

        let write = ConnState::new(self.params.clone(), TlsEntity::Client);

        let client_verify_data = self.params.client_verify_data(&self.handshakes);
        let client_finished = Finished::new(client_verify_data.clone());

        info!("Sent ChangeCipherSpec");
        info!("Sent ClientFinished");
        info!("Handshake complete! (abbr)");
        Ok((
            ClientEstablished {
                session_id: self.session_id,
                supported_extensions: self.negotiated_extensions,
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
pub struct ClientEstablished {
    pub session_id: SessionId,
    #[allow(unused)]
    supported_extensions: NegotiatedExtensions,
    pub server_verify_data: Vec<u8>,
    pub client_verify_data: Vec<u8>,
}

impl HandleRecord<TlsState> for ClientEstablished {
    fn handle(self, ctx: &mut TlsContext, event: TlsEvent) -> HandleResult<TlsState> {
        if let TlsEvent::IncomingMessage(TlsMessage::ApplicationData(data)) = event {
            println!("{:?}", String::from_utf8_lossy(data));
            return Ok((self.into(), vec![]));
        }

        // TODO:
        // The server may choose to ignore a renegotiation or simply
        // send a warning alert in which case it will remain in the established
        // state. The client needs to transition back to the established state
        // if it sees the server isn't willing to renegotiate, but doesn't want
        // to close the connection either.
        AwaitClientInitiateState {
            previous_verify_data: Some(PreviousVerifyData {
                client: self.client_verify_data,
                server: self.server_verify_data,
            }),
        }
        .handle(ctx, event)
    }
}

#[derive(Debug)]
pub struct ClientAttemptedRenegotiationState {}

impl HandleRecord<TlsState> for ClientAttemptedRenegotiationState {
    fn handle(self, _ctx: &mut TlsContext, _event: TlsEvent) -> HandleResult<TlsState> {
        // Maybe get server hello
        // Maybe get alert
        // Maybe get nothing...
        unimplemented!()
    }
}
