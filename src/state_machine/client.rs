use log::{debug, error, info, trace};
use rand::seq::IteratorRandom;
use std::collections::HashSet;
use std::time::Instant;

use crate::alert::AlertDesc;
use crate::ca::validate_certificate_chain;
use crate::ciphersuite::KeyExchangeAlgorithm;
use crate::client::{CertificateAndPrivateKey, Certificates, PublicKeyAlgorithm};
use crate::extensions::{
    ExtendedMasterSecretExt, ExtensionType, MaxFragmentLenExt, MaxFragmentLength,
    RenegotiationInfoExt, ServerNameExt, SessionTicketExt, SignatureAlgorithm,
    SignatureAlgorithmsExt, sign, verify,
};
use crate::messages::{
    Certificate, CertificateRequest, CertificateVerify, ClientHello, ServerDhParams,
    ServerKeyExchangeInner, SessionId,
};
use crate::oid::{ServerCertificate, deconstruct_dh_key, extract_dh_params};
use crate::signature::{get_dh_pre_master_secret, get_rsa_pre_master_secret};
use crate::state_machine::{
    NegotiatedExtensions, SessionResumption, TlsAction, TlsEntity, calculate_master_secret,
};
use crate::storage::SessionInfo;
use crate::{
    ciphersuite::CipherSuite,
    connection::{ConnState, SecurityParams},
    encoding::TlsCodable,
    messages::{ClientKeyExchange, Finished, TlsHandshake, TlsMessage},
};

use super::{
    ClientContext, ClientState, HandleEvent, HandleResult, PreviousVerifyData,
    SessionTicketResumption, TlsEvent,
};

#[derive(Debug)]
pub struct ExpectClientInitiateState {
    // The verify_data's from the previous handshake. This only has a
    // Some value in the case of a secure renegotiation.
    pub previous_verify_data: Option<PreviousVerifyData>,
}

impl HandleEvent<ClientContext, ClientState> for ExpectClientInitiateState {
    fn handle(self, ctx: &mut ClientContext, event: TlsEvent) -> HandleResult<ClientState> {
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
                Some(data) => {
                    extensions.push(RenegotiationInfoExt::renegotiation(&data.client).into())
                }
            }
        }

        if let SessionResumption::SessionTicket(info) = &session_resumption {
            extensions.push(SessionTicketExt::resume(info.session_ticket.clone()).into())
        } else if support_session_ticket {
            extensions.push(SessionTicketExt::new().into())
        }

        extensions.push(ServerNameExt::new(&server_name).into());

        let session_id = match &session_resumption {
            SessionResumption::SessionId(info) => Some(info.session_id.clone()),
            _ => None,
        };

        extensions
            .push(SignatureAlgorithmsExt::new(&ctx.config.supported_signature_algorithms).into());
        // println!("Client Extensions {:?}", extensions);

        let client_hello = ClientHello::new(
            cipher_suites.as_ref(),
            extensions,
            session_id.map(|x| SessionId::new(&x).unwrap()),
        );

        info!("Sent ClientHello");

        let client_random = client_hello.random.as_bytes();
        let client_extension_set = client_hello.extensions.extension_type_set();
        let handshake = TlsHandshake::ClientHello(client_hello);
        Ok((
            ExpectServerHello {
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
pub struct ExpectServerHello {
    handshakes: Vec<u8>,
    client_random: [u8; 32],
    session_resumption: SessionResumption,
    previous_verify_data: Option<PreviousVerifyData>,
    proposed_max_fragment_len: Option<MaxFragmentLength>,
    client_extension_set: HashSet<ExtensionType>,
}

impl HandleEvent<ClientContext, ClientState> for ExpectServerHello {
    fn handle(mut self, _ctx: &mut ClientContext, event: TlsEvent) -> HandleResult<ClientState> {
        let (handshake, server_hello) = require_handshake_msg!(event, TlsHandshake::ServerHello);

        info!("Received ServerHello");

        if !server_hello.version.is_tls12() {
            return Err(AlertDesc::ProtocolVersion);
        }

        handshake.write_to(&mut self.handshakes);

        // For secure renegotiations we need to verify the renegotiation_info
        if let Some(previous_verify_data) = self.previous_verify_data {
            let Some(renegotiation_info) = server_hello.extensions.get_renegotiation_info() else {
                return Err(AlertDesc::HandshakeFailure);
            };

            let expected = [previous_verify_data.client, previous_verify_data.server].concat();
            if renegotiation_info != expected {
                return Err(AlertDesc::HandshakeFailure);
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
            return Err(AlertDesc::UnsupportedExtension);
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
                        return Err(AlertDesc::IllegalParameter);
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
                let security_params = SecurityParams::new(
                    self.client_random,
                    server_hello.random.as_bytes(),
                    session.master_secret,
                    &CipherSuite::from(session.cipher_suite_id),
                );

                // The server must correctly remember the session's max_fragment_length
                if server_hello.extensions.get_max_fragment_len() != session.max_fragment_len {
                    return Err(AlertDesc::IllegalParameter);
                }

                // The server must correctly remember the session's ems use
                if server_hello.extensions.includes_extended_master_secret()
                    != session.extended_master_secret
                {
                    return Err(AlertDesc::IllegalParameter);
                }

                let negotiated_extensions = NegotiatedExtensions {
                    secure_renegotiation: server_hello.supports_secure_renegotiation(),
                    extended_master_secret: server_hello.supports_extended_master_secret(),
                    session_ticket: server_hello.supports_session_ticket(),
                    max_fragment_length: session.max_fragment_len,
                };

                return Ok((
                    ExpectServerChangeCipherAbbr {
                        session_id: server_hello.session_id.clone(),
                        handshakes: self.handshakes,
                        negotiated_extensions,
                        security_params,
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
                    ExpectNewSessionTicketOrCertificate {
                        session_id: server_hello.session_id.clone(),
                        handshakes: self.handshakes,
                        client_random: self.client_random,
                        server_random: server_hello.random.as_bytes(),
                        negotiated_cipher_suite: CipherSuite::from(server_hello.cipher_suite),
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
                ExpectServerChangeCipherOrCertificate {
                    session_id: server_hello.session_id.clone(),
                    client_random: self.client_random,
                    server_random: server_hello.random.as_bytes(),
                    negotiated_cipher_suite: CipherSuite::from(server_hello.cipher_suite),
                    negotiated_extensions,
                    handshakes: self.handshakes,
                    session_ticket_resumption: session,
                }
                .into(),
                actions,
            ));
        }

        // Boring... no session resumption, we're doing a full handshake.
        let negotiated_cipher_suite = CipherSuite::from(server_hello.cipher_suite);
        debug!("Selected CipherSuite: {}", negotiated_cipher_suite.name());

        // No server certificate for dh_anon...
        if !negotiated_cipher_suite
            .kx_algorithm()
            .sends_server_certificate()
        {
            return Ok((
                ExpectServerKeyExchange {
                    session_id: server_hello.session_id.clone(),
                    handshakes: self.handshakes,
                    client_random: self.client_random,
                    server_random: server_hello.random.as_bytes(),
                    negotiated_cipher_suite,
                    negotiated_extensions,
                    server_certificate: None,
                    client_certificate_request: None,
                }
                .into(),
                actions,
            ));
        }

        Ok((
            ExpectServerCertificate {
                session_id: server_hello.session_id.clone(),
                handshakes: self.handshakes,
                client_random: self.client_random,
                server_random: server_hello.random.as_bytes(),
                negotiated_cipher_suite: CipherSuite::from(server_hello.cipher_suite),
                negotiated_extensions,
            }
            .into(),
            actions,
        ))
    }
}

#[derive(Debug)]
pub struct ExpectServerCertificate {
    session_id: SessionId,
    handshakes: Vec<u8>,
    client_random: [u8; 32],
    server_random: [u8; 32],
    negotiated_cipher_suite: CipherSuite,
    negotiated_extensions: NegotiatedExtensions,
}

impl HandleEvent<ClientContext, ClientState> for ExpectServerCertificate {
    fn handle(mut self, ctx: &mut ClientContext, event: TlsEvent) -> HandleResult<ClientState> {
        let (handshake, certs) = require_handshake_msg!(event, TlsHandshake::Certificate);
        info!("Received ServerCertificate");

        handshake.write_to(&mut self.handshakes);

        let mut chain = vec![];
        for x in certs.list.iter() {
            chain.push(x.to_vec());
        }

        if ctx.config.policy.verify_server {
            if let Err(e) = validate_certificate_chain(chain, ctx.config.server_name.clone()) {
                error!("{:?}", e);
                return Err(AlertDesc::BadCertificate);
            }
        }

        match self.negotiated_cipher_suite.kx_algorithm() {
            KeyExchangeAlgorithm::DheDss
            | KeyExchangeAlgorithm::DheRsa
            | KeyExchangeAlgorithm::DhAnon => {
                return Ok((
                    ExpectServerKeyExchangeOrCertificateRequest {
                        session_id: self.session_id,
                        handshakes: self.handshakes,
                        client_random: self.client_random,
                        server_random: self.server_random,
                        negotiated_cipher_suite: self.negotiated_cipher_suite,
                        negotiated_extensions: self.negotiated_extensions,
                        server_certificate: ServerCertificate::from_der(&certs.list[0])
                            .map_err(|_| AlertDesc::BadCertificate)?,
                    }
                    .into(),
                    vec![],
                ));
            }
            _ => {}
        }

        Ok((
            ExpectServerHelloDoneOrCertificateRequest {
                session_id: self.session_id,
                handshakes: self.handshakes,
                client_random: self.client_random,
                server_random: self.server_random,
                negotiated_cipher_suite: self.negotiated_cipher_suite,
                negotiated_extensions: self.negotiated_extensions,
                server_certificate: Some(
                    ServerCertificate::from_der(&certs.list[0])
                        .map_err(|_| AlertDesc::BadCertificate)?,
                ),
                secrets: None,
            }
            .into(),
            vec![],
        ))
    }
}

#[derive(Debug)]
pub struct ExpectServerKeyExchangeOrCertificateRequest {
    session_id: SessionId,
    handshakes: Vec<u8>,
    client_random: [u8; 32],
    server_random: [u8; 32],
    negotiated_cipher_suite: CipherSuite,
    negotiated_extensions: NegotiatedExtensions,
    server_certificate: ServerCertificate,
}

impl HandleEvent<ClientContext, ClientState> for ExpectServerKeyExchangeOrCertificateRequest {
    fn handle(mut self, ctx: &mut ClientContext, event: TlsEvent) -> HandleResult<ClientState> {
        match event {
            TlsEvent::IncomingMessage(TlsMessage::Handshake(
                handshake @ TlsHandshake::CertificateRequest(certificate_request),
            )) => {
                // Anonymous servers are not permitted to request a client certificate
                if self.negotiated_cipher_suite.kx_algorithm() == KeyExchangeAlgorithm::DhAnon {
                    return Err(AlertDesc::HandshakeFailure);
                }

                handshake.write_to(&mut self.handshakes);
                Ok((
                    ExpectServerKeyExchange {
                        session_id: self.session_id,
                        handshakes: self.handshakes,
                        client_random: self.client_random,
                        server_random: self.server_random,
                        negotiated_cipher_suite: self.negotiated_cipher_suite,
                        negotiated_extensions: self.negotiated_extensions,
                        server_certificate: Some(self.server_certificate),
                        client_certificate_request: Some(certificate_request.clone()),
                    }
                    .into(),
                    vec![],
                ))
            }
            TlsEvent::IncomingMessage(TlsMessage::Handshake(TlsHandshake::ServerKeyExchange(
                _,
            ))) => ExpectServerKeyExchange {
                session_id: self.session_id,
                handshakes: self.handshakes,
                client_random: self.client_random,
                server_random: self.server_random,
                negotiated_cipher_suite: self.negotiated_cipher_suite,
                negotiated_extensions: self.negotiated_extensions,
                server_certificate: Some(self.server_certificate),
                client_certificate_request: None,
            }
            .handle(ctx, event),
            _ => Err(AlertDesc::UnexpectedMessage),
        }
    }
}

#[derive(Debug)]
pub struct ExpectServerKeyExchange {
    session_id: SessionId,
    handshakes: Vec<u8>,
    client_random: [u8; 32],
    server_random: [u8; 32],
    negotiated_cipher_suite: CipherSuite,
    negotiated_extensions: NegotiatedExtensions,
    server_certificate: Option<ServerCertificate>,
    client_certificate_request: Option<CertificateRequest>,
}

impl HandleEvent<ClientContext, ClientState> for ExpectServerKeyExchange {
    fn handle(mut self, _ctx: &mut ClientContext, event: TlsEvent) -> HandleResult<ClientState> {
        let (handshake, server_kx) = require_handshake_msg!(event, TlsHandshake::ServerKeyExchange);

        info!("Received ServerKeyExchange");

        let dh_params = match server_kx.resolve(self.negotiated_cipher_suite.kx_algorithm()) {
            ServerKeyExchangeInner::Dhe(server_kx) => {
                let server_public_key_der = self
                    .server_certificate
                    .as_ref()
                    .expect("server certificate must be present for this kx")
                    .public_key_der();

                let message = [
                    self.client_random.as_ref(),
                    self.server_random.as_ref(),
                    &server_kx.params.get_encoding(),
                ]
                .concat();

                let verified = verify(
                    server_kx.signed_params.signature_algorithm,
                    &server_public_key_der,
                    &message,
                    &server_kx.signed_params.signature,
                )
                .map_err(|_| AlertDesc::IllegalParameter)?;

                if !verified {
                    return Err(AlertDesc::DecryptError);
                }
                server_kx.params.clone()
            }
            ServerKeyExchangeInner::DhAnon(dh_params) => dh_params.clone(),
        };

        handshake.write_to(&mut self.handshakes);

        Ok((
            ExpectServerHelloDone {
                session_id: self.session_id,
                handshakes: self.handshakes,
                client_random: self.client_random,
                server_random: self.server_random,
                negotiated_cipher_suite: self.negotiated_cipher_suite,
                negotiated_extensions: self.negotiated_extensions,
                server_certificate: self.server_certificate,
                dh_params: Some(dh_params),
                client_certificate_request: self.client_certificate_request,
            }
            .into(),
            vec![],
        ))
    }
}

#[derive(Debug)]
pub struct ExpectServerHelloDoneOrCertificateRequest {
    session_id: SessionId,
    handshakes: Vec<u8>,
    client_random: [u8; 32],
    server_random: [u8; 32],
    negotiated_cipher_suite: CipherSuite,
    negotiated_extensions: NegotiatedExtensions,
    server_certificate: Option<ServerCertificate>,
    secrets: Option<ServerDhParams>,
}

impl HandleEvent<ClientContext, ClientState> for ExpectServerHelloDoneOrCertificateRequest {
    fn handle(mut self, ctx: &mut ClientContext, event: TlsEvent) -> HandleResult<ClientState> {
        match event {
            TlsEvent::IncomingMessage(TlsMessage::Handshake(
                handshake @ TlsHandshake::CertificateRequest(certificate_request),
            )) => {
                handshake.write_to(&mut self.handshakes);
                Ok((
                    ExpectServerHelloDone {
                        session_id: self.session_id,
                        handshakes: self.handshakes,
                        client_random: self.client_random,
                        server_random: self.server_random,
                        negotiated_cipher_suite: self.negotiated_cipher_suite,
                        negotiated_extensions: self.negotiated_extensions,
                        server_certificate: self.server_certificate,
                        dh_params: self.secrets,
                        client_certificate_request: Some(certificate_request.clone()),
                    }
                    .into(),
                    vec![],
                ))
            }
            TlsEvent::IncomingMessage(TlsMessage::Handshake(TlsHandshake::ServerHelloDone)) => {
                ExpectServerHelloDone {
                    session_id: self.session_id,
                    handshakes: self.handshakes,
                    client_random: self.client_random,
                    server_random: self.server_random,
                    negotiated_cipher_suite: self.negotiated_cipher_suite,
                    negotiated_extensions: self.negotiated_extensions,
                    server_certificate: self.server_certificate,
                    dh_params: self.secrets,
                    client_certificate_request: None,
                }
                .handle(ctx, event)
            }
            _ => Err(AlertDesc::UnexpectedMessage),
        }
    }
}

fn choose_client_certificate<'a>(
    certificiate_request: &CertificateRequest,
    certificates: &'a Certificates,
) -> Option<&'a CertificateAndPrivateKey> {
    // Find certs that match a certificate type
    // Find certs whose signature algo is supported
    // Find certs who can sign (if applicable)
    // Find certs with distinguished name

    let signature_algorithm_set: HashSet<SignatureAlgorithm> = certificiate_request
        .supported_signature_algorithms
        .iter()
        .cloned()
        .collect();

    let issuer_set: HashSet<_> = certificiate_request
        .certificate_authorities
        .iter()
        .map(|x| x.to_vec())
        .collect();

    let suitable_certificates: Vec<_> = certificates
        .certificates_with_type(&certificiate_request.certificate_types)
        .iter()
        .filter(|cert| {
            signature_algorithm_set.contains(&cert.signature_algorithm)
                && (issuer_set.is_empty() || issuer_set.contains(&cert.distinguished_name_der))
        })
        .copied()
        .collect();

    suitable_certificates
        .into_iter()
        .choose(&mut rand::thread_rng())
}

fn prepare_client_key_exchange(
    kx_algorithm: KeyExchangeAlgorithm,
    server_certificate: Option<&ServerCertificate>,
    dh_params: Option<&ServerDhParams>,
    client_certificate: Option<&CertificateAndPrivateKey>,
) -> Result<(Vec<u8>, ClientKeyExchange), AlertDesc> {
    let use_implicit = client_certificate
        .is_some_and(|x| x.public_key_algorithm == PublicKeyAlgorithm::DhKeyAgreement)
        && kx_algorithm.kx_type().uses_dh();
    if use_implicit {
        let (p, _, private_key) = deconstruct_dh_key(&client_certificate.unwrap().private_key_der);
        let dh_params =
            extract_dh_params(&server_certificate.unwrap()).map_err(|_| AlertDesc::HandshakeFailure)?;
        let pre_master_secret = dh_params.server_public_key.modpow(&private_key, &p);
        return Ok((
            pre_master_secret.to_bytes_be(),
            ClientKeyExchange::new_dh_implicit(),
        ));
    }

    match kx_algorithm {
        KeyExchangeAlgorithm::Rsa => {
            let server_public_key_der = server_certificate
                .expect("server certificate must be present for this kx")
                .public_key_der();
            let (pre_master_secret, encrypted_pre_master_secret) =
                get_rsa_pre_master_secret(&server_public_key_der)?;
            Ok((
                pre_master_secret,
                ClientKeyExchange::new_rsa(encrypted_pre_master_secret),
            ))
        }
        KeyExchangeAlgorithm::DheDss
        | KeyExchangeAlgorithm::DheRsa
        | KeyExchangeAlgorithm::DhAnon => {
            let dh_params = dh_params
                .as_ref()
                .expect("dh params must be present for this kx");
            let (pre_master_secret, client_public_key) =
                get_dh_pre_master_secret(&dh_params.p, &dh_params.g, &dh_params.server_public_key);
            Ok((
                pre_master_secret,
                ClientKeyExchange::new_dh_explicit(client_public_key),
            ))
        }
        KeyExchangeAlgorithm::DhDss | KeyExchangeAlgorithm::DhRsa => {
            let server_certificate =
                server_certificate.expect("server certificate must be present for this kx");
            let dh_params =
                extract_dh_params(&server_certificate).map_err(|_| AlertDesc::HandshakeFailure)?;
            let (pre_master_secret, client_public_key) =
                get_dh_pre_master_secret(&dh_params.p, &dh_params.g, &dh_params.server_public_key);
            Ok((
                pre_master_secret,
                ClientKeyExchange::new_dh_explicit(client_public_key),
            ))
        }
        KeyExchangeAlgorithm::EcdheRsa => unimplemented!(),
    }
}

#[derive(Debug)]
pub struct ExpectServerHelloDone {
    session_id: SessionId,
    handshakes: Vec<u8>,
    client_random: [u8; 32],
    server_random: [u8; 32],
    negotiated_cipher_suite: CipherSuite,
    negotiated_extensions: NegotiatedExtensions,
    server_certificate: Option<ServerCertificate>,
    dh_params: Option<ServerDhParams>,
    client_certificate_request: Option<CertificateRequest>,
}

impl HandleEvent<ClientContext, ClientState> for ExpectServerHelloDone {
    fn handle(mut self, ctx: &mut ClientContext, event: TlsEvent) -> HandleResult<ClientState> {
        let handshake = require_handshake_msg!(event, TlsHandshake::ServerHelloDone, *);

        info!("Received ServerHelloDone");
        handshake.write_to(&mut self.handshakes);

        let mut actions = vec![];

        // Send ClientCertificate
        let requested_certificate = match &self.client_certificate_request {
            None => None,
            Some(certificate_request) => {
                let client_certificate =
                    choose_client_certificate(&certificate_request, &ctx.config.certificates);

                let certificate = TlsHandshake::Certificate(
                    client_certificate
                        .map(|cert| Certificate::new(cert.certificate_der.clone()))
                        .unwrap_or(Certificate::empty()),
                );

                certificate.write_to(&mut self.handshakes);
                actions.push(TlsAction::SendHandshakeMsg(certificate));
                info!("Sent ClientCertificate");
                client_certificate
            }
        };

        // Send ClientKeyExchange
        let (pre_master_secret, client_kx) = prepare_client_key_exchange(
            self.negotiated_cipher_suite.kx_algorithm(),
            self.server_certificate.as_ref(),
            self.dh_params.as_ref(),
            requested_certificate,
        )?;
        let client_kx = TlsHandshake::ClientKeyExchange(client_kx);
        client_kx.write_to(&mut self.handshakes);
        actions.push(TlsAction::SendHandshakeMsg(client_kx));
        info!("Sent ClientKeyExchange");

        let master_secret = calculate_master_secret(
            &self.handshakes,
            &self.client_random,
            &self.server_random,
            &pre_master_secret,
            self.negotiated_cipher_suite.prf_algorithm(),
            self.negotiated_extensions.extended_master_secret,
        );
        // println!("MS: {:?}", master_secret);

        // Send CertificateVerify
        if let Some(client_certificate) = requested_certificate {
            if client_certificate.public_key_algorithm.can_sign() {
                let signature = sign(
                    client_certificate.signature_algorithm,
                    &client_certificate.private_key_der,
                    &self.handshakes,
                )
                .map_err(|_| AlertDesc::InternalError)?;
                let certificate_verify = TlsHandshake::CertificateVerify(CertificateVerify::new(
                    client_certificate.signature_algorithm,
                    signature,
                ));
                certificate_verify.write_to(&mut self.handshakes);
                actions.push(TlsAction::SendHandshakeMsg(certificate_verify));
                info!("Sent CertificateVerify");
            }
        }

        // Send ChangeCipherSuite
        let security_params = SecurityParams::new(
            self.client_random,
            self.server_random,
            master_secret,
            &self.negotiated_cipher_suite,
        );
        let write = ConnState::client(&security_params);
        actions.push(TlsAction::ChangeCipherSpec(TlsEntity::Client, write));
        info!("Sent ChangeCipherSuite");

        // Send ClientFinished
        let client_verify_data = security_params.client_verify_data(&self.handshakes);
        let client_finished = Finished::new(client_verify_data.clone());
        let client_finished = TlsHandshake::Finished(client_finished);
        client_finished.write_to(&mut self.handshakes);
        actions.push(TlsAction::SendHandshakeMsg(client_finished));
        info!("Sent ClientFinished");

        if self.negotiated_extensions.session_ticket {
            return Ok((
                ExpectNewSessionTicket {
                    session_id: self.session_id,
                    handshakes: self.handshakes,
                    negotiated_extensions: self.negotiated_extensions,
                    client_verify_data,
                    security_params,
                }
                .into(),
                actions,
            ));
        }

        Ok((
            ExpectServerChangeCipher {
                session_id: self.session_id,
                session_ticket: None,
                handshakes: self.handshakes,
                negotiated_extensions: self.negotiated_extensions,
                client_verify_data,
                security_params,
            }
            .into(),
            actions,
        ))
    }
}
#[derive(Debug)]
pub struct ExpectNewSessionTicket {
    session_id: SessionId,
    handshakes: Vec<u8>,
    negotiated_extensions: NegotiatedExtensions,
    security_params: SecurityParams,
    client_verify_data: Vec<u8>,
}

impl HandleEvent<ClientContext, ClientState> for ExpectNewSessionTicket {
    fn handle(mut self, _: &mut ClientContext, event: TlsEvent) -> HandleResult<ClientState> {
        let (handshake, new_session_ticket) =
            require_handshake_msg!(event, TlsHandshake::NewSessionTicket);

        info!("Received NewSessionTicket");
        handshake.write_to(&mut self.handshakes);

        Ok((
            ExpectServerChangeCipher {
                session_id: self.session_id,
                session_ticket: Some(new_session_ticket.ticket.to_vec()),
                handshakes: self.handshakes,
                negotiated_extensions: self.negotiated_extensions,
                client_verify_data: self.client_verify_data,
                security_params: self.security_params,
            }
            .into(),
            vec![],
        ))
    }
}

#[derive(Debug)]
pub struct ExpectNewSessionTicketOrCertificate {
    session_id: SessionId,
    handshakes: Vec<u8>,
    client_random: [u8; 32],
    server_random: [u8; 32],
    negotiated_cipher_suite: CipherSuite,
    negotiated_extensions: NegotiatedExtensions,
    session_ticket_resumption: SessionTicketResumption,
}

impl HandleEvent<ClientContext, ClientState> for ExpectNewSessionTicketOrCertificate {
    fn handle(self, ctx: &mut ClientContext, event: TlsEvent) -> HandleResult<ClientState> {
        // Session resumption accepted
        if let TlsEvent::IncomingMessage(TlsMessage::Handshake(TlsHandshake::NewSessionTicket(_))) =
            event
        {
            let security_params = SecurityParams::new(
                self.client_random,
                self.server_random,
                self.session_ticket_resumption.master_secret,
                &CipherSuite::from(self.session_ticket_resumption.cipher_suite_id),
            );

            // The ClientHello and ServerHello resulted in a different max_fragment_length
            // from what was decided for this session.
            if self.session_ticket_resumption.max_fragment_len
                != self.negotiated_extensions.max_fragment_length
            {
                return Err(AlertDesc::IllegalParameter);
            }

            if self.session_ticket_resumption.extended_master_secret
                != self.negotiated_extensions.extended_master_secret
            {
                return Err(AlertDesc::IllegalParameter);
            }

            if self.session_ticket_resumption.cipher_suite_id != self.negotiated_cipher_suite.id() {
                return Err(AlertDesc::IllegalParameter);
            }

            return ExpectNewSessionTicketAbbr {
                session_id: self.session_id,
                handshakes: self.handshakes,
                negotiated_extensions: self.negotiated_extensions,
                security_params,
            }
            .handle(ctx, event);
        } else if let TlsEvent::IncomingMessage(TlsMessage::Handshake(TlsHandshake::Certificate(
            _,
        ))) = event
        {
            let next_state = ExpectServerCertificate {
                session_id: self.session_id,
                handshakes: self.handshakes,
                client_random: self.client_random,
                server_random: self.server_random,
                negotiated_cipher_suite: self.negotiated_cipher_suite,
                negotiated_extensions: self.negotiated_extensions,
            }
            .handle(ctx, event);

            return prepend_action(
                next_state,
                TlsAction::InvalidateSessionTicket(self.session_ticket_resumption.session_ticket),
            );
        }

        Err(AlertDesc::UnexpectedMessage)
    }
}

fn prepend_action(
    result: HandleResult<ClientState>,
    action: TlsAction,
) -> HandleResult<ClientState> {
    result.map(|(state, mut actions)| {
        actions.insert(0, action);
        (state, actions)
    })
}

#[derive(Debug)]
pub struct ExpectServerChangeCipherOrCertificate {
    session_id: SessionId,
    handshakes: Vec<u8>,
    client_random: [u8; 32],
    server_random: [u8; 32],
    negotiated_cipher_suite: CipherSuite,
    negotiated_extensions: NegotiatedExtensions,
    session_ticket_resumption: SessionTicketResumption,
}

impl HandleEvent<ClientContext, ClientState> for ExpectServerChangeCipherOrCertificate {
    fn handle(self, ctx: &mut ClientContext, event: TlsEvent) -> HandleResult<ClientState> {
        if let TlsEvent::IncomingMessage(TlsMessage::ChangeCipherSpec) = event {
            let security_params = SecurityParams::new(
                self.client_random,
                self.server_random,
                self.session_ticket_resumption.master_secret,
                &CipherSuite::from(self.session_ticket_resumption.cipher_suite_id),
            );

            // The ClientHello and ServerHello resulted in a different max_fragment_length
            // from what was decided for this session.
            if self.session_ticket_resumption.max_fragment_len
                != self.negotiated_extensions.max_fragment_length
            {
                return Err(AlertDesc::IllegalParameter);
            }

            if self.session_ticket_resumption.extended_master_secret
                != self.negotiated_extensions.extended_master_secret
            {
                return Err(AlertDesc::IllegalParameter);
            }

            if self.session_ticket_resumption.cipher_suite_id != self.negotiated_cipher_suite.id() {
                return Err(AlertDesc::IllegalParameter);
            }

            return ExpectServerChangeCipherAbbr {
                session_id: self.session_id,
                handshakes: self.handshakes,
                negotiated_extensions: self.negotiated_extensions,
                security_params,
            }
            .handle(ctx, event);
        } else if let TlsEvent::IncomingMessage(TlsMessage::Handshake(TlsHandshake::Certificate(
            _,
        ))) = event
        {
            let next_state = ExpectServerCertificate {
                session_id: self.session_id,
                handshakes: self.handshakes,
                client_random: self.client_random,
                server_random: self.server_random,
                negotiated_cipher_suite: self.negotiated_cipher_suite,
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
pub struct ExpectServerChangeCipher {
    session_id: SessionId,
    session_ticket: Option<Vec<u8>>,
    handshakes: Vec<u8>,
    negotiated_extensions: NegotiatedExtensions,
    client_verify_data: Vec<u8>,
    security_params: SecurityParams,
}

impl HandleEvent<ClientContext, ClientState> for ExpectServerChangeCipher {
    fn handle(self, _ctx: &mut ClientContext, event: TlsEvent) -> HandleResult<ClientState> {
        let TlsEvent::IncomingMessage(TlsMessage::ChangeCipherSpec) = event else {
            return Err(AlertDesc::UnexpectedMessage);
        };

        info!("Received ChangeCipherSpec");
        let read = ConnState::server(&self.security_params);

        Ok((
            ExpectServerFinished {
                session_id: self.session_id,
                session_ticket: self.session_ticket,
                handshakes: self.handshakes,
                negotiated_extensions: self.negotiated_extensions,
                client_verify_data: self.client_verify_data,
                security_params: self.security_params,
            }
            .into(),
            vec![TlsAction::ChangeCipherSpec(TlsEntity::Server, read)],
        ))
    }
}

#[derive(Debug)]
pub struct ExpectServerFinished {
    session_id: SessionId,
    session_ticket: Option<Vec<u8>>,
    handshakes: Vec<u8>,
    negotiated_extensions: NegotiatedExtensions,
    security_params: SecurityParams,
    client_verify_data: Vec<u8>,
}

impl HandleEvent<ClientContext, ClientState> for ExpectServerFinished {
    fn handle(mut self, _: &mut ClientContext, event: TlsEvent) -> HandleResult<ClientState> {
        let (handshake, server_finished) = require_handshake_msg!(event, TlsHandshake::Finished);
        info!("Received ServerFinished");

        let server_verify_data = self.security_params.server_verify_data(&self.handshakes);
        if server_verify_data != server_finished.verify_data {
            return Err(AlertDesc::DecryptError);
        }
        handshake.write_to(&mut self.handshakes);

        info!("Handshake complete! (full)");

        let mut actions = vec![];
        if let Some(session_ticket) = self.session_ticket {
            actions.push(TlsAction::StoreSessionTicketInfo(
                session_ticket,
                SessionInfo::new(
                    self.security_params.master_secret,
                    self.security_params.cipher_suite_id,
                    self.negotiated_extensions.max_fragment_length,
                    self.negotiated_extensions.extended_master_secret,
                ),
            ));
        }

        if !self.session_id.is_empty() {
            actions.push(TlsAction::StoreSessionIdInfo(
                self.session_id.to_vec(),
                SessionInfo {
                    master_secret: self.security_params.master_secret,
                    cipher_suite: self.security_params.cipher_suite_id,
                    max_fragment_len: self.negotiated_extensions.max_fragment_length,
                    extended_master_secret: self.negotiated_extensions.extended_master_secret,
                },
            ));
        }

        Ok((
            ClientEstablished {
                session_id: self.session_id,
                negotiated_extensions: self.negotiated_extensions,
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
    security_params: SecurityParams,
}

impl HandleEvent<ClientContext, ClientState> for ExpectNewSessionTicketAbbr {
    fn handle(mut self, _: &mut ClientContext, event: TlsEvent) -> HandleResult<ClientState> {
        let (handshake, new_session_ticket) =
            require_handshake_msg!(event, TlsHandshake::NewSessionTicket);

        info!("Received NewSessionTicket ");
        handshake.write_to(&mut self.handshakes);

        let action = TlsAction::StoreSessionTicketInfo(
            new_session_ticket.ticket.to_vec(),
            SessionInfo::new(
                self.security_params.master_secret,
                self.security_params.cipher_suite_id,
                self.negotiated_extensions.max_fragment_length,
                self.negotiated_extensions.extended_master_secret,
            ),
        );

        Ok((
            ExpectServerChangeCipherAbbr {
                session_id: self.session_id,
                handshakes: self.handshakes,
                negotiated_extensions: self.negotiated_extensions,
                security_params: self.security_params,
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
    security_params: SecurityParams,
}

impl HandleEvent<ClientContext, ClientState> for ExpectServerChangeCipherAbbr {
    fn handle(self, _ctx: &mut ClientContext, event: TlsEvent) -> HandleResult<ClientState> {
        let TlsEvent::IncomingMessage(TlsMessage::ChangeCipherSpec) = event else {
            return Err(AlertDesc::UnexpectedMessage);
        };

        info!("Received ChangeCipherSpec");
        let read = ConnState::server(&self.security_params);

        Ok((
            ExpectServerFinishedAbbr {
                session_id: self.session_id,
                handshakes: self.handshakes,
                negotiated_extensions: self.negotiated_extensions,
                security_params: self.security_params,
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
    security_params: SecurityParams,
}

impl HandleEvent<ClientContext, ClientState> for ExpectServerFinishedAbbr {
    fn handle(mut self, _: &mut ClientContext, event: TlsEvent) -> HandleResult<ClientState> {
        let (handshake, server_finished) = require_handshake_msg!(event, TlsHandshake::Finished);
        info!("Received ServerFinished");

        let server_verify_data = self.security_params.server_verify_data(&self.handshakes);
        if server_verify_data != server_finished.verify_data {
            return Err(AlertDesc::DecryptError);
        }
        handshake.write_to(&mut self.handshakes);

        let client_verify_data = self.security_params.client_verify_data(&self.handshakes);
        let write = ConnState::client(&self.security_params);
        let client_finished = Finished::new(client_verify_data.clone());

        info!("Sent ChangeCipherSpec");
        info!("Sent ClientFinished");
        info!("Handshake complete! (abbr)");
        Ok((
            ClientEstablished {
                session_id: self.session_id,
                negotiated_extensions: self.negotiated_extensions,
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
    #[allow(unused)]
    pub session_id: SessionId,
    #[allow(unused)]
    negotiated_extensions: NegotiatedExtensions,
    pub server_verify_data: Vec<u8>,
    pub client_verify_data: Vec<u8>,
}

impl HandleEvent<ClientContext, ClientState> for ClientEstablished {
    fn handle(self, ctx: &mut ClientContext, event: TlsEvent) -> HandleResult<ClientState> {
        if let TlsEvent::IncomingMessage(TlsMessage::ApplicationData(data)) = event {
            println!("{:?}", String::from_utf8_lossy(data));
            return Ok((self.into(), vec![]));
        }

        let (state, actions) = ExpectClientInitiateState {
            // TODO: only use the previous verify data if configured as such
            previous_verify_data: Some(PreviousVerifyData {
                client: self.client_verify_data.clone(),
                server: self.server_verify_data.clone(),
            }),
        }
        .handle(ctx, event)?;

        let ClientState::ExpectServerHello(state) = state else {
            unreachable!()
        };

        Ok((
            ClientAttemptedRenegotiationState {
                initiated_at: Instant::now(),
                message_count: 0,
                established_state: self,
                expect_server_hello_state: state,
            }
            .into(),
            actions,
        ))
    }
}

#[derive(Debug)]
pub struct ClientAttemptedRenegotiationState {
    initiated_at: Instant,
    message_count: u32,
    established_state: ClientEstablished,
    expect_server_hello_state: ExpectServerHello,
}

impl HandleEvent<ClientContext, ClientState> for ClientAttemptedRenegotiationState {
    fn handle(mut self, ctx: &mut ClientContext, event: TlsEvent) -> HandleResult<ClientState> {
        if let TlsEvent::IncomingMessage(TlsMessage::ApplicationData(data)) = event {
            println!("{:?}", String::from_utf8_lossy(data));

            self.message_count += 1;
            match self.message_count >= ctx.config.policy.client_renegotation.max_wait_messages
                || self.initiated_at.elapsed()
                    >= ctx.config.policy.client_renegotation.max_wait_time
            {
                false => return Ok((self.into(), vec![])),
                true => {
                    if ctx.config.policy.client_renegotation.close_on_failure {
                        return Err(AlertDesc::HandshakeFailure);
                    }
                    return Ok((self.established_state.into(), vec![]));
                }
            };
        }

        if let TlsEvent::IncomingMessage(TlsMessage::Handshake(TlsHandshake::ServerHello(_))) =
            event
        {
            return self.expect_server_hello_state.handle(ctx, event);
        }

        // This will only be warning, fatals handled higher up
        if let TlsEvent::IncomingMessage(TlsMessage::Alert(alert)) = event {
            if alert.description == AlertDesc::NoRenegotiation {
                return Ok((self.established_state.into(), vec![]));
            }
            return Ok((self.into(), vec![]));
        }

        Err(AlertDesc::UnexpectedMessage)
    }
}
