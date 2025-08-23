use std::collections::HashMap;

use log::{debug, info};
use num_bigint::BigUint;

use crate::alert::TlsAlertDesc;
use crate::ciphersuite::{CipherSuiteId, KeyExchangeAlgorithm};
use crate::client::PrioritisedCipherSuite;
use crate::encoding::Reader;
use crate::extensions::{HashAlgo, SignatureAlgorithm, verify};
use crate::messages::{
    Certificate, CertificateRequest, ClientHello, ClientKeyExchangeInner, NewSessionTicket,
    ProtocolVersion, PublicValueEncoding, ServerDHParams, ServerHello, ServerKeyExchange,
    SessionId,
};
use crate::oid::deconstruct_dh_key;
use crate::session_ticket::{ClientIdentity, SessionTicket};
use crate::signature::{
    decrypt_rsa_master_secret, generate_dh_keypair, get_dh_params, public_key_from_cert,
};
use crate::state_machine::{
    NegotiatedExtensions, SessionValidation, TlsAction, TlsEntity, calculate_master_secret,
    close_connection, close_with_unexpected_message,
};
use crate::storage::SessionInfo;
use crate::{ClientAuthPolicy, MaxFragmentLengthNegotiationPolicy, RenegotiationPolicy, utils};
use crate::{
    alert::TlsAlert,
    ciphersuite::CipherSuite,
    connection::{ConnState, SecurityParams},
    encoding::TlsCodable,
    messages::{Finished, TlsHandshake, TlsMessage},
};

use super::{HandleRecord, HandleResult, PreviousVerifyData, TlsContext, TlsEvent, TlsState};
use rand::prelude::IteratorRandom;

fn select_cipher_suite(
    prioritised: &[PrioritisedCipherSuite],
    offered: &[CipherSuiteId],
) -> Option<CipherSuiteId> {
    let mut map: HashMap<CipherSuiteId, u32> = HashMap::new();
    for pcs in prioritised {
        map.insert(pcs.id, pcs.priority);
    }

    let acceptable: Vec<CipherSuiteId> = offered
        .iter()
        .filter(|x| map.contains_key(x))
        .copied()
        .collect();

    if acceptable.is_empty() {
        return None;
    }

    acceptable
        .iter()
        .max_by_key(|&id| map.get(id).unwrap_or(&0u32))
        .copied()
}

fn start_abbr_handshake(client_hello: ClientHello, session: SessionInfo) -> HandleResult<TlsState> {
    if client_hello.extensions.get_max_fragment_len() != session.max_fragment_len {
        return close_connection(TlsAlertDesc::IllegalParameter);
    }

    if session.extended_master_secret != client_hello.extensions.includes_extended_master_secret() {
        return close_connection(TlsAlertDesc::IllegalParameter);
    }

    if session.max_fragment_len != client_hello.extensions.get_max_fragment_len() {
        return close_connection(TlsAlertDesc::IllegalParameter);
    }

    let mut handshakes = TlsHandshake::ClientHello(client_hello.clone()).get_encoding();

    let negotiated_extensions = NegotiatedExtensions {
        extended_master_secret: client_hello.extensions.includes_extended_master_secret(),
        session_ticket: client_hello.extensions.includes_session_ticket(),
        secure_renegotiation: client_hello.extensions.includes_secure_renegotiation(),
        max_fragment_length: session.max_fragment_len,
    };

    let mut server_hello = ServerHello::new(
        session.cipher_suite,
        client_hello.extensions.includes_secure_renegotiation(),
        client_hello.extensions.includes_extended_master_secret(),
        false,
        client_hello.extensions.includes_server_name(),
        None,
        session.max_fragment_len,
    );
    server_hello.session_id = client_hello.session_id.clone();

    let params = SecurityParams::new(
        client_hello.random.as_bytes(),
        server_hello.random.as_bytes(),
        session.master_secret,
        &CipherSuite::from(session.cipher_suite),
    );

    let server_hello = TlsHandshake::ServerHello(server_hello);
    server_hello.write_to(&mut handshakes);

    let write = ConnState::new(params.clone(), TlsEntity::Server);

    let server_verify_data = params.server_verify_data(&handshakes);
    let server_finished = TlsHandshake::Finished(Finished::new(server_verify_data.clone()));
    server_finished.write_to(&mut handshakes);

    info!("Sent ServerHello");
    info!("Sent ChangeCipherSpec");
    info!("Sent ServerFinished");
    Ok((
        AwaitClientChangeCipherAbbr {
            handshakes,
            params,
            negotiated_extensions,
            server_verify_data,
        }
        .into(),
        vec![
            TlsAction::SendHandshakeMsg(server_hello),
            TlsAction::ChangeCipherSpec(TlsEntity::Server, write),
            TlsAction::SendHandshakeMsg(server_finished),
        ],
    ))
}

fn choose_signature_algorithm(
    cipher_suite: &CipherSuite,
    client_signature_algorithms: Option<&[SignatureAlgorithm]>,
    supported_signature_algoritms: &[SignatureAlgorithm],
) -> SignatureAlgorithm {
    let default = SignatureAlgorithm {
        hash: HashAlgo::Sha1,
        signature: cipher_suite.kx_algorithm().signature_type(),
    };
    match client_signature_algorithms {
        None => default,
        Some(algorithms) => supported_signature_algoritms
            .iter()
            .flat_map(|sa1| algorithms.iter().filter(move |sa2| sa1 == *sa2).cloned())
            .choose(&mut rand::thread_rng())
            .unwrap_or(default),
    }
}

fn start_full_handshake(
    ctx: &TlsContext,
    previous_verify_data: Option<PreviousVerifyData>,
    client_hello: ClientHello,
    issue_session_ticket: bool,
) -> HandleResult<TlsState> {
    let mut handshakes = TlsHandshake::ClientHello(client_hello.clone()).get_encoding();
    let suites: Vec<_> = client_hello
        .cipher_suites
        .iter()
        .map(|x| CipherSuite::from(*x).name())
        .filter(|x| *x != "UNKNOWN")
        .collect();
    debug!("CipherSuites: {:#?}", suites);

    let Some(selected_cipher_suite_id) =
        select_cipher_suite(&ctx.config.cipher_suites, &client_hello.cipher_suites)
    else {
        return close_connection(TlsAlertDesc::HandshakeFailure);
    };

    let selected_cipher_suite = CipherSuite::from(selected_cipher_suite_id);
    debug!("Selected CipherSuite {}", selected_cipher_suite.name());

    let max_fragment_length = client_hello.extensions.get_max_fragment_len().filter(|_| {
        ctx.config.policy.max_fragment_length_negotiation
            == MaxFragmentLengthNegotiationPolicy::Support
    });

    // If this is a secure renegotiation we need to send the right renegotation_info
    let renegotiation_info = previous_verify_data.map(|data| [data.client, data.server].concat());

    let server_hello = ServerHello::new(
        selected_cipher_suite_id,
        client_hello.extensions.includes_secure_renegotiation(),
        client_hello.extensions.includes_extended_master_secret(),
        issue_session_ticket,
        client_hello.extensions.includes_server_name(),
        renegotiation_info,
        max_fragment_length,
    );

    let server_random = server_hello.random.as_bytes();
    let session_id = server_hello.session_id.to_vec();
    let server_hello: TlsHandshake = server_hello.into();
    server_hello.write_to(&mut handshakes);

    let mut actions = vec![];
    actions.push(TlsAction::SendHandshakeMsg(server_hello));
    info!("Sent ServerHello");

    if selected_cipher_suite
        .kx_algorithm()
        .sends_server_certificate()
    {
        let certificate: TlsHandshake = Certificate::new(
            ctx.config
                .certificates
                .primary()
                .as_ref()
                .expect("Server certificate not configured")
                .certificate_der
                .clone(),
        )
        .into();
        certificate.write_to(&mut handshakes);

        actions.push(TlsAction::SendHandshakeMsg(certificate));
        info!("Sent Certificate");
    }

    let private_key_der = ctx
        .config
        .certificates
        .primary()
        .as_ref()
        .expect("Server certificate not configured")
        .private_key_der
        .clone();

    let mut server_dh_params = None;
    match selected_cipher_suite.kx_algorithm() {
        KeyExchangeAlgorithm::DhRsa | KeyExchangeAlgorithm::DhDss => {
            let (p, g, private_key) =
                deconstruct_dh_key(&ctx.config.certificates.dh.as_ref().unwrap().private_key_der);
            server_dh_params = Some(ServerDhParams { p, g, private_key });
        }
        KeyExchangeAlgorithm::DhAnon => {
            let (p, g) = get_dh_params();
            let (private_key, public_key) = generate_dh_keypair(&p, &g);
            server_dh_params = Some(ServerDhParams {
                p: p.clone(),
                g: g.clone(),
                private_key,
            });

            let dh_params = ServerDHParams::new(p, g, public_key);
            let server_kx = ServerKeyExchange::new_dh_anon(dh_params);

            let server_kx = TlsHandshake::ServerKeyExchange(server_kx);
            server_kx.write_to(&mut handshakes);

            actions.push(TlsAction::SendHandshakeMsg(server_kx));
            info!("Sent ServerKeyExchange");
        }
        KeyExchangeAlgorithm::DheRsa | KeyExchangeAlgorithm::DheDss => {
            let (p, g) = get_dh_params();
            let (private_key, public_key) = generate_dh_keypair(&p, &g);
            server_dh_params = Some(ServerDhParams {
                p: p.clone(),
                g: g.clone(),
                private_key,
            });

            let signature_algorithm = choose_signature_algorithm(
                &selected_cipher_suite,
                client_hello
                    .extensions
                    .get_signature_algorithms()
                    .as_deref(),
                &ctx.config.supported_signature_algorithms,
            );

            let dh_params = ServerDHParams::new(p, g, public_key);
            let server_kx = ServerKeyExchange::new_dhe(
                dh_params,
                client_hello.random.as_bytes(),
                server_random,
                signature_algorithm,
                &private_key_der,
            );

            let server_kx = TlsHandshake::ServerKeyExchange(server_kx);
            server_kx.write_to(&mut handshakes);

            actions.push(TlsAction::SendHandshakeMsg(server_kx));
            info!("Sent ServerKeyExchange");
        }
        _ => {}
    }

    if let ClientAuthPolicy::Auth {
        certificate_types, ..
    } = &ctx.config.policy.client_auth
    {
        let certificate_request = CertificateRequest::new(
            &ctx.config.supported_signature_algorithms,
            certificate_types,
        );
        let certificate_request = TlsHandshake::CertificateRequest(certificate_request);
        certificate_request.write_to(&mut handshakes);
        actions.push(TlsAction::SendHandshakeMsg(certificate_request));
        info!("Sent CertificateRequest");
    }

    let server_hello_done = TlsHandshake::ServerHelloDone;
    server_hello_done.write_to(&mut handshakes);

    actions.extend([TlsAction::SendHandshakeMsg(server_hello_done)]);

    info!("Sent ServerHelloDone");

    if let ClientAuthPolicy::Auth { .. } = &ctx.config.policy.client_auth {
        return Ok((
            AwaitClientCertificate {
                session_id,
                handshakes,
                client_random: client_hello.random.as_bytes(),
                server_random,
                selected_cipher_suite,
                supported_extensions: NegotiatedExtensions {
                    session_ticket: false,
                    extended_master_secret: client_hello
                        .extensions
                        .includes_extended_master_secret(),
                    secure_renegotiation: client_hello.extensions.includes_secure_renegotiation(),
                    max_fragment_length,
                },
                issue_session_ticket,
                server_dh_params,
            }
            .into(),
            actions,
        ));
    }
    Ok((
        AwaitClientKeyExchange {
            session_id,
            handshakes,
            client_random: client_hello.random.as_bytes(),
            server_random,
            selected_cipher_suite,
            supported_extensions: NegotiatedExtensions {
                session_ticket: false,
                extended_master_secret: client_hello.extensions.includes_extended_master_secret(),
                secure_renegotiation: client_hello.extensions.includes_secure_renegotiation(),
                max_fragment_length,
            },
            issue_session_ticket,
            server_dh_params,
            expect_certificate_verify: false,
            client_public_key: None,
        }
        .into(),
        actions,
    ))
}

#[derive(Debug)]
pub struct AwaitClientHello {
    pub previous_verify_data: Option<PreviousVerifyData>,
}

impl HandleRecord<TlsState> for AwaitClientHello {
    fn handle(self, ctx: &mut TlsContext, event: TlsEvent) -> HandleResult<TlsState> {
        let (_, client_hello) = require_handshake_msg!(event, TlsHandshake::ClientHello);
        info!("Received ClientHello");

        // We're not willing to go below TLS1.2. For TLS1.3 we'll give the client
        // the option to decide whether to continue when we respond with TLS1.2.
        if client_hello.version < ProtocolVersion::tls12() {
            return close_connection(TlsAlertDesc::ProtocolVersion);
        }

        let issue_session_ticket = client_hello.extensions.includes_session_ticket();

        if let Some(session_ticket) = client_hello.extensions.get_session_ticket() {
            let mut reader = Reader::new(&session_ticket);
            let ticket = SessionTicket::read_from(&mut reader).unwrap();
            let key_name = ticket.key_name;
            return Ok((
                AwaitStekInfo {
                    previous_verify_data: self.previous_verify_data,
                    client_hello: client_hello.clone(),
                    issue_session_ticket,
                    ticket,
                }
                .into(),
                vec![TlsAction::GetStekInfo(key_name.to_vec())],
            ));
        }

        if !client_hello.session_id.is_empty() {
            return Ok((
                AwaitSessionValidation {
                    previous_verify_data: self.previous_verify_data,
                    client_hello: client_hello.clone(),
                    issue_session_ticket,
                }
                .into(),
                vec![TlsAction::ValidateSessionId(
                    client_hello.session_id.to_vec(),
                )],
            ));
        }

        start_full_handshake(
            ctx,
            self.previous_verify_data,
            client_hello.clone(),
            issue_session_ticket,
        )
    }
}

#[derive(Debug)]
pub struct AwaitStekInfo {
    previous_verify_data: Option<PreviousVerifyData>,
    client_hello: ClientHello,
    issue_session_ticket: bool,
    ticket: SessionTicket,
}
impl HandleRecord<TlsState> for AwaitStekInfo {
    fn handle(self, ctx: &mut TlsContext, event: TlsEvent) -> HandleResult<TlsState> {
        let TlsEvent::StekInfo(maybe_stek) = event else {
            panic!("Expected STEK info");
        };

        if let Some(stek) = maybe_stek {
            if let Ok(session_state) = self.ticket.decrypt(&stek) {
                let session = SessionInfo::new(
                    session_state.master_secret,
                    session_state.cipher_suite,
                    session_state.max_fragment_length,
                    session_state.extended_master_secret,
                );
                return start_abbr_handshake(self.client_hello, session);
            }
        }

        start_full_handshake(
            ctx,
            self.previous_verify_data,
            self.client_hello,
            self.issue_session_ticket,
        )
    }
}

#[derive(Debug)]
pub struct AwaitSessionValidation {
    previous_verify_data: Option<PreviousVerifyData>,
    client_hello: ClientHello,
    issue_session_ticket: bool,
}

impl HandleRecord<TlsState> for AwaitSessionValidation {
    fn handle(self, ctx: &mut TlsContext, event: TlsEvent) -> HandleResult<TlsState> {
        let TlsEvent::SessionValidation(validation) = event else {
            return close_with_unexpected_message();
        };

        let SessionValidation::Valid(session) = validation else {
            return start_full_handshake(
                ctx,
                self.previous_verify_data,
                self.client_hello,
                self.issue_session_ticket,
            );
        };

        start_abbr_handshake(self.client_hello, session)
    }
}

#[derive(Debug)]
pub struct AwaitClientChangeCipherAbbr {
    handshakes: Vec<u8>,
    params: SecurityParams,
    negotiated_extensions: NegotiatedExtensions,
    server_verify_data: Vec<u8>,
}

impl HandleRecord<TlsState> for AwaitClientChangeCipherAbbr {
    fn handle(self, _ctx: &mut TlsContext, event: TlsEvent) -> HandleResult<TlsState> {
        let TlsEvent::IncomingMessage(TlsMessage::ChangeCipherSpec) = event else {
            return close_with_unexpected_message();
        };

        info!("Received ChangeCipherSpec");
        let read = ConnState::new(self.params.clone(), TlsEntity::Client);

        Ok((
            AwaitClientFinishedAbbr {
                handshakes: self.handshakes,
                params: self.params,
                supported_extensions: self.negotiated_extensions,
                server_verify_data: self.server_verify_data,
            }
            .into(),
            vec![TlsAction::ChangeCipherSpec(TlsEntity::Client, read)],
        ))
    }
}

#[derive(Debug)]
pub struct AwaitClientFinishedAbbr {
    handshakes: Vec<u8>,
    params: SecurityParams,
    supported_extensions: NegotiatedExtensions,
    server_verify_data: Vec<u8>,
}

impl HandleRecord<TlsState> for AwaitClientFinishedAbbr {
    fn handle(self, _ctx: &mut TlsContext, event: TlsEvent) -> HandleResult<TlsState> {
        let (_, client_finished) = require_handshake_msg!(event, TlsHandshake::Finished);

        info!("Received ClientFinished");
        let client_verify_data = self.params.client_verify_data(&self.handshakes);
        if client_verify_data != client_finished.verify_data {
            return close_connection(TlsAlertDesc::DecryptError);
        }

        info!("Handshake complete! (abbr)");
        Ok((
            ServerEstablished {
                session_id: SessionId::new(&[]).unwrap(),
                negotiated_extensions: self.supported_extensions,
                client_verify_data,
                server_verify_data: self.server_verify_data,
            }
            .into(),
            vec![],
        ))
    }
}

#[derive(Debug)]
pub struct ServerDhParams {
    p: BigUint,
    #[allow(dead_code)]
    g: BigUint,
    private_key: BigUint,
}

#[derive(Debug)]
pub struct AwaitClientCertificate {
    session_id: Vec<u8>,
    handshakes: Vec<u8>,
    client_random: [u8; 32],
    server_random: [u8; 32],
    selected_cipher_suite: CipherSuite,
    supported_extensions: NegotiatedExtensions,
    issue_session_ticket: bool,
    server_dh_params: Option<ServerDhParams>,
}

impl HandleRecord<TlsState> for AwaitClientCertificate {
    fn handle(mut self, ctx: &mut TlsContext, event: TlsEvent) -> HandleResult<TlsState> {
        let (handshake, certificate) = require_handshake_msg!(event, TlsHandshake::Certificates);

        info!("Received ClientCertificate");

        if matches!(
            ctx.config.policy.client_auth,
            ClientAuthPolicy::Auth {
                mandatory: true,
                ..
            }
        ) && certificate.list.is_empty()
        {
            return close_connection(TlsAlertDesc::HandshakeFailure);
        }

        handshake.write_to(&mut self.handshakes);

        let client_public_key = if let Some(cert) = certificate.list.first() {
            let Ok(key) = public_key_from_cert(cert) else {
                return close_connection(TlsAlertDesc::IllegalParameter);
            };
            Some(key)
        } else {
            None
        };

        Ok((
            AwaitClientKeyExchange {
                session_id: self.session_id,
                handshakes: self.handshakes,
                client_random: self.client_random,
                server_random: self.server_random,
                selected_cipher_suite: self.selected_cipher_suite,
                supported_extensions: self.supported_extensions,
                issue_session_ticket: self.issue_session_ticket,
                server_dh_params: self.server_dh_params,
                expect_certificate_verify: !certificate.list.is_empty(),
                client_public_key,
            }
            .into(),
            vec![],
        ))
    }
}

#[derive(Debug)]
pub struct AwaitClientKeyExchange {
    session_id: Vec<u8>,
    handshakes: Vec<u8>,
    client_random: [u8; 32],
    server_random: [u8; 32],
    selected_cipher_suite: CipherSuite,
    supported_extensions: NegotiatedExtensions,
    issue_session_ticket: bool,
    server_dh_params: Option<ServerDhParams>,
    expect_certificate_verify: bool,
    client_public_key: Option<Vec<u8>>,
}

impl HandleRecord<TlsState> for AwaitClientKeyExchange {
    fn handle(mut self, ctx: &mut TlsContext, event: TlsEvent) -> HandleResult<TlsState> {
        let (handshake, client_kx) = require_handshake_msg!(event, TlsHandshake::ClientKeyExchange);

        info!("Received ClientKeyExchange");
        handshake.write_to(&mut self.handshakes);

        let kx_algo = self.selected_cipher_suite.kx_algorithm();
        let client_kx = client_kx.resolve(kx_algo);

        let pre_master_secret = match client_kx {
            ClientKeyExchangeInner::ClientDiffieHellmanPublic(PublicValueEncoding::Implicit) => {
                // TODO: this is for when client has fixed_dh authenticated
                unimplemented!()
            }
            ClientKeyExchangeInner::ClientDiffieHellmanPublic(PublicValueEncoding::Explicit(
                client_public_key,
            )) => {
                let dh_params = self.server_dh_params.unwrap();
                let client_public_key = BigUint::from_bytes_be(&client_public_key);
                let secret = client_public_key.modpow(&dh_params.private_key, &dh_params.p);
                secret.to_bytes_be()
            }
            ClientKeyExchangeInner::EncryptedPreMasterSecret(enc_pre_master_secret) => {
                let Ok(pre_master_secret) = decrypt_rsa_master_secret(
                    &ctx.config
                        .certificates
                        .rsa
                        .as_ref()
                        .expect("Server private key not configured")
                        .private_key_der,
                    &enc_pre_master_secret,
                ) else {
                    return close_connection(TlsAlertDesc::DecryptError);
                };
                pre_master_secret
            }
        };

        let master_secret = calculate_master_secret(
            &self.handshakes,
            &self.client_random,
            &self.server_random,
            &pre_master_secret,
            self.selected_cipher_suite.prf_algorithm(),
            self.supported_extensions.extended_master_secret,
        );
        //println!("MS: {:?}", master_secret);

        let params = SecurityParams::new(
            self.client_random,
            self.server_random,
            master_secret,
            &self.selected_cipher_suite,
        );

        if self.expect_certificate_verify {
            return Ok((
                AwaitCertificateVerify {
                    session_id: self.session_id,
                    handshakes: self.handshakes,
                    params,
                    supported_extensions: self.supported_extensions,
                    issue_session_ticket: self.issue_session_ticket,
                    client_public_key: self.client_public_key.unwrap(),
                }
                .into(),
                vec![],
            ));
        }

        Ok((
            AwaitClientChangeCipher {
                session_id: self.session_id,
                handshakes: self.handshakes,
                params,
                supported_extensions: self.supported_extensions,
                issue_session_ticket: self.issue_session_ticket,
            }
            .into(),
            vec![],
        ))
    }
}

#[derive(Debug)]
pub struct AwaitCertificateVerify {
    session_id: Vec<u8>,
    handshakes: Vec<u8>,
    params: SecurityParams,
    supported_extensions: NegotiatedExtensions,
    issue_session_ticket: bool,
    client_public_key: Vec<u8>,
}

impl HandleRecord<TlsState> for AwaitCertificateVerify {
    fn handle(mut self, _ctx: &mut TlsContext, event: TlsEvent) -> HandleResult<TlsState> {
        let (handshake, certificate_verify) =
            require_handshake_msg!(event, TlsHandshake::CertificateVerify);

        info!("Received CertificateVerify");

        let verified = match verify(
            certificate_verify.signed.signature_algorithm,
            &self.client_public_key,
            &self.handshakes,
            &certificate_verify.signed.signature,
        ) {
            Ok(verified) => verified,
            Err(_) => return close_connection(TlsAlertDesc::IllegalParameter),
        };

        if !verified {
            return close_connection(TlsAlertDesc::DecryptError);
        }

        handshake.write_to(&mut self.handshakes);

        Ok((
            AwaitClientChangeCipher {
                session_id: self.session_id,
                handshakes: self.handshakes,
                params: self.params,
                supported_extensions: self.supported_extensions,
                issue_session_ticket: self.issue_session_ticket,
            }
            .into(),
            vec![],
        ))
    }
}

#[derive(Debug)]
pub struct AwaitClientChangeCipher {
    session_id: Vec<u8>,
    handshakes: Vec<u8>,
    params: SecurityParams,
    supported_extensions: NegotiatedExtensions,
    issue_session_ticket: bool,
}

impl HandleRecord<TlsState> for AwaitClientChangeCipher {
    fn handle(self, _ctx: &mut TlsContext, event: TlsEvent) -> HandleResult<TlsState> {
        let TlsEvent::IncomingMessage(TlsMessage::ChangeCipherSpec) = event else {
            return close_with_unexpected_message();
        };

        info!("Received ChangeCipherSpec");
        let read = ConnState::new(self.params.clone(), TlsEntity::Client);

        Ok((
            AwaitClientFinished {
                session_id: self.session_id,
                handshakes: self.handshakes,
                params: self.params,
                negotiated_extensions: self.supported_extensions,
                issue_session_ticket: self.issue_session_ticket,
            }
            .into(),
            vec![TlsAction::ChangeCipherSpec(TlsEntity::Client, read)],
        ))
    }
}

#[derive(Debug)]
pub struct AwaitClientFinished {
    session_id: Vec<u8>,
    handshakes: Vec<u8>,
    params: SecurityParams,
    negotiated_extensions: NegotiatedExtensions,
    issue_session_ticket: bool,
}

impl HandleRecord<TlsState> for AwaitClientFinished {
    fn handle(mut self, ctx: &mut TlsContext, event: TlsEvent) -> HandleResult<TlsState> {
        let (handshake, client_finished) = require_handshake_msg!(event, TlsHandshake::Finished);

        info!("Received ClientFinished");
        let client_verify_data = self.params.client_verify_data(&self.handshakes);
        if client_verify_data != client_finished.verify_data {
            return close_connection(TlsAlertDesc::DecryptError);
        }

        handshake.write_to(&mut self.handshakes);

        let mut actions = vec![];

        if self.issue_session_ticket {
            let new_session_ticket = NewSessionTicket::new(
                ProtocolVersion::tls12(),
                self.params.cipher_suite_id,
                self.params.compression_algorithm,
                self.params.master_secret,
                ClientIdentity::Anonymous,
                utils::get_unix_time(),
                self.negotiated_extensions.max_fragment_length,
                self.negotiated_extensions.extended_master_secret,
                ctx.stek.as_ref().unwrap(),
            );
            let new_session_ticket = TlsHandshake::NewSessionTicket(new_session_ticket);
            new_session_ticket.write_to(&mut self.handshakes);
            actions.push(TlsAction::SendHandshakeMsg(new_session_ticket));
            info!("Sent NewSessionTicket");
        }

        let write = ConnState::new(self.params.clone(), TlsEntity::Server);

        actions.push(TlsAction::ChangeCipherSpec(TlsEntity::Server, write));

        let server_verify_data = self.params.server_verify_data(&self.handshakes);
        let server_finished: TlsHandshake = Finished::new(server_verify_data.clone()).into();
        actions.push(TlsAction::SendHandshakeMsg(server_finished));

        if !self.issue_session_ticket {
            actions.push(TlsAction::StoreSessionIdInfo(
                self.session_id.clone(),
                SessionInfo::new(
                    self.params.master_secret,
                    self.params.cipher_suite_id,
                    self.negotiated_extensions.max_fragment_length,
                    self.negotiated_extensions.extended_master_secret,
                ),
            ));
        }

        info!("Sent ChangeCipherSpec");
        info!("Sent ServerFinished");
        info!("Handshake complete! (full)");
        Ok((
            ServerEstablished {
                session_id: SessionId::new(&self.session_id).unwrap(),
                negotiated_extensions: self.negotiated_extensions,
                client_verify_data,
                server_verify_data,
            }
            .into(),
            actions,
        ))
    }
}

#[derive(Debug)]
pub struct ServerEstablished {
    pub session_id: SessionId,
    #[allow(unused)]
    negotiated_extensions: NegotiatedExtensions,
    pub server_verify_data: Vec<u8>,
    pub client_verify_data: Vec<u8>,
}

impl HandleRecord<TlsState> for ServerEstablished {
    fn handle(self, ctx: &mut TlsContext, event: TlsEvent) -> HandleResult<TlsState> {
        if let TlsEvent::IncomingMessage(TlsMessage::ApplicationData(data)) = event {
            println!("{:?}", String::from_utf8_lossy(data));
            return Ok((self.into(), vec![]));
        }
        let (_, client_hello) = require_handshake_msg!(event, TlsHandshake::ClientHello);

        // TODO:
        // Add options to simply ignore client renegotiation or simply send a warning.
        match ctx.config.policy.renegotiation {
            RenegotiationPolicy::None => close_connection(TlsAlertDesc::NoRenegotiation),
            RenegotiationPolicy::OnlyLegacy => {
                if client_hello.extensions.includes_secure_renegotiation() {
                    return close_connection(TlsAlertDesc::HandshakeFailure);
                }
                AwaitClientHello {
                    previous_verify_data: None,
                }
                .handle(ctx, event)
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
                close_connection(TlsAlertDesc::NoRenegotiation)
            }
        }
    }
}

// #[derive(Debug)]
// pub struct HelloRequested {
//     pub session_id: SessionId,
//     #[allow(unused)]
//     negotiated_extensions: NegotiatedExtensions,
//     pub server_verify_data: Vec<u8>,
//     pub client_verify_data: Vec<u8>,
// }
//
// impl HandleRecord<TlsState> for ServerEstablished {
//     fn handle(self, ctx: &mut TlsContext, event: TlsEvent) -> HandleResult<TlsState> {
//         if let TlsEvent::IncomingMessage(TlsMessage::ApplicationData(data)) = event {
//             println!("{:?}", String::from_utf8_lossy(data));
//             return Ok((self.into(), vec![]));
//         }
//     }
// }
