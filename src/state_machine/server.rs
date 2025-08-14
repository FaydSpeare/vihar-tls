use std::collections::HashMap;

use log::{debug, info};
use num_bigint::BigUint;

use crate::alert::TlsAlertDesc;
use crate::ciphersuite::{CipherSuiteId, KeyExchangeType};
use crate::client::PrioritisedCipherSuite;
use crate::encoding::Reader;
use crate::extensions::{HashAlgo, SignatureAndHashAlgorithm, verify};
use crate::messages::{
    Certificate, CertificateRequest, ClientHello, ClientKeyExchangeInner, NewSessionTicket,
    ProtocolVersion, ServerDHParams, ServerHello, ServerKeyExchange, SessionId,
};
use crate::session_ticket::{ClientIdentity, SessionTicket};
use crate::signature::{P, decrypt_rsa_master_secret, generate_dh_keypair, public_key_from_cert};
use crate::state_machine::{
    NegotiatedExtensions, SessionValidation, TlsAction, TlsEntity, calculate_master_secret,
    close_connection, close_with_unexpected_message,
};
use crate::storage::SessionInfo;
use crate::{MaxFragmentLengthNegotiationPolicy, RenegotiationPolicy, utils};
use crate::{
    alert::TlsAlert,
    ciphersuite::{CipherSuite, CipherSuiteMethods},
    connection::{ConnState, SecureConnState, SecurityParams},
    encoding::TlsCodable,
    messages::{Finished, TlsHandshake, TlsMessage},
};

use super::{HandleRecord, HandleResult, PreviousVerifyData, TlsContext, TlsEvent, TlsState};
use rand::prelude::IteratorRandom;
use rsa::pkcs1::EncodeRsaPrivateKey;

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
        None,
        session.max_fragment_len,
    );
    server_hello.session_id = client_hello.session_id.clone();

    let params = SecurityParams::new(
        client_hello.random.as_bytes(),
        server_hello.random.as_bytes(),
        session.master_secret,
        session.cipher_suite,
    );

    let server_hello = TlsHandshake::ServerHello(server_hello);
    server_hello.write_to(&mut handshakes);

    let keys = params.derive_keys();
    let write = ConnState::Secure(SecureConnState::new(
        params.clone(),
        keys.server_enc_key,
        keys.server_mac_key,
        keys.server_write_iv,
    ));

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
        .map(|x| CipherSuite::from(*x).params().name)
        .filter(|x| *x != "UNKNOWN")
        .collect();
    debug!("CipherSuites: {:#?}", suites);

    let Some(selected_cipher_suite) =
        select_cipher_suite(&ctx.config.cipher_suites, &client_hello.cipher_suites)
    else {
        return close_connection(TlsAlertDesc::HandshakeFailure);
    };

    let cipher_suite = CipherSuite::from(selected_cipher_suite);
    debug!("Selected CipherSuite {}", cipher_suite.params().name);

    let backup = SignatureAndHashAlgorithm {
        hash: HashAlgo::Sha1,
        signature: cipher_suite
            .params()
            .key_exchange_algorithm
            .signature_algorithm(),
    };
    let signature_algorithm = match client_hello.extensions.get_signature_algorithms() {
        None => backup,
        Some(algorithms) => ctx
            .config
            .signature_algorithms
            .iter()
            .flat_map(|algo| {
                algorithms
                    .iter()
                    .filter(move |hs| hs.hash == algo.hash && hs.signature == algo.signature)
                    .cloned()
            })
            .choose(&mut rand::thread_rng())
            .unwrap_or(backup),
    };
    debug!("Selected SignatureAlgorithm: {:?}", signature_algorithm);

    let max_fragment_length = client_hello.extensions.get_max_fragment_len().filter(|_| {
        ctx.config.policy.max_fragment_length_negotiation
            == MaxFragmentLengthNegotiationPolicy::Support
    });

    // If this is a secure renegotiation we need to send the right renegotation_info
    let renegotiation_info = previous_verify_data.map(|data| [data.client, data.server].concat());

    let server_hello = ServerHello::new(
        selected_cipher_suite,
        client_hello.extensions.includes_secure_renegotiation(),
        client_hello.extensions.includes_extended_master_secret(),
        issue_session_ticket,
        renegotiation_info,
        max_fragment_length,
    );

    let server_random = server_hello.random.as_bytes();
    let session_id = server_hello.session_id.to_vec();
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
    let mut actions = vec![];
    actions.extend([
        TlsAction::SendHandshakeMsg(server_hello),
        TlsAction::SendHandshakeMsg(certificate),
    ]);
    info!("Sent ServerHello");
    info!("Sent Certificate");

    let rsa_private_key = ctx
        .config
        .certificate
        .as_ref()
        .expect("Server certificate not configured")
        .private_key
        .clone();

    let mut server_private_key = None;
    let cipher_suite = CipherSuite::from(selected_cipher_suite);
    if let KeyExchangeType::Dhe = cipher_suite.params().key_exchange_algorithm.kx_type() {
        let (p, g, private_key, public_key) = generate_dh_keypair();
        server_private_key = Some(private_key);

        let dh_params = ServerDHParams::new(p, g, public_key);
        let server_kx = ServerKeyExchange::new_dhe(
            dh_params,
            client_hello.random.as_bytes(),
            server_random,
            signature_algorithm.hash,
            signature_algorithm.signature,
            &rsa_private_key.to_pkcs1_der().unwrap().to_bytes(),
        );

        let server_kx = TlsHandshake::ServerKeyExchange(server_kx);
        server_kx.write_to(&mut handshakes);

        actions.push(TlsAction::SendHandshakeMsg(server_kx));
        info!("Sent ServerKeyExchange");
    }

    let request_certificate = true;
    if request_certificate {
        let certificate_request = CertificateRequest::new(&ctx.config.signature_algorithms);
        let certificate_request = TlsHandshake::CertificateRequest(certificate_request);
        certificate_request.write_to(&mut handshakes);
        actions.push(TlsAction::SendHandshakeMsg(certificate_request));
        info!("Sent CertificateRequest");
    }

    let server_hello_done = TlsHandshake::ServerHelloDone;
    server_hello_done.write_to(&mut handshakes);

    actions.extend([TlsAction::SendHandshakeMsg(server_hello_done)]);

    info!("Sent ServerHelloDone");

    if request_certificate {
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
                server_private_key,
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
            server_private_key,
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
            if let Ok(session_state) = ticket.decrypt(&[0; 16], &[0; 32]) {
                let session = SessionInfo::new(
                    session_state.master_secret,
                    session_state.cipher_suite,
                    session_state.max_fragment_length,
                    session_state.extended_master_secret,
                );
                return start_abbr_handshake(client_hello.clone(), session);
            }
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
        let keys = self.params.derive_keys();
        let read = ConnState::Secure(SecureConnState::new(
            self.params.clone(),
            keys.client_enc_key,
            keys.client_mac_key,
            keys.client_write_iv,
        ));

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
pub struct AwaitClientCertificate {
    session_id: Vec<u8>,
    handshakes: Vec<u8>,
    client_random: [u8; 32],
    server_random: [u8; 32],
    selected_cipher_suite: CipherSuiteId,
    supported_extensions: NegotiatedExtensions,
    issue_session_ticket: bool,
    server_private_key: Option<BigUint>,
}

impl HandleRecord<TlsState> for AwaitClientCertificate {
    fn handle(mut self, _ctx: &mut TlsContext, event: TlsEvent) -> HandleResult<TlsState> {
        let (handshake, certificate) = require_handshake_msg!(event, TlsHandshake::Certificates);

        info!("Received ClientCertificate");
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
                server_private_key: self.server_private_key,
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
    selected_cipher_suite: CipherSuiteId,
    supported_extensions: NegotiatedExtensions,
    issue_session_ticket: bool,
    server_private_key: Option<BigUint>,
    expect_certificate_verify: bool,
    client_public_key: Option<Vec<u8>>,
}

impl HandleRecord<TlsState> for AwaitClientKeyExchange {
    fn handle(mut self, ctx: &mut TlsContext, event: TlsEvent) -> HandleResult<TlsState> {
        let (handshake, client_kx) = require_handshake_msg!(event, TlsHandshake::ClientKeyExchange);

        info!("Received ClientKeyExchange");
        handshake.write_to(&mut self.handshakes);

        let kx_algo = CipherSuite::from(self.selected_cipher_suite)
            .params()
            .key_exchange_algorithm;
        let client_kx = client_kx.resolve(kx_algo);

        let pre_master_secret = match client_kx {
            ClientKeyExchangeInner::ClientDiffieHellmanPublic(client_public_key) => {
                let client_public_key = BigUint::from_bytes_be(&client_public_key);
                let secret = client_public_key.modpow(&self.server_private_key.unwrap(), &P);
                secret.to_bytes_be()
            }
            ClientKeyExchangeInner::EncryptedPreMasterSecret(enc_pre_master_secret) => {
                let Ok(pre_master_secret) = decrypt_rsa_master_secret(
                    &ctx.config
                        .certificate
                        .as_ref()
                        .expect("Server private key not configured")
                        .private_key,
                    &enc_pre_master_secret,
                ) else {
                    return close_connection(TlsAlertDesc::DecryptError);
                };
                pre_master_secret
            }
        };

        let ciphersuite = CipherSuite::from(self.selected_cipher_suite);
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
            certificate_verify.signed.hash_algorithm,
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
        let keys = self.params.derive_keys();
        let read = ConnState::Secure(SecureConnState::new(
            self.params.clone(),
            keys.client_enc_key,
            keys.client_mac_key,
            keys.client_write_iv,
        ));

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
    fn handle(mut self, _ctx: &mut TlsContext, event: TlsEvent) -> HandleResult<TlsState> {
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
            );
            let new_session_ticket = TlsHandshake::NewSessionTicket(new_session_ticket);
            new_session_ticket.write_to(&mut self.handshakes);
            actions.push(TlsAction::SendHandshakeMsg(new_session_ticket));
            info!("Sent NewSessionTicket");
        }

        let keys = self.params.derive_keys();
        let write = ConnState::Secure(SecureConnState::new(
            self.params.clone(),
            keys.server_enc_key,
            keys.server_mac_key,
            keys.server_write_iv,
        ));

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
