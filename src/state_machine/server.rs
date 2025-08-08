use std::collections::HashMap;

use log::{debug, info};

use crate::MaxFragmentLengthNegotiationPolicy;
use crate::alert::TlsAlertDesc;
use crate::ciphersuite::CipherSuiteId;
use crate::client::PrioritisedCipherSuite;
use crate::messages::{Certificate, ProtocolVersion, ServerHello, SessionId};
use crate::signature::decrypt_rsa_master_secret;
use crate::state_machine::{
    EstablishedState, SupportedExtensions, TlsAction, TlsEntity, calculate_master_secret,
    close_connection, close_with_unexpected_message,
};
use crate::{
    alert::TlsAlert,
    ciphersuite::{CipherSuite, CipherSuiteMethods},
    connection::{ConnState, SecureConnState, SecurityParams},
    encoding::TlsCodable,
    messages::{Finished, TlsHandshake, TlsMessage},
};

use super::{HandleRecord, HandleResult, PreviousVerifyData, TlsContext, TlsEvent};

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

#[derive(Debug)]
pub struct AwaitClientHello {
    pub previous_verify_data: Option<PreviousVerifyData>,
}

impl HandleRecord for AwaitClientHello {
    fn handle(self, ctx: &mut TlsContext, event: TlsEvent) -> HandleResult {
        let (handshake, client_hello) = require_handshake_msg!(event, TlsHandshake::ClientHello);
        info!("Received ClientHello");

        // We're not willing to go below TLS1.2. For TLS1.3 we'll give the client
        // the option to decide whether to continue when we respond with TLS1.2.
        if client_hello.version < ProtocolVersion::tls12() {
            return close_connection(TlsAlertDesc::ProtocolVersion);
        }

        let mut handshakes = handshake.get_encoding();

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
pub struct AwaitClientFinished {
    handshakes: Vec<u8>,
    params: SecurityParams,
    supported_extensions: SupportedExtensions,
}

impl HandleRecord for AwaitClientFinished {
    fn handle(mut self, _ctx: &mut TlsContext, event: TlsEvent) -> HandleResult {
        let (handshake, client_finished) = require_handshake_msg!(event, TlsHandshake::Finished);

        info!("Received ClientFinished");
        let client_verify_data = self.params.client_verify_data(&self.handshakes);
        if client_verify_data != client_finished.verify_data {
            return close_connection(TlsAlertDesc::DecryptError);
        }

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
