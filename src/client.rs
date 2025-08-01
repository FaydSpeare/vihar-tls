use std::{
    io::{Read, Write},
    sync::Arc,
};

use crate::{
    TlsResult,
    ciphersuite::CipherSuiteId,
    connection::TlsConnection,
    extensions::{
        ALPNExt, ExtendedMasterSecretExt, Extension, SecureRenegotationExt, SessionTicketExt,
    },
    storage::{SessionTicketStorage, SledSessionTicketStore},
};

pub struct TlsConfig {
    pub cipher_suites: Arc<[CipherSuiteId]>,
    pub extensions: Arc<[Extension]>,
    pub session_ticket_store: Arc<dyn SessionTicketStorage>,
}

impl TlsConfig {
    pub fn default() -> Self {
        Self {
            cipher_suites: vec![
                CipherSuiteId::RsaAes128CbcSha,
                CipherSuiteId::RsaAes256CbcSha,
                CipherSuiteId::RsaAes256CbcSha,
                CipherSuiteId::RsaAes128CbcSha256,
                CipherSuiteId::RsaAes128GcmSha256,
                CipherSuiteId::RsaAes256GcmSha384,
            ]
            .into(),
            extensions: vec![
                SecureRenegotationExt::Initial.into(),
                ExtendedMasterSecretExt::new().into(),
                ALPNExt::new(vec!["http/1.1".to_string()]).unwrap().into(),
            ]
            .into(),
            session_ticket_store: Arc::from(
                SledSessionTicketStore::open("session_tickets.sled").unwrap(),
            ),
        }
    }
}

pub struct TlsClient<T: Read + Write> {
    config: TlsConfig,
    connection: TlsConnection<T>,
}

impl<T: Read + Write> TlsClient<T> {
    pub fn new(config: TlsConfig, stream: T) -> Self {
        Self {
            connection: TlsConnection::new(stream, &config),
            config,
        }
    }

    pub fn write(&mut self, buf: &[u8]) -> TlsResult<usize> {
        if !self.connection.is_established() {
            self.connection.perform_handshake(&self.config)?;
        }
        self.connection.write(buf)?;
        Ok(buf.len())
    }
}
