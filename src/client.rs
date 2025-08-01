use std::{
    io::{Read, Write},
    sync::Arc,
};

use crate::{TlsResult, ciphersuite::CipherSuiteId, connection::TlsConnection};

pub struct TlsConfig {
    pub cipher_suites: Arc<[CipherSuiteId]>,
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
            config,
            connection: TlsConnection::new(stream),
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
