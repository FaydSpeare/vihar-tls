use std::{
    io::{Read, Write},
    sync::Arc,
};

use rsa::{RsaPrivateKey, pkcs8::DecodePrivateKey};
use x509_parser::pem::parse_x509_pem;

use crate::{
    TlsResult,
    ciphersuite::CipherSuiteId,
    connection::TlsConnection,
    extensions::{ALPNExt, ExtendedMasterSecretExt, Extension, SecureRenegotationExt},
    state_machine::TlsEntity,
    storage::{SessionTicketStorage, SledSessionTicketStore},
};

#[derive(Debug, Clone)]
pub struct CertificateAndPrivateKey {
    pub certificate_der: Vec<u8>,
    pub private_key: RsaPrivateKey,
}

pub struct TlsConfigBuilder {
    pub cipher_suites: Option<Box<[CipherSuiteId]>>,
    pub extensions: Option<Box<[Extension]>>,
    pub session_ticket_store: Option<Box<dyn SessionTicketStorage>>,
    pub certificate: Option<CertificateAndPrivateKey>,
}

impl TlsConfigBuilder {
    pub fn new() -> Self {
        Self {
            cipher_suites: Some(
                vec![
                    CipherSuiteId::RsaAes128CbcSha,
                    CipherSuiteId::RsaAes256CbcSha,
                    CipherSuiteId::RsaAes256CbcSha,
                    CipherSuiteId::RsaAes128CbcSha256,
                    CipherSuiteId::RsaAes128GcmSha256,
                    CipherSuiteId::RsaAes256GcmSha384,
                ]
                .into(),
            ),
            extensions: Some(
                vec![
                    SecureRenegotationExt::Initial.into(),
                    ExtendedMasterSecretExt::new().into(),
                    ALPNExt::new(vec!["http/1.1".to_string()]).unwrap().into(),
                ]
                .into(),
            ),
            session_ticket_store: None,
            certificate: None,
        }
    }

    pub fn build(self) -> TlsConfig {
        TlsConfig {
            cipher_suites: self.cipher_suites.unwrap(),
            extensions: self.extensions.unwrap(),
            session_ticket_store: self.session_ticket_store,
            certificate: self.certificate,
        }
    }

    pub fn with_session_ticket_store(mut self, path: &str) -> Self {
        self.session_ticket_store = Some(Box::new(SledSessionTicketStore::open(path).unwrap()));
        self
    }

    pub fn with_certificate_pem(
        mut self,
        certificate_path: &str,
        private_key_path: &str,
    ) -> Self {
        let certificate_pem = std::fs::read(certificate_path).expect("Failed to read certificate");
        let certificate_der = parse_x509_pem(&certificate_pem)
            .expect("Failed to parse certificate")
            .1
            .contents;
        let private_key_pem =
            std::fs::read_to_string(private_key_path).expect("Failed to read private key");
        let private_key =
            RsaPrivateKey::from_pkcs8_pem(&private_key_pem).expect("Failed to parse private key");
        self.certificate = Some(CertificateAndPrivateKey {
            certificate_der,
            private_key,
        });
        self
    }
}

#[derive(Debug)]
pub struct TlsConfig {
    pub cipher_suites: Box<[CipherSuiteId]>,
    pub extensions: Box<[Extension]>,
    pub session_ticket_store: Option<Box<dyn SessionTicketStorage>>,
    pub certificate: Option<CertificateAndPrivateKey>,
}

pub struct TlsClient<T: Read + Write> {
    config: Arc<TlsConfig>,
    connection: TlsConnection<T>,
}

impl<T: Read + Write> TlsClient<T> {
    pub fn new(config: TlsConfig, stream: T) -> Self {
        let config = Arc::new(config);
        Self {
            connection: TlsConnection::new(TlsEntity::Client, stream, config.clone()),
            config,
        }
    }

    pub fn write(&mut self, buf: &[u8]) -> TlsResult<usize> {
        if !self.connection.is_established() {
            self.connection
                .complete_handshake(TlsEntity::Client, &self.config)?;
        }
        self.connection.write(buf)?;
        Ok(buf.len())
    }
}
