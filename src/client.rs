use std::{
    io::{Read, Write},
    sync::Arc,
};

use rsa::{RsaPrivateKey, pkcs8::DecodePrivateKey};
use x509_parser::pem::parse_x509_pem;

use crate::{
    ciphersuite::CipherSuiteId, connection::TlsConnection, extensions::{HashAlgo, MaxFragmentLength, SigAlgo}, state_machine::TlsEntity, storage::{SessionStorage, SledSessionStore}, TlsPolicy, TlsResult
};

#[derive(Debug, Clone)]
pub struct PrioritisedCipherSuite {
    pub id: CipherSuiteId,
    pub priority: u32,
}

#[derive(Debug, Clone)]
pub struct CertificateAndPrivateKey {
    pub certificate_der: Vec<u8>,
    pub private_key: RsaPrivateKey,
}

pub struct TlsConfigBuilder {
    pub cipher_suites: Option<Box<[PrioritisedCipherSuite]>>,
    pub session_store: Option<Box<dyn SessionStorage>>,
    pub certificate: Option<CertificateAndPrivateKey>,
    pub server_name: Option<String>,
    pub policy: Option<TlsPolicy>,
    pub max_fragment_length: Option<MaxFragmentLength>,
}

impl TlsConfigBuilder {
    pub fn new() -> Self {
        Self {
            cipher_suites: None,
            session_store: None,
            certificate: None,
            server_name: None,
            policy: None,
            max_fragment_length: None,
        }
    }

    pub fn build(self) -> TlsConfig {
        use crate::ciphersuite::CipherSuiteId::*;
        TlsConfig {
            cipher_suites: self.cipher_suites.unwrap_or(Box::new([
                pcs!(4, RsaAes128GcmSha256),
                pcs!(3, RsaAes256GcmSha384),
                pcs!(2, RsaAes128CbcSha),
                pcs!(1, RsaAes128CbcSha256),
                pcs!(1, RsaAes256CbcSha),
                pcs!(1, RsaAes256CbcSha256),
            ])),
            signature_algorithms: Box::new([
                (SigAlgo::Rsa, HashAlgo::Sha1),
                (SigAlgo::Rsa, HashAlgo::Sha224),
                (SigAlgo::Rsa, HashAlgo::Sha256),
                (SigAlgo::Rsa, HashAlgo::Sha384),
                (SigAlgo::Rsa, HashAlgo::Sha512),
            ]),
            session_store: self.session_store,
            certificate: self.certificate,
            server_name: self.server_name,
            policy: self.policy.unwrap_or_default(),
            max_fragment_length: self.max_fragment_length,
        }
    }

    pub fn with_max_fragment_length(mut self, len: MaxFragmentLength) -> Self {
        self.max_fragment_length = Some(len);
        self
    }

    pub fn with_cipher_suites(mut self, suites: Box<[PrioritisedCipherSuite]>) -> Self {
        self.cipher_suites = Some(suites);
        self
    }

    pub fn with_session_store(mut self, path: &str) -> Self {
        self.session_store = Some(Box::new(SledSessionStore::open(path).unwrap()));
        self
    }

    pub fn with_server_name(mut self, server_name: &str) -> Self {
        self.server_name = Some(server_name.to_string());
        self
    }

    pub fn with_policy(mut self, policy: TlsPolicy) -> Self {
        self.policy = Some(policy);
        self
    }

    pub fn with_certificate_pem(mut self, certificate_path: &str, private_key_path: &str) -> Self {
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
    pub cipher_suites: Box<[PrioritisedCipherSuite]>,
    pub signature_algorithms: Box<[(SigAlgo, HashAlgo)]>,
    pub session_store: Option<Box<dyn SessionStorage>>,
    pub certificate: Option<CertificateAndPrivateKey>,
    pub server_name: Option<String>,
    pub policy: TlsPolicy,
    pub max_fragment_length: Option<MaxFragmentLength>,
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

    pub fn renegotiate(&mut self) -> TlsResult<()> {
        self.connection
            .complete_handshake(TlsEntity::Client, &self.config)?;
        Ok(())
    }
}
