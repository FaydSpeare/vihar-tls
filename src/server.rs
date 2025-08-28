use std::{
    io::{Read, Write},
    rc::Rc,
};

use crate::{
    TlsPolicy, TlsResult,
    client::{Certificates, PrioritisedCipherSuite},
    connection::ServerConnection,
    extensions::{HashType, SignatureAlgorithm, SignatureType},
    storage::{SessionStorage, SledSessionStore},
};

pub struct TlsServer<T: Read + Write> {
    config: Rc<TlsServerConfig>,
    connection: ServerConnection<T>,
}

impl<T: Read + Write> TlsServer<T> {
    pub fn new(config: TlsServerConfig, stream: T) -> Self {
        let config = Rc::new(config);
        Self {
            connection: ServerConnection::new(stream, config.clone()),
            config,
        }
    }

    pub fn write(&mut self, buf: &[u8]) -> TlsResult<usize> {
        if !self.connection.core.is_established() {
            while !self
                .connection
                .core
                .handshake_state_machine
                .is_established()
            {
                self.connection
                    .core
                    .next_message(&self.config.policy, self.config.session_store.as_deref())?;
            }
        }
        self.connection.core.write(buf)?;
        Ok(buf.len())
    }

    pub fn serve(&mut self) -> TlsResult<()> {
        loop {
            self.connection
                .core
                .next_message(&self.config.policy, self.config.session_store.as_deref())?;
        }
    }
}

// Server can choose
// cipher suites with priority
// session_store
// stek_store
// policy

pub struct TlsServerConfigBuilder {
    pub cipher_suites: Option<Box<[PrioritisedCipherSuite]>>,
    pub session_store: Option<Box<dyn SessionStorage>>,
    pub certificates: Option<Certificates>,
    pub server_name: String,
    pub policy: Option<TlsPolicy>,
}

impl TlsServerConfigBuilder {
    pub fn new(server_name: String) -> Self {
        Self {
            cipher_suites: None,
            session_store: None,
            certificates: None,
            server_name,
            policy: None,
        }
    }

    pub fn build(self) -> TlsServerConfig {
        use crate::ciphersuite::CipherSuiteId::*;
        TlsServerConfig {
            cipher_suites: self.cipher_suites.unwrap_or(Box::new([
                // pcs!(4, RsaWithAes128GcmSha256),
                // pcs!(3, RsaWithAes256GcmSha384),
                pcs!(2, RsaWithAes128CbcSha),
                pcs!(1, RsaWithAes128CbcSha256),
                pcs!(1, RsaWithAes256CbcSha),
                pcs!(1, RsaWithAes256CbcSha256),
            ])),
            supported_signature_algorithms: Box::new([
                SignatureAlgorithm {
                    signature: SignatureType::Rsa,
                    hash: HashType::Sha1,
                },
                SignatureAlgorithm {
                    signature: SignatureType::Rsa,
                    hash: HashType::Sha224,
                },
                SignatureAlgorithm {
                    signature: SignatureType::Rsa,
                    hash: HashType::Sha256,
                },
                SignatureAlgorithm {
                    signature: SignatureType::Rsa,
                    hash: HashType::Sha384,
                },
                SignatureAlgorithm {
                    signature: SignatureType::Rsa,
                    hash: HashType::Sha512,
                },
            ]),
            session_store: self.session_store,
            certificates: self.certificates.unwrap_or_default(),
            server_name: self.server_name,
            policy: self.policy.unwrap_or_default(),
        }
    }

    pub fn with_cipher_suites(mut self, suites: Box<[PrioritisedCipherSuite]>) -> Self {
        self.cipher_suites = Some(suites);
        self
    }

    pub fn with_session_store(mut self, path: &str) -> Self {
        self.session_store = Some(Box::new(SledSessionStore::open(path).unwrap()));
        self
    }

    pub fn with_policy(mut self, policy: TlsPolicy) -> Self {
        self.policy = Some(policy);
        self
    }

    pub fn with_certificates(mut self, certificates: Certificates) -> Self {
        self.certificates = Some(certificates);
        self
    }
}

#[derive(Debug, Clone)]
pub enum PublicKeyAlgorithm {
    DhKeyAgreement,
    RsaEncryption,
    DsaEncryption,
}

#[derive(Debug)]
pub struct TlsServerConfig {
    pub cipher_suites: Box<[PrioritisedCipherSuite]>,
    pub supported_signature_algorithms: Box<[SignatureAlgorithm]>,
    pub session_store: Option<Box<dyn SessionStorage>>,
    pub certificates: Certificates,
    pub server_name: String,
    pub policy: TlsPolicy,
}
