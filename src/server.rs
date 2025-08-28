use std::{
    io::{Read, Write},
    rc::Rc,
};

use crate::{
    TlsPolicy, TlsResult, ValidationPolicy,
    client::{Certificates, PrioritisedCipherSuite},
    connection::ConnectionCore,
    extensions::{HashType, SignatureAlgorithm, SignatureType},
    storage::{SessionStorage, SledSessionStore},
};

pub struct TlsServer<T: Read + Write> {
    #[allow(dead_code)]
    config: Rc<TlsServerConfig>,
    pub connection: ConnectionCore<T>,
}

impl<T: Read + Write> TlsServer<T> {
    pub fn new(config: TlsServerConfig, stream: T) -> Self {
        let config = Rc::new(config);
        Self {
            connection: ConnectionCore::server(stream, config.clone()),
            config,
        }
    }

    pub fn write(&mut self, buf: &[u8]) -> TlsResult<usize> {
        if !self.connection.is_established() {
            while !self.connection.is_established() {
                self.connection.next_message()?;
            }
        }
        self.connection.write(buf)?;
        Ok(buf.len())
    }

    pub fn serve(&mut self) -> TlsResult<()> {
        loop {
            self.connection.next_message()?;
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
    pub fn new<S: Into<String>>(server_name: S) -> Self {
        Self {
            cipher_suites: None,
            session_store: None,
            certificates: None,
            server_name: server_name.into(),
            policy: None,
        }
    }

    pub fn build(self) -> TlsServerConfig {
        use crate::ciphersuite::CipherSuiteId::*;
        TlsServerConfig {
            validation_policy: ValidationPolicy::default(),
            cipher_suites: self.cipher_suites.unwrap_or(Box::new([
                pcs!(3, RsaWithAes128GcmSha256),
                pcs!(3, RsaWithAes256GcmSha384),
                pcs!(2, RsaWithAes128CbcSha),
                pcs!(1, RsaWithAes128CbcSha256),
                pcs!(1, RsaWithAes256CbcSha),
                pcs!(1, RsaWithAes256CbcSha256),
                pcs!(1, DhRsaWithAes128CbcSha),
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
                SignatureAlgorithm {
                    signature: SignatureType::Dsa,
                    hash: HashType::Sha1,
                },
                SignatureAlgorithm {
                    signature: SignatureType::Dsa,
                    hash: HashType::Sha224,
                },
                SignatureAlgorithm {
                    signature: SignatureType::Dsa,
                    hash: HashType::Sha256,
                },
                SignatureAlgorithm {
                    signature: SignatureType::Dsa,
                    hash: HashType::Sha384,
                },
                SignatureAlgorithm {
                    signature: SignatureType::Dsa,
                    hash: HashType::Sha512,
                },
            ]),
            session_store: self.session_store.map(|b| Rc::from(b)),
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
    pub validation_policy: ValidationPolicy,
    pub cipher_suites: Box<[PrioritisedCipherSuite]>,
    pub supported_signature_algorithms: Box<[SignatureAlgorithm]>,
    pub session_store: Option<Rc<dyn SessionStorage>>,
    pub certificates: Certificates,
    pub server_name: String,
    pub policy: TlsPolicy,
}
