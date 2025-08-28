use std::{
    collections::HashSet,
    io::{Read, Write},
    rc::Rc,
};

use rand::seq::IteratorRandom;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::{
    TlsPolicy, TlsResult, ValidationPolicy,
    ciphersuite::{CipherSuite, CipherSuiteId},
    connection::ConnectionCore,
    extensions::{HashType, MaxFragmentLength, SignatureAlgorithm, SignatureType},
    messages::ClientCertificateType,
    oid::{get_public_key_algorithm, get_signature_algorithm},
    state_machine::TlsEntity,
    storage::{SessionStorage, SledSessionStore},
    utils,
};

#[derive(Debug, Clone)]
pub struct PrioritisedCipherSuite {
    pub id: CipherSuiteId,
    pub priority: u32,
}

#[derive(Debug, Clone)]
pub struct CertificateAndPrivateKey {
    pub certificate_der: Vec<u8>,
    pub private_key_der: Vec<u8>,
    pub public_key_algorithm: PublicKeyAlgorithm,
    pub signature_algorithm: SignatureAlgorithm,
    pub distinguished_name_der: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum PublicKeyType {
    Rsa,
    Dsa,
    Dh,
}

impl CertificateAndPrivateKey {
    pub fn public_key_type(&self) -> PublicKeyType {
        match self.public_key_algorithm {
            PublicKeyAlgorithm::RsaEncryption => PublicKeyType::Rsa,
            PublicKeyAlgorithm::DsaEncryption => PublicKeyType::Dsa,
            PublicKeyAlgorithm::DhKeyAgreement => PublicKeyType::Dh,
        }
    }
}

#[derive(Debug)]
pub struct Certificates {
    pub rsa: Option<CertificateAndPrivateKey>,
    pub dsa: Option<CertificateAndPrivateKey>,
    pub dh: Option<CertificateAndPrivateKey>,
}

impl Default for Certificates {
    fn default() -> Self {
        Self::new()
    }
}

impl Certificates {
    pub fn new() -> Self {
        Self {
            rsa: None,
            dsa: None,
            dh: None,
        }
    }

    pub fn certificate_for_cipher_suite(
        &self,
        cipher_suite: &CipherSuite,
    ) -> &CertificateAndPrivateKey {
        let kx = cipher_suite.kx_algorithm();
        self.certificates()
            .iter()
            .filter(|cert| {
                kx.public_key_type().unwrap() == cert.public_key_type()
                    && kx.signature_type().unwrap() == cert.signature_algorithm.signature
            })
            .choose(&mut rand::thread_rng())
            .unwrap()
    }

    pub fn certificates(&self) -> Vec<&CertificateAndPrivateKey> {
        let mut certs = vec![];
        if let Some(v) = self.rsa.as_ref() {
            certs.push(v)
        }
        if let Some(v) = self.dsa.as_ref() {
            certs.push(v)
        }
        if let Some(v) = self.dh.as_ref() {
            certs.push(v)
        }
        certs
    }

    pub fn certificates_with_type(
        &self,
        certificate_types: &[ClientCertificateType],
    ) -> Vec<&CertificateAndPrivateKey> {
        let types: HashSet<_> = certificate_types.iter().collect();
        let mut certs = vec![];

        if types.contains(&ClientCertificateType::RsaSign) {
            if let Some(v) = self.rsa.as_ref() {
                certs.push(v)
            }
        }
        if types.contains(&ClientCertificateType::DssSign) {
            if let Some(v) = self.dsa.as_ref() {
                certs.push(v)
            }
        }
        if types.contains(&ClientCertificateType::DssFixedDh)
            || types.contains(&ClientCertificateType::RsaFixedDh)
        {
            if let Some(v) = self.dh.as_ref() {
                certs.push(v)
            }
        }
        certs
    }

    fn parse(certificate_path: &str, private_key_path: &str) -> CertificateAndPrivateKey {
        let certificate_der = utils::read_pem(certificate_path).expect("Failed to read certifiate");
        let certificate = X509Certificate::from_der(&certificate_der)
            .expect("Failed to parse certificate")
            .1;

        let distinguished_name_der = certificate.issuer().as_raw().to_vec();
        let public_key_algorithm = get_public_key_algorithm(&certificate);
        let signature_algorithm = get_signature_algorithm(&certificate);

        let private_key_der =
            utils::read_pem(private_key_path).expect("Failed to read private key");

        CertificateAndPrivateKey {
            certificate_der,
            private_key_der,
            public_key_algorithm,
            signature_algorithm,
            distinguished_name_der,
        }
    }

    pub fn with_rsa(mut self, certificate_path: &str, private_key_path: &str) -> Self {
        self.rsa = Some(Self::parse(certificate_path, private_key_path));
        self
    }

    pub fn with_dsa(mut self, certificate_path: &str, private_key_path: &str) -> Self {
        self.dsa = Some(Self::parse(certificate_path, private_key_path));
        self
    }

    pub fn with_dh(mut self, certificate_path: &str, private_key_path: &str) -> Self {
        self.dh = Some(Self::parse(certificate_path, private_key_path));
        self
    }
}

pub struct TlsClientConfigBuilder {
    pub cipher_suites: Option<Box<[CipherSuiteId]>>,
    pub session_store: Option<Box<dyn SessionStorage>>,
    pub certificates: Option<Certificates>,
    pub server_name: String,
    pub policy: Option<TlsPolicy>,
    pub max_fragment_length: Option<MaxFragmentLength>,
}

// Client can choose:
// cipher suites to offer
// server name
// certificates
// session store
// max_fragment_length
// client policy

impl TlsClientConfigBuilder {
    pub fn new(server_name: String) -> Self {
        Self {
            cipher_suites: None,
            session_store: None,
            certificates: None,
            server_name,
            policy: None,
            max_fragment_length: None,
        }
    }

    pub fn build(self) -> TlsClientConfig {
        TlsClientConfig {
            validation_policy: ValidationPolicy::default(),
            cipher_suites: self.cipher_suites.unwrap_or(Box::new([
                CipherSuiteId::RsaWithAes128CbcSha,
                CipherSuiteId::RsaWithAes128CbcSha256,
                CipherSuiteId::RsaWithAes256CbcSha,
                CipherSuiteId::RsaWithAes256CbcSha256,
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
            max_fragment_length: self.max_fragment_length,
        }
    }

    pub fn with_max_fragment_length(mut self, len: MaxFragmentLength) -> Self {
        self.max_fragment_length = Some(len);
        self
    }

    pub fn with_cipher_suites(mut self, suites: Box<[CipherSuiteId]>) -> Self {
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

#[derive(Debug, Clone, PartialEq)]
pub enum PublicKeyAlgorithm {
    DhKeyAgreement,
    RsaEncryption,
    DsaEncryption,
}

impl PublicKeyAlgorithm {
    pub fn can_sign(&self) -> bool {
        !matches!(self, Self::DhKeyAgreement)
    }
}

#[derive(Debug)]
pub struct TlsClientConfig {
    pub cipher_suites: Box<[CipherSuiteId]>,
    pub supported_signature_algorithms: Box<[SignatureAlgorithm]>,
    pub session_store: Option<Rc<dyn SessionStorage>>,
    pub certificates: Certificates,
    pub server_name: String,
    pub policy: TlsPolicy,
    pub validation_policy: ValidationPolicy,
    pub max_fragment_length: Option<MaxFragmentLength>,
}

pub struct TlsClient<T: Read + Write> {
    #[allow(dead_code)]
    config: Rc<TlsClientConfig>,
    connection: ConnectionCore<T>,
}

impl<T: Read + Write> TlsClient<T> {
    pub fn new(config: TlsClientConfig, stream: T) -> Self {
        let config = Rc::new(config);
        Self {
            connection: ConnectionCore::client(stream, config.clone()),
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
