use std::{
    io::{Read, Write},
    sync::Arc,
};

use x509_parser::{
    asn1_rs::Oid,
    prelude::{FromDer, X509Certificate},
};

use crate::{
    TlsPolicy, TlsResult,
    ciphersuite::CipherSuiteId,
    connection::TlsConnection,
    extensions::{HashAlgo, MaxFragmentLength, SigAlgo, SignatureAndHashAlgorithm},
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
    pub cert_signature_algorithm: SigAlgo,
    pub distinguised_name_der: Vec<u8>,
}

#[derive(Debug)]
pub struct Certificates {
    pub rsa: Option<CertificateAndPrivateKey>,
    pub dsa: Option<CertificateAndPrivateKey>,
}

impl Certificates {
    pub fn new() -> Self {
        Self {
            rsa: None,
            dsa: None,
        }
    }

    pub fn primary(&self) -> Option<&CertificateAndPrivateKey> {
        self.rsa.as_ref().or(self.dsa.as_ref())
    }

    fn parse(certificate_path: &str, private_key_path: &str) -> CertificateAndPrivateKey {
        let certificate_der = utils::read_pem(certificate_path).expect("Failed to read certifiate");
        let certificate = X509Certificate::from_der(&certificate_der)
            .expect("Failed to parse certificate")
            .1;
        let distinguised_name_der = certificate.issuer().as_raw().to_vec();
        let cert_signature_algorithm =
            oid_to_key_type(&certificate.subject_pki.algorithm.algorithm);

        let private_key_der =
            utils::read_pem(private_key_path).expect("Failed to read private key");

        CertificateAndPrivateKey {
            certificate_der,
            private_key_der,
            cert_signature_algorithm,
            distinguised_name_der,
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
}

pub struct TlsConfigBuilder {
    pub cipher_suites: Option<Box<[PrioritisedCipherSuite]>>,
    pub session_store: Option<Box<dyn SessionStorage>>,
    pub certificates: Option<Certificates>,
    pub server_name: Option<String>,
    pub policy: Option<TlsPolicy>,
    pub max_fragment_length: Option<MaxFragmentLength>,
}

impl TlsConfigBuilder {
    pub fn new() -> Self {
        Self {
            cipher_suites: None,
            session_store: None,
            certificates: None,
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
                SignatureAndHashAlgorithm {
                    signature: SigAlgo::Rsa,
                    hash: HashAlgo::Sha1,
                },
                SignatureAndHashAlgorithm {
                    signature: SigAlgo::Rsa,
                    hash: HashAlgo::Sha224,
                },
                SignatureAndHashAlgorithm {
                    signature: SigAlgo::Rsa,
                    hash: HashAlgo::Sha256,
                },
                SignatureAndHashAlgorithm {
                    signature: SigAlgo::Rsa,
                    hash: HashAlgo::Sha384,
                },
                SignatureAndHashAlgorithm {
                    signature: SigAlgo::Rsa,
                    hash: HashAlgo::Sha512,
                },
            ]),
            session_store: self.session_store,
            certificates: self.certificates.unwrap_or(Certificates::new()),
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

    pub fn with_certificates(mut self, certificates: Certificates) -> Self {
        self.certificates = Some(certificates);
        self
    }
}

fn oid_to_key_type(oid: &Oid) -> SigAlgo {
    match oid.to_id_string().as_str() {
        "1.2.840.113549.1.1.1" => SigAlgo::Rsa,
        "1.2.840.10040.4.1" => SigAlgo::Dsa,
        x => unimplemented!("{x}"),
    }
}

#[derive(Debug)]
pub struct TlsConfig {
    pub cipher_suites: Box<[PrioritisedCipherSuite]>,
    pub signature_algorithms: Box<[SignatureAndHashAlgorithm]>,
    pub session_store: Option<Box<dyn SessionStorage>>,
    pub certificates: Certificates,
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
