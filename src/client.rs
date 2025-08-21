use std::{
    io::{Read, Write},
    rc::Rc,
};

use x509_parser::prelude::{FromDer, X509Certificate};

use crate::{
    TlsPolicy, TlsResult,
    ciphersuite::CipherSuiteId,
    connection::TlsConnection,
    extensions::{HashAlgo, MaxFragmentLength, SigAlgo, SignatureAlgorithm},
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
    pub distinguished_name_der: Vec<u8>,
}

impl CertificateAndPrivateKey {
    pub fn signature_algorithm(&self) -> SigAlgo {
        match self.public_key_algorithm {
            PublicKeyAlgorithm::RsaEncryption => SigAlgo::Rsa,
            PublicKeyAlgorithm::DsaEncryption => SigAlgo::Dsa,
            _ => unimplemented!(),
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

    pub fn primary(&self) -> Option<&CertificateAndPrivateKey> {
        self.rsa.as_ref().or(self.dsa.as_ref()).or(self.dh.as_ref())
    }

    pub fn certificates(&self) -> Vec<&CertificateAndPrivateKey> {
        let mut certs = vec![];
        if let Some(v) = self.rsa.as_ref() {
            certs.push(v)
        }
        if let Some(v) = self.dsa.as_ref() {
            certs.push(v)
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

        let private_key_der =
            utils::read_pem(private_key_path).expect("Failed to read private key");

        CertificateAndPrivateKey {
            certificate_der,
            private_key_der,
            public_key_algorithm,
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

pub struct TlsConfigBuilder {
    pub cipher_suites: Option<Box<[PrioritisedCipherSuite]>>,
    pub session_store: Option<Box<dyn SessionStorage>>,
    pub certificates: Option<Certificates>,
    pub server_name: Option<String>,
    pub policy: Option<TlsPolicy>,
    pub max_fragment_length: Option<MaxFragmentLength>,
}

impl Default for TlsConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
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
                // pcs!(4, RsaWithAes128GcmSha256),
                // pcs!(3, RsaWithAes256GcmSha384),
                pcs!(2, RsaWithAes128CbcSha),
                pcs!(1, RsaWithAes128CbcSha256),
                pcs!(1, RsaWithAes256CbcSha),
                pcs!(1, RsaWithAes256CbcSha256),
            ])),
            signature_algorithms: Box::new([
                // SignatureAndHashAlgorithm {
                //     signature: SigAlgo::Ecdsa,
                //     hash: HashAlgo::Sha1,
                // },
                // SignatureAndHashAlgorithm {
                //     signature: SigAlgo::Ecdsa,
                //     hash: HashAlgo::Sha256,
                // },
                SignatureAlgorithm {
                    signature: SigAlgo::Rsa,
                    hash: HashAlgo::Sha1,
                },
                SignatureAlgorithm {
                    signature: SigAlgo::Rsa,
                    hash: HashAlgo::Sha224,
                },
                SignatureAlgorithm {
                    signature: SigAlgo::Rsa,
                    hash: HashAlgo::Sha256,
                },
                SignatureAlgorithm {
                    signature: SigAlgo::Rsa,
                    hash: HashAlgo::Sha384,
                },
                SignatureAlgorithm {
                    signature: SigAlgo::Rsa,
                    hash: HashAlgo::Sha512,
                },
            ]),
            session_store: self.session_store,
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

#[derive(Debug, Clone)]
pub enum PublicKeyAlgorithm {
    DhKeyAgreement,
    RsaEncryption,
    DsaEncryption,
}

pub fn get_public_key_algorithm(cert: &X509Certificate) -> PublicKeyAlgorithm {
    match cert.subject_pki.algorithm.oid().to_id_string().as_str() {
        "1.2.840.113549.1.1.1" => PublicKeyAlgorithm::RsaEncryption,
        "1.2.840.10040.4.1" => PublicKeyAlgorithm::DsaEncryption,
        "1.2.840.113549.1.3.1" => PublicKeyAlgorithm::DhKeyAgreement,
        x => unimplemented!("{x}"),
    }
}

#[derive(Debug)]
pub struct TlsConfig {
    pub cipher_suites: Box<[PrioritisedCipherSuite]>,
    pub signature_algorithms: Box<[SignatureAlgorithm]>,
    pub session_store: Option<Box<dyn SessionStorage>>,
    pub certificates: Certificates,
    pub server_name: Option<String>,
    pub policy: TlsPolicy,
    pub max_fragment_length: Option<MaxFragmentLength>,
}

pub struct TlsClient<T: Read + Write> {
    config: Rc<TlsConfig>,
    connection: TlsConnection<T>,
}

impl<T: Read + Write> TlsClient<T> {
    pub fn new(config: TlsConfig, stream: T) -> Self {
        let config = Rc::new(config);
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
