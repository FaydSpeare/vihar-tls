use std::cmp::Ordering;

use log::debug;
use num_bigint::BigUint;

use crate::alert::{Alert, AlertDesc};
use crate::ciphersuite::{CipherSuiteId, CompressionMethod, KeyExchangeAlgorithm};
use crate::encoding::{
    LengthPrefixWriter, LengthPrefixedVec, MaybeEmpty, NonEmpty, Reader, TlsCodable, u24,
};
use crate::errors::{DecodingError, InvalidEncodingError};
use crate::extensions::{
    ExtendedMasterSecretExt, Extension, Extensions, MaxFragmentLenExt, RenegotiationInfoExt,
    ServerNameExt, SessionTicketExt, SignatureAlgorithm, sign,
};
use crate::session_ticket::{ClientIdentity, StatePlaintext};
use crate::storage::StekInfo;
use crate::{MaxFragmentLength, TlsPolicy, TlsValidateable, utils};

#[derive(Debug, Clone, Copy)]
pub struct ProtocolVersion {
    pub major: u8,
    pub minor: u8,
}

impl ProtocolVersion {
    pub fn is_tls12(&self) -> bool {
        self.minor == 3 && self.major == 3
    }

    pub fn tls12() -> Self {
        Self { major: 3, minor: 3 }
    }
}

impl PartialEq for ProtocolVersion {
    fn eq(&self, other: &Self) -> bool {
        self.major == other.major && self.minor == other.minor
    }
}

impl PartialOrd for ProtocolVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match self.major.cmp(&other.major) {
            Ordering::Equal => Some(self.minor.cmp(&other.minor)),
            ord => Some(ord),
        }
    }
}

impl TlsCodable for ProtocolVersion {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        self.major.write_to(bytes);
        self.minor.write_to(bytes);
    }

    fn read_from(reader: &mut Reader) -> Result<Self, DecodingError> {
        Ok(ProtocolVersion {
            major: u8::read_from(reader)?,
            minor: u8::read_from(reader)?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Random {
    unix_time: u32,
    random_bytes: [u8; 28],
}

impl TlsCodable for Random {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        self.unix_time.write_to(bytes);
        self.random_bytes.write_to(bytes);
    }
    fn read_from(reader: &mut Reader) -> Result<Self, DecodingError> {
        Ok(Random {
            unix_time: u32::read_from(reader)?,
            random_bytes: TlsCodable::read_from(reader)?,
        })
    }
}

impl Random {
    pub fn as_bytes(&self) -> [u8; 32] {
        let mut bytes = [0; 32];
        bytes[..4].copy_from_slice(&self.unix_time.to_be_bytes());
        bytes[4..].copy_from_slice(&self.random_bytes);
        bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionId(LengthPrefixedVec<u8, u8, MaybeEmpty>);

impl SessionId {
    const MAX_LEN: usize = 32;

    pub fn new(session_id: &[u8]) -> Result<Self, InvalidEncodingError> {
        if session_id.len() > Self::MAX_LEN {
            return Err(InvalidEncodingError::LengthTooLarge(
                Self::MAX_LEN,
                session_id.len(),
            ));
        }
        Ok(Self(session_id.to_vec().try_into()?))
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl TlsCodable for SessionId {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        debug_assert!(self.0.len() <= Self::MAX_LEN);
        self.0.write_to(bytes);
    }
    fn read_from(reader: &mut Reader) -> Result<Self, DecodingError> {
        let session_id = LengthPrefixedVec::<u8, u8, MaybeEmpty>::read_from(reader)?;
        if session_id.len() > Self::MAX_LEN {
            return Err(
                InvalidEncodingError::LengthTooLarge(Self::MAX_LEN, session_id.len()).into(),
            );
        }
        Ok(Self(session_id))
    }
}

type CipherSuites = LengthPrefixedVec<u16, CipherSuiteId, NonEmpty>;
type CompressionMethods = LengthPrefixedVec<u8, CompressionMethod, NonEmpty>;

#[derive(Debug, Clone)]
pub struct ClientHello {
    pub version: ProtocolVersion,
    pub random: Random,
    pub session_id: SessionId,
    pub cipher_suites: CipherSuites,
    pub compression_methods: CompressionMethods,
    pub extensions: Extensions,
}

impl ClientHello {
    pub fn new(
        suites: &[CipherSuiteId],
        extensions: Vec<Extension>,
        session_id: Option<SessionId>,
    ) -> Result<Self, DecodingError> {
        Ok(ClientHello {
            version: ProtocolVersion { major: 3, minor: 3 },
            random: Random {
                unix_time: utils::get_unix_time(),
                random_bytes: utils::get_random_bytes(28).try_into().unwrap(),
            },
            session_id: session_id.unwrap_or(SessionId::new(&[]).unwrap()),
            cipher_suites: suites.to_vec().try_into()?,
            compression_methods: vec![CompressionMethod::Null].try_into()?,
            extensions: Extensions::new(extensions)?,
        })
    }
}

impl From<ClientHello> for TlsHandshake {
    fn from(value: ClientHello) -> Self {
        Self::ClientHello(value)
    }
}

impl TlsCodable for ClientHello {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        self.version.write_to(bytes);
        self.random.write_to(bytes);
        self.session_id.write_to(bytes);
        self.cipher_suites.write_to(bytes);
        self.compression_methods.write_to(bytes);
        self.extensions.write_to(bytes);
    }

    fn read_from(reader: &mut Reader) -> Result<Self, DecodingError> {
        let client_version = ProtocolVersion::read_from(reader)?;
        let random = Random::read_from(reader)?;
        let session_id = SessionId::read_from(reader)?;
        let cipher_suites = CipherSuites::read_from(reader)?;
        let compression_methods = CompressionMethods::read_from(reader)?;
        let extensions = Extensions::read_from(reader)?;
        println!("Client Extensions: {:#?}", extensions);
        Ok(Self {
            version: client_version,
            random,
            session_id,
            cipher_suites,
            compression_methods,
            extensions,
        })
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ServerHello {
    pub version: ProtocolVersion,
    pub random: Random,
    pub session_id: SessionId,
    pub cipher_suite: CipherSuiteId,
    pub compression_method: CompressionMethod,
    pub extensions: Extensions,
}

impl ServerHello {
    pub fn new(
        cipher_suite: CipherSuiteId,
        with_renegotiation_info: bool,
        with_extended_master_secret: bool,
        with_session_ticket: bool,
        with_server_name: bool,
        renegotiation_info: Option<Vec<u8>>,
        max_fragment_len: Option<MaxFragmentLength>,
    ) -> Self {
        let mut extensions = vec![];
        if let Some(len) = max_fragment_len {
            extensions.push(MaxFragmentLenExt::new(len).into());
        }

        if with_renegotiation_info {
            if let Some(info) = renegotiation_info {
                extensions.push(RenegotiationInfoExt::renegotiation(&info).unwrap().into());
            } else {
                extensions.push(RenegotiationInfoExt::IndicateSupport.into());
            }
        }

        if with_extended_master_secret {
            extensions.push(ExtendedMasterSecretExt::indicate_support().into());
        }

        if with_session_ticket {
            extensions.push(SessionTicketExt::new().into());
        }

        if with_server_name {
            extensions.push(ServerNameExt::empty().into());
        }

        Self {
            version: ProtocolVersion { major: 3, minor: 3 },
            random: Random {
                unix_time: utils::get_unix_time(),
                random_bytes: utils::get_random_bytes(28).try_into().unwrap(),
            },
            session_id: SessionId(utils::get_random_bytes(32).try_into().unwrap()),
            cipher_suite,
            compression_method: CompressionMethod::Null,
            extensions: Extensions::new(extensions).unwrap(),
        }
    }

    pub fn supports_secure_renegotiation(&self) -> bool {
        self.extensions.includes_secure_renegotiation()
    }

    pub fn supports_session_ticket(&self) -> bool {
        self.extensions.includes_session_ticket()
    }

    pub fn supports_extended_master_secret(&self) -> bool {
        self.extensions.includes_extended_master_secret()
    }
}

impl From<ServerHello> for TlsHandshake {
    fn from(value: ServerHello) -> Self {
        Self::ServerHello(value)
    }
}

impl TlsCodable for ServerHello {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        self.version.write_to(bytes);
        self.random.write_to(bytes);
        self.session_id.write_to(bytes);
        self.cipher_suite.write_to(bytes);
        self.compression_method.write_to(bytes);
        self.extensions.write_to(bytes);
    }
    fn read_from(reader: &mut Reader) -> Result<Self, DecodingError> {
        let server_version = ProtocolVersion::read_from(reader)?;
        let random = Random::read_from(reader)?;
        let session_id = SessionId::read_from(reader)?;
        let cipher_suite = CipherSuiteId::read_from(reader)?;
        let compression_method = CompressionMethod::read_from(reader)?;
        let extensions = Extensions::read_from(reader)?;
        println!("Server Extensions: {:#?}", extensions.extension_type_set());
        Ok(Self {
            version: server_version,
            random,
            session_id,
            cipher_suite,
            compression_method,
            extensions,
        })
    }
}

type ASN1Cert = LengthPrefixedVec<u24, u8, NonEmpty>;
pub type CeritificateList = LengthPrefixedVec<u24, ASN1Cert, MaybeEmpty>;

#[derive(Debug, Clone)]
pub struct Certificate {
    pub list: CeritificateList,
}

impl Certificate {
    pub fn new(cert: Vec<u8>) -> Self {
        let cert: ASN1Cert = cert.try_into().unwrap();
        Self {
            list: vec![cert].try_into().unwrap(),
        }
    }
    pub fn empty() -> Self {
        Self {
            list: vec![].try_into().unwrap(),
        }
    }
}

impl From<Certificate> for TlsHandshake {
    fn from(value: Certificate) -> Self {
        Self::Certificate(value)
    }
}

impl TlsCodable for Certificate {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        self.list.write_to(bytes);
    }
    fn read_from(reader: &mut Reader) -> Result<Self, DecodingError> {
        let list = CeritificateList::read_from(reader)?;
        Ok(Self { list })
    }
}

// struct {
//  SignatureAndHashAlgorithm algorithm;
//  opaque signature<0..2^16-1>;
// } DigitallySigned;

// struct {
//     HashAlgorithm hash;
//     SignatureAlgorithm signature;
// } SignatureAndHashAlgorithm;
//
// ServerDHParams params;
//    digitally-signed struct {
//        opaque client_random[32];
//        opaque server_random[32];
//        ServerDHParams params;
//    } signed_params;
//
// struct {
//    opaque dh_p<1..2^16-1>;
//    opaque dh_g<1..2^16-1>;
//    opaque dh_Ys<1..2^16-1>;
// } ServerDHParams

// pub enum ECCurveType {}
// pub enum NamedCurve {}
// pub struct ECParams {}
// pub struct ECPoint {}
// pub struct ServerECDHParams {}
//
// #[derive(Debug)]
// pub enum ServerKeyExchange {
//     Dhe(DheServerKeyExchange),
//     Ecdhe(EcdheServerKeyExchange),
//     Unresolved(Vec<u8>),
// }
//
// impl ServerKeyExchange {
//     pub fn resolve(self, kx_algo: KeyExchangeAlgorithm) -> TLSResult<ServerKeyExchange> {
//         if let Self::Unresolved(bytes) = self {
//             match kx_algo {
//                 KeyExchangeAlgorithm::DheRsa | KeyExchangeAlgorithm::DheDss => {
//                     return ServerKeyExchange::Dhe(DheServerKeyExchange::try_from(bytes.as_ref())?)
//                 }
//                 KeyExchangeAlgorithm::EcdheRsa => ServerKeyExchange::Ecdhe(EcdheServerKeyExchange::try_from(bytes)?),
//                 _ => panic!("NOPE"),
//             };
//         }
//         panic!("NOPE");
//     }
// }
//
// impl ToBytes for ServerKeyExchange {
//     fn to_bytes(&self) -> Vec<u8> {
//         match self {
//             Self::Dhe(kx) => kx.to_bytes(),
//             Self::Ecdhe(kx) => unimplemented!(),
//             Self::Unresolved(bytes) => bytes.clone(),
//         }
//     }
// }
//
// impl TryFrom<&[u8]> for ServerKeyExchange {
//     type Error = Box<dyn std::error::Error>;
//
//     fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
//         Ok(Self::Unresolved(buf.to_vec()))
//     }
// }
//
// #[derive(Debug)]
// pub struct EcdheServerKeyExchange {
//     pub p: Vec<u8>,
//     pub g: Vec<u8>,
//     pub server_pubkey: Vec<u8>,
//     pub hash_algo: HashAlgo,
//     pub sig_algo: SigAlgo,
//     pub signature: Vec<u8>,
// }

type DhParam = LengthPrefixedVec<u16, u8, NonEmpty>;
type Signature = LengthPrefixedVec<u16, u8, MaybeEmpty>;

#[derive(Debug, Clone)]
pub struct ServerDhParams {
    pub p: BigUint,
    pub g: BigUint,
    pub server_public_key: BigUint,
}

impl ServerDhParams {
    pub fn new(p: BigUint, g: BigUint, server_public_key: BigUint) -> Self {
        Self {
            p,
            g,
            server_public_key,
        }
    }
}

impl TlsCodable for ServerDhParams {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        DhParam::try_from(self.p.to_bytes_be())
            .unwrap()
            .write_to(bytes);
        DhParam::try_from(self.g.to_bytes_be())
            .unwrap()
            .write_to(bytes);
        DhParam::try_from(self.server_public_key.to_bytes_be())
            .unwrap()
            .write_to(bytes);
    }
    fn read_from(reader: &mut Reader) -> Result<Self, DecodingError> {
        Ok(Self {
            p: BigUint::from_bytes_be(&DhParam::read_from(reader)?),
            g: BigUint::from_bytes_be(&DhParam::read_from(reader)?),
            server_public_key: BigUint::from_bytes_be(&DhParam::read_from(reader)?),
        })
    }
}

#[derive(Debug, Clone)]
pub struct DigitallySigned {
    pub signature_algorithm: SignatureAlgorithm,
    pub signature: Signature,
}

impl TlsCodable for DigitallySigned {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        self.signature_algorithm.write_to(bytes);
        self.signature.write_to(bytes);
    }
    fn read_from(reader: &mut Reader) -> Result<Self, DecodingError> {
        Ok(Self {
            signature_algorithm: SignatureAlgorithm::read_from(reader)?,
            signature: Signature::read_from(reader)?,
        })
    }
}

//type ClientKeyExchangeBytes = LengthPrefixedVec<u16, u8, NonEmpty>;

#[derive(Debug, Clone)]
pub enum ServerKeyExchangeInner {
    Dhe(DheServerKeyExchange),
    DhAnon(ServerDhParams),
}

#[derive(Debug, Clone)]
pub enum ServerKeyExchange {
    Resolved(ServerKeyExchangeInner),
    Unresolved(Vec<u8>),
}

impl ServerKeyExchange {
    pub fn new_dh_anon(params: ServerDhParams) -> Self {
        Self::Resolved(ServerKeyExchangeInner::DhAnon(params))
    }
    pub fn new_dhe(
        params: ServerDhParams,
        client_random: [u8; 32],
        server_random: [u8; 32],
        signature_algorithm: SignatureAlgorithm,
        private_key_der: &[u8],
    ) -> Self {
        let data = [&client_random[..], &server_random, &params.get_encoding()].concat();
        let signature = sign(signature_algorithm, private_key_der, &data).unwrap();
        Self::Resolved(ServerKeyExchangeInner::Dhe(DheServerKeyExchange {
            params,
            signed_params: DigitallySigned {
                signature_algorithm,
                signature: signature.try_into().unwrap(),
            },
        }))
    }

    pub fn resolve(&self, kx: KeyExchangeAlgorithm) -> ServerKeyExchangeInner {
        match self {
            Self::Resolved(x) => x.clone(),
            Self::Unresolved(bytes) => {
                let mut reader = Reader::new(bytes);
                match kx {
                    KeyExchangeAlgorithm::DhAnon => {
                        return ServerKeyExchangeInner::DhAnon(
                            ServerDhParams::read_from(&mut reader).unwrap(),
                        );
                    }
                    _ => {
                        return ServerKeyExchangeInner::Dhe(
                            DheServerKeyExchange::read_from(&mut reader).unwrap(),
                        );
                    }
                }
            }
        }
    }
}

impl TlsCodable for ServerKeyExchange {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        match self {
            Self::Resolved(ServerKeyExchangeInner::Dhe(kx)) => kx.write_to(bytes),
            Self::Resolved(ServerKeyExchangeInner::DhAnon(kx)) => kx.write_to(bytes),
            Self::Unresolved(x) => bytes.extend_from_slice(&x),
        };
    }
    fn read_from(reader: &mut Reader) -> Result<Self, DecodingError> {
        Ok(Self::Unresolved(reader.consume_rest().to_vec()))
    }
}

#[derive(Debug, Clone)]
pub struct DheServerKeyExchange {
    pub params: ServerDhParams,
    pub signed_params: DigitallySigned,
}

impl TlsCodable for DheServerKeyExchange {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        self.params.write_to(bytes);
        self.signed_params.write_to(bytes);
    }
    fn read_from(reader: &mut Reader) -> Result<Self, DecodingError> {
        Ok(Self {
            params: ServerDhParams::read_from(reader)?,
            signed_params: DigitallySigned::read_from(reader)?,
        })
    }
}

impl From<ServerKeyExchange> for TlsHandshake {
    fn from(value: ServerKeyExchange) -> Self {
        Self::ServerKeyExchange(value)
    }
}

tls_codable_enum! {
    #[repr(u8)]
    pub enum ClientCertificateType {
        RsaSign = 1, // A certificate containing an RSA key
        DssSign = 2, // A certificate containing an DSA key
        RsaFixedDh = 3, // A certificate containing a static DH key
        DssFixedDh = 4 // A certificate containing a static DH key
    }
}

type CertificateTypes = LengthPrefixedVec<u8, ClientCertificateType, NonEmpty>;
type DistinguishedName = LengthPrefixedVec<u16, u8, NonEmpty>;
type CertificateAuthorities = LengthPrefixedVec<u16, DistinguishedName, MaybeEmpty>;
type SupportedSignatureAlgorithms = LengthPrefixedVec<u16, SignatureAlgorithm, MaybeEmpty>;

#[derive(Debug, Clone)]
pub struct CertificateRequest {
    pub certificate_types: CertificateTypes,
    pub supported_signature_algorithms: SupportedSignatureAlgorithms,
    pub certificate_authorities: CertificateAuthorities,
}

impl CertificateRequest {
    pub fn new(
        signature_algorithms: &[SignatureAlgorithm],
        certificate_types: &[ClientCertificateType],
    ) -> Self {
        Self {
            certificate_types: certificate_types.to_vec().try_into().unwrap(),
            supported_signature_algorithms: signature_algorithms.to_vec().try_into().unwrap(),
            certificate_authorities: vec![].try_into().unwrap(), // TODO: config
        }
    }
}

impl TlsCodable for CertificateRequest {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        self.certificate_types.write_to(bytes);
        self.supported_signature_algorithms.write_to(bytes);
        self.certificate_authorities.write_to(bytes);
    }
    fn read_from(reader: &mut Reader) -> Result<Self, DecodingError> {
        Ok(Self {
            certificate_types: CertificateTypes::read_from(reader)?,
            supported_signature_algorithms: SupportedSignatureAlgorithms::read_from(reader)?,
            certificate_authorities: CertificateAuthorities::read_from(reader)?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct CertificateVerify {
    pub signed: DigitallySigned,
}

impl CertificateVerify {
    pub fn new(signature_algorithm: SignatureAlgorithm, signature: Vec<u8>) -> Self {
        Self {
            signed: DigitallySigned {
                signature_algorithm,
                signature: signature.try_into().unwrap(),
            },
        }
    }
}

impl TlsCodable for CertificateVerify {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        self.signed.write_to(bytes);
    }
    fn read_from(reader: &mut Reader) -> Result<Self, DecodingError> {
        Ok(Self {
            signed: DigitallySigned::read_from(reader)?,
        })
    }
}

type ClientKeyExchangeBytes = LengthPrefixedVec<u16, u8, NonEmpty>;

#[derive(Debug, Clone)]
pub enum PublicValueEncoding {
    Implicit,
    Explicit(ClientKeyExchangeBytes),
}

#[derive(Debug, Clone)]
pub enum ClientKeyExchangeInner {
    EncryptedPreMasterSecret(ClientKeyExchangeBytes),
    ClientDiffieHellmanPublic(PublicValueEncoding),
}

#[derive(Debug, Clone)]
pub enum ClientKeyExchange {
    Resolved(ClientKeyExchangeInner),
    Unresolved(ClientKeyExchangeBytes),
}

impl ClientKeyExchange {
    pub fn new_dh() -> Self {
        Self::Resolved(ClientKeyExchangeInner::ClientDiffieHellmanPublic(
            PublicValueEncoding::Implicit,
        ))
    }
    pub fn new_dhe(client_public_key_der: Vec<u8>) -> Self {
        Self::Resolved(ClientKeyExchangeInner::ClientDiffieHellmanPublic(
            PublicValueEncoding::Explicit(
                client_public_key_der
                    .try_into()
                    .expect("significantly smaller"),
            ),
        ))
    }
    pub fn new_rsa(encrypted_pre_master_secret: Vec<u8>) -> Self {
        Self::Resolved(ClientKeyExchangeInner::EncryptedPreMasterSecret(
            encrypted_pre_master_secret
                .try_into()
                .expect("significantly smaller"),
        ))
    }
    pub fn resolve(&self, kx: KeyExchangeAlgorithm) -> ClientKeyExchangeInner {
        match self {
            Self::Unresolved(bytes) => match kx {
                KeyExchangeAlgorithm::DheRsa
                | KeyExchangeAlgorithm::DheDss
                | KeyExchangeAlgorithm::DhRsa
                | KeyExchangeAlgorithm::DhDss
                | KeyExchangeAlgorithm::DhAnon => {
                    ClientKeyExchangeInner::ClientDiffieHellmanPublic(
                        PublicValueEncoding::Explicit(bytes.clone()),
                    )
                }
                KeyExchangeAlgorithm::Rsa => {
                    ClientKeyExchangeInner::EncryptedPreMasterSecret(bytes.clone())
                }
                _ => unimplemented!(),
            },
            Self::Resolved(inner) => inner.clone(),
        }
    }
}

impl From<ClientKeyExchange> for TlsHandshake {
    fn from(value: ClientKeyExchange) -> Self {
        Self::ClientKeyExchange(value)
    }
}

impl TlsCodable for ClientKeyExchange {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        match self {
            Self::Resolved(inner) => match inner {
                ClientKeyExchangeInner::ClientDiffieHellmanPublic(
                    PublicValueEncoding::Implicit,
                ) => {}
                ClientKeyExchangeInner::ClientDiffieHellmanPublic(
                    PublicValueEncoding::Explicit(value),
                ) => value.write_to(bytes),
                ClientKeyExchangeInner::EncryptedPreMasterSecret(value) => value.write_to(bytes),
            },
            Self::Unresolved(value) => value.write_to(bytes),
        };
    }
    fn read_from(reader: &mut Reader) -> Result<Self, DecodingError> {
        Ok(Self::Unresolved(ClientKeyExchangeBytes::read_from(reader)?))
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Finished {
    pub verify_data: Vec<u8>,
}

impl Finished {
    pub fn new(verify_data: Vec<u8>) -> Self {
        Self { verify_data }
    }
}

impl TlsCodable for Finished {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.verify_data);
    }
    fn read_from(reader: &mut Reader) -> Result<Self, DecodingError> {
        let verify_data = reader.consume_rest().to_vec();
        Ok(Self { verify_data })
    }
}

impl From<Finished> for TlsHandshake {
    fn from(value: Finished) -> Self {
        Self::Finished(value)
    }
}

type SessionTicketBytes = LengthPrefixedVec<u16, u8, MaybeEmpty>;

#[derive(Hash, Eq, PartialEq, Debug, Clone)]
pub struct NewSessionTicket {
    lifetime_hint: u32,
    pub ticket: SessionTicketBytes,
}

impl NewSessionTicket {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuiteId,
        compression_method: CompressionMethod,
        master_secret: [u8; 48],
        client_identity: ClientIdentity,
        timestamp: u32,
        max_fragment_length: Option<MaxFragmentLength>,
        extended_master_secret: bool,
        stek: &StekInfo,
    ) -> Self {
        let session_ticket = StatePlaintext {
            timestamp,
            protocol_version,
            cipher_suite,
            compression_method,
            master_secret,
            client_identity,
            max_fragment_length,
            extended_master_secret,
        }
        .encrypt(stek);
        Self {
            lifetime_hint: 0,
            ticket: session_ticket.get_encoding().try_into().unwrap(),
        }
    }
}

impl TlsCodable for NewSessionTicket {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        self.lifetime_hint.write_to(bytes);
        self.ticket.write_to(bytes);
    }
    fn read_from(reader: &mut Reader) -> Result<Self, DecodingError> {
        let lifetime_hint = u32::read_from(reader)?;
        let ticket = SessionTicketBytes::read_from(reader)?;
        Ok(Self {
            lifetime_hint,
            ticket,
        })
    }
}

impl From<NewSessionTicket> for TlsHandshake {
    fn from(value: NewSessionTicket) -> Self {
        Self::NewSessionTicket(value)
    }
}

tls_codable_enum! {
    #[repr(u8)]
    pub enum TlsContentType {
        ChangeCipherSpec = 20,
        Alert = 21,
        Handshake = 22,
        ApplicationData = 23,
    }
}

tls_codable_enum! {
    #[repr(u8)]
    pub enum TlsHandshakeType {
        ClientHello = 1,
        ServerHello = 2,
        NewSessionTicket = 4,
        Certificates = 11,
        ServerKeyExchange = 12,
        CertificateRequest = 13,
        ServerHelloDone = 14,
        CertificateVerify = 15,
        ClientKeyExchange = 16,
        Finished = 20,
    }
}

#[derive(Debug, Clone)]
pub enum TlsHandshake {
    ClientHello(ClientHello),
    ServerHello(ServerHello),
    NewSessionTicket(NewSessionTicket),
    Certificate(Certificate),
    ServerKeyExchange(ServerKeyExchange),
    ServerHelloDone,
    CertificateVerify(CertificateVerify),
    CertificateRequest(CertificateRequest),
    ClientKeyExchange(ClientKeyExchange),
    Finished(Finished),
}

impl TlsHandshake {
    fn handshake_type(&self) -> TlsHandshakeType {
        match self {
            Self::ClientHello(_) => TlsHandshakeType::ClientHello,
            Self::ServerHello(_) => TlsHandshakeType::ServerHello,
            Self::NewSessionTicket(_) => TlsHandshakeType::NewSessionTicket,
            Self::Certificate(_) => TlsHandshakeType::Certificates,
            Self::ServerKeyExchange(_) => TlsHandshakeType::ServerKeyExchange,
            Self::ServerHelloDone => TlsHandshakeType::ServerHelloDone,
            Self::CertificateVerify(_) => TlsHandshakeType::CertificateVerify,
            Self::CertificateRequest(_) => TlsHandshakeType::CertificateRequest,
            Self::ClientKeyExchange(_) => TlsHandshakeType::ClientKeyExchange,
            Self::Finished(_) => TlsHandshakeType::Finished,
        }
    }

    pub fn validate(&self, policy: &TlsPolicy) -> Result<(), Alert> {
        if let Self::ClientHello(hello) = self {
            hello.extensions.validate(policy)?
        }
        Ok(())
    }
}

impl TlsCodable for TlsHandshake {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        self.handshake_type().write_to(bytes);
        let mut writer = LengthPrefixWriter::<u24>::new(bytes);

        match self {
            Self::ClientHello(h) => h.write_to(&mut writer),
            Self::ServerHello(h) => h.write_to(&mut writer),
            Self::NewSessionTicket(h) => h.write_to(&mut writer),
            Self::Certificate(h) => h.write_to(&mut writer),
            Self::ServerKeyExchange(h) => h.write_to(&mut writer),
            Self::ServerHelloDone => {}
            Self::CertificateVerify(h) => h.write_to(&mut writer),
            Self::CertificateRequest(h) => h.write_to(&mut writer),
            Self::ClientKeyExchange(h) => h.write_to(&mut writer),
            Self::Finished(h) => h.write_to(&mut writer),
        }

        writer.finalize_length_prefix();
    }

    fn read_from(reader: &mut Reader) -> Result<Self, DecodingError> {
        let handshake_type = TlsHandshakeType::read_from(reader)?;
        let len = u24::read_from(reader)?;
        let mut subreader = reader.consume(len.into()).map(Reader::new)?;
        match handshake_type {
            TlsHandshakeType::ClientHello => {
                ClientHello::read_from(&mut subreader).map(TlsHandshake::ClientHello)
            }
            TlsHandshakeType::ServerHello => {
                ServerHello::read_from(&mut subreader).map(TlsHandshake::ServerHello)
            }
            TlsHandshakeType::NewSessionTicket => {
                NewSessionTicket::read_from(&mut subreader).map(TlsHandshake::NewSessionTicket)
            }
            TlsHandshakeType::Certificates => {
                Certificate::read_from(&mut subreader).map(TlsHandshake::Certificate)
            }
            TlsHandshakeType::ServerKeyExchange => {
                ServerKeyExchange::read_from(&mut subreader).map(TlsHandshake::ServerKeyExchange)
            }
            TlsHandshakeType::ServerHelloDone => Ok(TlsHandshake::ServerHelloDone),
            TlsHandshakeType::ClientKeyExchange => {
                ClientKeyExchange::read_from(&mut subreader).map(TlsHandshake::ClientKeyExchange)
            }
            TlsHandshakeType::Finished => {
                Finished::read_from(&mut subreader).map(TlsHandshake::Finished)
            }
            TlsHandshakeType::CertificateRequest => {
                CertificateRequest::read_from(&mut subreader).map(TlsHandshake::CertificateRequest)
            }
            TlsHandshakeType::CertificateVerify => {
                CertificateVerify::read_from(&mut subreader).map(TlsHandshake::CertificateVerify)
            }
            TlsHandshakeType::Unknown(_) => unimplemented!(),
        }
    }
}

impl From<TlsHandshake> for TlsMessage {
    fn from(value: TlsHandshake) -> Self {
        TlsMessage::Handshake(value)
    }
}

impl TryFrom<TlsHandshake> for TlsPlaintext {
    type Error = DecodingError;

    fn try_from(value: TlsHandshake) -> Result<Self, Self::Error> {
        TlsPlaintext::new(TlsContentType::Handshake, value.get_encoding())
    }
}

#[derive(Debug)]
pub enum TlsMessage {
    Handshake(TlsHandshake),
    Alert(Alert),
    ChangeCipherSpec,
    ApplicationData(Vec<u8>),
}

impl TlsMessage {
    pub fn new_appdata(bytes: Vec<u8>) -> Self {
        Self::ApplicationData(bytes)
    }

    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::ApplicationData(bytes) => bytes.to_vec(),
            Self::Alert(alert) => alert.get_encoding(),
            Self::Handshake(handshake) => handshake.get_encoding(),
            Self::ChangeCipherSpec => vec![1],
        }
    }

    pub fn content_type(&self) -> TlsContentType {
        match self {
            Self::ApplicationData(_) => TlsContentType::ApplicationData,
            Self::Alert(_) => TlsContentType::Alert,
            Self::Handshake(_) => TlsContentType::Handshake,
            Self::ChangeCipherSpec => TlsContentType::ChangeCipherSpec,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TlsPlaintext {
    pub content_type: TlsContentType,
    pub version: ProtocolVersion,
    pub fragment: Vec<u8>,
}

impl TlsPlaintext {
    pub fn new(content_type: TlsContentType, fragment: Vec<u8>) -> Result<Self, DecodingError> {
        Ok(Self {
            content_type,
            version: ProtocolVersion { major: 3, minor: 3 },
            fragment,
        })
    }
}

impl TlsValidateable for TlsPlaintext {
    fn validate(&self, _policy: &TlsPolicy) -> Result<(), Alert> {
        if let TlsContentType::Unknown(x) = self.content_type {
            debug!("Received unrecognised content type: {}", x);
            return Err(Alert::fatal(AlertDesc::UnexpectedMessage));
        }
        Ok(())
    }
}

impl TryFrom<TlsMessage> for TlsPlaintext {
    type Error = DecodingError;

    fn try_from(value: TlsMessage) -> Result<Self, Self::Error> {
        match value {
            TlsMessage::ChangeCipherSpec => {
                TlsPlaintext::new(TlsContentType::ChangeCipherSpec, vec![1])
            }
            TlsMessage::Alert(alert) => TlsPlaintext::try_from(alert),
            TlsMessage::Handshake(msg) => TlsPlaintext::try_from(msg),
            TlsMessage::ApplicationData(data) => {
                TlsPlaintext::new(TlsContentType::ApplicationData, data)
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct TlsCompressed {
    pub content_type: TlsContentType,
    pub version: ProtocolVersion,
    pub fragment: Vec<u8>,
}

pub struct TlsCiphertext {
    pub content_type: TlsContentType,
    pub version: ProtocolVersion,
    pub fragment: Vec<u8>,
}

impl TlsCodable for TlsCiphertext {
    fn read_from(reader: &mut Reader) -> Result<Self, DecodingError> {
        let content_type = TlsContentType::read_from(reader)?;
        let version = ProtocolVersion::read_from(reader)?;
        let fragment_len = u16::read_from(reader)? as usize;
        let fragment = reader.consume(fragment_len)?;
        Ok(Self {
            content_type,
            version,
            fragment: fragment.to_vec(),
        })
    }

    fn write_to(&self, bytes: &mut Vec<u8>) {
        self.content_type.write_to(bytes);
        self.version.write_to(bytes);
        (self.fragment.len() as u16).write_to(bytes);
        bytes.extend_from_slice(&self.fragment);
    }
}
