use crate::alert::TLSAlert;
use crate::ciphersuite::CipherSuiteId;
use crate::encoding::{
    CodingError, LengthPrefixWriter, LengthPrefixedVec, MaybeEmpty, NonEmpty, Reader, TlsCodable,
    u24,
};
use crate::extensions::{Extension, Extensions, HashAlgo, SigAlgo, SignatureAlgorithmsExt};
use crate::utils;
use crate::{TLSError, TLSResult};
use num_enum::TryFromPrimitive;

#[derive(Debug, Clone)]
pub struct ProtocolVersion {
    pub major: u8,
    pub minor: u8,
}

impl TlsCodable for ProtocolVersion {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        self.major.write_to(bytes);
        self.minor.write_to(bytes);
    }

    fn read_from(reader: &mut Reader) -> Result<Self, CodingError> {
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
    fn read_from(reader: &mut Reader) -> Result<Self, CodingError> {
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

    pub fn new(session_id: &[u8]) -> Result<Self, CodingError> {
        if session_id.len() > Self::MAX_LEN {
            return Err(CodingError::LengthTooLarge);
        }
        Ok(Self(session_id.to_vec().try_into()?))
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
    fn read_from(reader: &mut Reader) -> Result<Self, CodingError> {
        let session_id = LengthPrefixedVec::<u8, u8, MaybeEmpty>::read_from(reader)?;
        if session_id.len() > Self::MAX_LEN {
            return Err(CodingError::LengthTooLarge);
        }
        Ok(Self(session_id))
    }
}

tls_codable_enum! {
    #[repr(u8)]
    pub enum CompressionMethodId {
        Null = 0
    }
}

type CipherSuites = LengthPrefixedVec<u16, CipherSuiteId, NonEmpty>;
type CompressionMethods = LengthPrefixedVec<u8, CompressionMethodId, NonEmpty>;

#[derive(Debug, Clone)]
pub struct ClientHello {
    pub client_version: ProtocolVersion,
    pub random: Random,
    pub session_id: SessionId,
    pub cipher_suites: CipherSuites,
    pub compression_methods: CompressionMethods,
    pub extensions: Extensions,
}

impl ClientHello {
    pub fn new(
        suites: &[CipherSuiteId],
        mut extensions: Vec<Extension>,
        session_id: Option<SessionId>,
    ) -> Result<Self, CodingError> {
        extensions.push(
            SignatureAlgorithmsExt::new_from_product(
                vec![SigAlgo::Rsa, SigAlgo::Dsa],
                vec![HashAlgo::Sha1, HashAlgo::Sha256],
            )?
            .into(),
        );
        // println!("Client Extensions {:?}", extensions);
        Ok(ClientHello {
            client_version: ProtocolVersion { major: 3, minor: 3 },
            random: Random {
                unix_time: utils::get_unix_time(),
                random_bytes: utils::get_random_bytes(28).try_into().unwrap(),
            },
            session_id: session_id.unwrap_or(SessionId::new(&[]).unwrap()),
            cipher_suites: suites.to_vec().try_into()?,
            compression_methods: vec![CompressionMethodId::Null].try_into()?,
            extensions: Extensions::new(extensions)?,
        })
    }
}

impl TlsCodable for ClientHello {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        self.client_version.write_to(bytes);
        self.random.write_to(bytes);
        self.session_id.write_to(bytes);
        self.cipher_suites.write_to(bytes);
        self.compression_methods.write_to(bytes);
        self.extensions.write_to(bytes);
    }

    fn read_from(reader: &mut Reader) -> Result<Self, CodingError> {
        let client_version = ProtocolVersion::read_from(reader)?;
        let random = Random::read_from(reader)?;
        let session_id = SessionId::read_from(reader)?;
        let cipher_suites = CipherSuites::read_from(reader)?;
        let compression_methods = CompressionMethods::read_from(reader)?;
        let extensions = Extensions::read_from(reader)?;
        Ok(Self {
            client_version,
            random,
            session_id,
            cipher_suites,
            compression_methods,
            extensions,
        })
    }
}

impl ToBytes for ClientHello {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::<u8>::new();
        self.client_version.write_to(&mut bytes);
        self.random.write_to(&mut bytes);
        self.session_id.write_to(&mut bytes);
        self.cipher_suites.write_to(&mut bytes);
        self.compression_methods.write_to(&mut bytes);
        self.extensions.write_to(&mut bytes);
        handshake_bytes(TlsHandshakeType::ClientHello, &bytes)
    }
}

impl IntoBytes for ClientHello {
    fn into_bytes(self) -> Vec<u8> {
        self.to_bytes()
    }
}

impl From<ClientHello> for TLSPlaintext {
    fn from(value: ClientHello) -> TLSPlaintext {
        TLSPlaintext::new(TLSContentType::Handshake, value.into_bytes())
    }
}

impl From<ClientHello> for TlsMessage {
    fn from(value: ClientHello) -> TlsMessage {
        TlsMessage::Handshake(TlsHandshake::ClientHello(value))
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct ServerHello {
    pub server_version: ProtocolVersion,
    pub random: Random,
    pub session_id: SessionId,
    pub cipher_suite: CipherSuiteId,
    pub compression_method: CompressionMethodId,
    pub extensions: Extensions,
}

impl ServerHello {
    pub fn supports_secure_renegotiation(&self) -> bool {
        self.extensions.includes_secure_renegotiation()
    }

    pub fn supports_session_ticket(&self) -> bool {
        self.extensions.includes_session_ticket()
    }

    pub fn supports_extended_master_secret(&self) -> bool {
        false
        //self.extensions
        //    .iter()
        //    .any(|x| matches!(x, Extension::ExtendedMasterSecret(_)))
    }
}

impl TlsCodable for ServerHello {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        self.server_version.write_to(bytes);
        self.random.write_to(bytes);
        self.session_id.write_to(bytes);
        self.cipher_suite.write_to(bytes);
        self.compression_method.write_to(bytes);
        self.extensions.write_to(bytes);
    }
    fn read_from(reader: &mut Reader) -> Result<Self, CodingError> {
        let server_version = ProtocolVersion::read_from(reader)?;
        let random = Random::read_from(reader)?;
        let session_id = SessionId::read_from(reader)?;
        let cipher_suite = CipherSuiteId::read_from(reader)?;
        let compression_method = CompressionMethodId::read_from(reader)?;
        let extensions = Extensions::read_from(reader)?;
        Ok(Self {
            server_version,
            random,
            session_id,
            cipher_suite,
            compression_method,
            extensions,
        })
    }
}

impl ToBytes for ServerHello {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::<u8>::new();
        self.server_version.write_to(&mut bytes);
        self.random.write_to(&mut bytes);
        self.session_id.write_to(&mut bytes);
        self.cipher_suite.write_to(&mut bytes);
        self.compression_method.write_to(&mut bytes);
        self.extensions.write_to(&mut bytes);
        handshake_bytes(TlsHandshakeType::ServerHello, &bytes)
    }
}

impl TryFrom<&[u8]> for ServerHello {
    type Error = Box<dyn std::error::Error>;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        let mut reader = Reader::new(buf);
        let server_version = ProtocolVersion::read_from(&mut reader)?;
        let random = Random::read_from(&mut reader)?;
        let session_id = SessionId::read_from(&mut reader)?;
        let cipher_suite = CipherSuiteId::read_from(&mut reader)?;
        let compression_method = CompressionMethodId::read_from(&mut reader)?;
        let extensions = Extensions::read_from(&mut reader)?;
        // println!("Server Extensions {:?}", extensions);
        Ok(Self {
            server_version,
            random,
            session_id,
            cipher_suite,
            compression_method,
            extensions,
        })
    }
}

type ASN1Cert = LengthPrefixedVec<u24, u8, NonEmpty>;
type CeritificateList = LengthPrefixedVec<u24, ASN1Cert, MaybeEmpty>;

#[derive(Debug)]
pub struct Certificate {
    pub list: CeritificateList,
}

impl TlsCodable for Certificate {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        self.list.write_to(bytes);
    }
    fn read_from(reader: &mut Reader) -> Result<Self, CodingError> {
        let list = CeritificateList::read_from(reader)?;
        Ok(Self { list })
    }
}

impl ToBytes for Certificate {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::<u8>::new();
        self.list.write_to(&mut bytes);
        handshake_bytes(TlsHandshakeType::Certificates, &bytes)
    }
}

impl TryFrom<&[u8]> for Certificate {
    type Error = Box<dyn std::error::Error>;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        let mut reader = Reader::new(buf);
        let list = CeritificateList::read_from(&mut reader)?;
        Ok(Self { list })

        // let cert_bytes = u32::from_be_bytes([0, buf[0], buf[1], buf[2]]) as usize;

        // let slice = &buf[3..];
        // if cert_bytes > slice.len() {
        //     return Err(TLSError::NeedData.into());
        // }

        // let mut idx = 0;
        // let mut certs: Vec<Certificate> = vec![];

        // while idx < cert_bytes {
        //     let cert_len =
        //         u32::from_be_bytes([0, slice[idx], slice[idx + 1], slice[idx + 2]]) as usize;
        //     certs.push(Certificate {
        //         bytes: slice[idx + 3..idx + 3 + cert_len].to_vec(),
        //     });
        //     idx += 3 + cert_len;
        // }

        // return Ok(Self { list: certs });
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

#[derive(Debug)]
pub struct ServerKeyExchange {
    pub p: Vec<u8>,
    pub g: Vec<u8>,
    pub server_pubkey: Vec<u8>,
    pub hash_algo: HashAlgo,
    pub sig_algo: SigAlgo,
    pub signature: Vec<u8>,
}

impl ServerKeyExchange {
    pub fn dh_params_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(self.p.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.p);
        bytes.extend_from_slice(&(self.g.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.g);
        bytes.extend_from_slice(&(self.server_pubkey.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.server_pubkey);
        bytes
    }
}

impl ToBytes for ServerKeyExchange {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::<u8>::new();
        bytes.extend_from_slice(&(self.p.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.p);
        bytes.extend_from_slice(&(self.g.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.g);
        bytes.extend_from_slice(&(self.server_pubkey.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.server_pubkey);
        bytes.push(u8::from(self.hash_algo));
        bytes.push(u8::from(self.sig_algo));
        bytes.extend_from_slice(&(self.signature.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.signature);
        handshake_bytes(TlsHandshakeType::ServerKeyExchange, &bytes)
    }
}

impl TryFrom<&[u8]> for ServerKeyExchange {
    type Error = Box<dyn std::error::Error>;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        let p_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
        let p = buf[2..2 + p_len].to_vec();

        let mut idx = 2 + p_len;
        let g_len = u16::from_be_bytes([buf[idx], buf[idx + 1]]) as usize;
        let g = buf[idx + 2..idx + 2 + g_len].to_vec();

        idx += 2 + g_len;
        let pk_len = u16::from_be_bytes([buf[idx], buf[idx + 1]]) as usize;
        let server_pubkey = buf[idx + 2..idx + 2 + pk_len].to_vec();

        idx += 2 + pk_len;
        let hash_algo = HashAlgo::try_from(buf[idx])?;
        let sig_algo = SigAlgo::try_from(buf[idx + 1])?;

        idx += 2;
        let sig_len = u16::from_be_bytes([buf[idx], buf[idx + 1]]) as usize;
        let signature = buf[idx + 2..idx + 2 + sig_len].to_vec();

        return Ok(Self {
            p,
            g,
            server_pubkey,
            hash_algo,
            sig_algo,
            signature,
        });
    }
}

#[derive(Debug)]
pub struct ClientKeyExchange {
    enc_pre_master_secret: Vec<u8>,
}

impl ClientKeyExchange {
    pub fn new(enc_pre_master_secret: &[u8]) -> Self {
        Self {
            enc_pre_master_secret: enc_pre_master_secret.to_vec(),
        }
    }
}

pub trait IntoBytes {
    fn into_bytes(self) -> Vec<u8>;
}

pub trait ToBytes {
    fn to_bytes(&self) -> Vec<u8>;
}

impl ToBytes for ClientKeyExchange {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::<u8>::new();
        bytes.extend((self.enc_pre_master_secret.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.enc_pre_master_secret);
        handshake_bytes(TlsHandshakeType::ClientKeyExchange, &bytes)
    }
}

impl IntoBytes for ClientKeyExchange {
    fn into_bytes(self) -> Vec<u8> {
        self.to_bytes()
    }
}

impl From<ClientKeyExchange> for TLSPlaintext {
    fn from(value: ClientKeyExchange) -> Self {
        TLSPlaintext::new(TLSContentType::Handshake, value.to_bytes())
    }
}

impl From<ClientKeyExchange> for TlsMessage {
    fn from(value: ClientKeyExchange) -> Self {
        TlsMessage::Handshake(TlsHandshake::ClientKeyExchange(value))
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

impl From<Finished> for TlsMessage {
    fn from(value: Finished) -> Self {
        TlsMessage::Handshake(TlsHandshake::Finished(value))
    }
}

impl ToBytes for Finished {
    fn to_bytes(&self) -> Vec<u8> {
        handshake_bytes(TlsHandshakeType::Finished, &self.verify_data)
    }
}

impl IntoBytes for Finished {
    fn into_bytes(self) -> Vec<u8> {
        self.to_bytes()
    }
}

impl From<Finished> for TLSPlaintext {
    fn from(value: Finished) -> Self {
        TLSPlaintext::new(TLSContentType::Handshake, value.into_bytes())
    }
}

pub struct ChangeCipherSpec;

impl ChangeCipherSpec {
    pub fn new() -> Self {
        Self {}
    }
}

impl ToBytes for ChangeCipherSpec {
    fn to_bytes(&self) -> Vec<u8> {
        vec![1]
    }
}

impl IntoBytes for ChangeCipherSpec {
    fn into_bytes(self) -> Vec<u8> {
        self.to_bytes()
    }
}

impl From<ChangeCipherSpec> for TLSPlaintext {
    fn from(value: ChangeCipherSpec) -> Self {
        TLSPlaintext::new(TLSContentType::ChangeCipherSpec, value.into_bytes())
    }
}

impl From<ChangeCipherSpec> for TlsMessage {
    fn from(_: ChangeCipherSpec) -> Self {
        TlsMessage::ChangeCipherSpec
    }
}

pub struct ApplicationData(Vec<u8>);

impl ApplicationData {
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }
}

impl From<ApplicationData> for TLSPlaintext {
    fn from(value: ApplicationData) -> Self {
        TLSPlaintext::new(TLSContentType::ApplicationData, value.0)
    }
}

type SessionTicket = LengthPrefixedVec<u16, u8, MaybeEmpty>;

#[derive(Hash, Eq, PartialEq, Debug, Clone)]
pub struct NewSessionTicket {
    lifetime_hint: u32,
    pub ticket: SessionTicket,
}

impl TlsCodable for NewSessionTicket {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        self.lifetime_hint.write_to(bytes);
        self.ticket.write_to(bytes);
    }
    fn read_from(reader: &mut Reader) -> Result<Self, CodingError> {
        let lifetime_hint = u32::read_from(reader)?;
        let ticket = SessionTicket::read_from(reader)?;
        Ok(Self {
            lifetime_hint,
            ticket,
        })
    }
}

impl TryFrom<&[u8]> for NewSessionTicket {
    type Error = Box<dyn std::error::Error>;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        let mut reader = Reader::new(buf);
        let lifetime_hint = u32::read_from(&mut reader)?;
        let ticket = SessionTicket::read_from(&mut reader)?;
        Ok(Self {
            lifetime_hint,
            ticket,
        })
    }
}

impl ToBytes for NewSessionTicket {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::<u8>::new();
        self.lifetime_hint.write_to(&mut bytes);
        self.ticket.write_to(&mut bytes);
        handshake_bytes(TlsHandshakeType::NewSessionTicket, &bytes)
    }
}

#[derive(Debug, TryFromPrimitive, Copy, Clone)]
#[repr(u8)]
pub enum TLSContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

tls_codable_enum! {
    #[repr(u8)]
    pub enum TlsHandshakeType {
        ClientHello = 1,
        ServerHello = 2,
        NewSessionTicket = 4,
        Certificates = 11,
        ServerKeyExchange = 12,
        ServerHelloDone = 14,
        ClientKeyExchange = 16,
        Finished = 20,
        VerifyCertificate = 15
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum TlsHandshake {
    ClientHello(ClientHello),
    ServerHello(ServerHello),
    NewSessionTicket(NewSessionTicket),
    Certificates(Certificate),
    ServerKeyExchange(ServerKeyExchange),
    ServerHelloDone,
    ClientKeyExchange(ClientKeyExchange),
    Finished(Finished),
}

impl TlsHandshake {
    fn handshake_type(&self) -> TlsHandshakeType {
        match self {
            Self::ClientHello(_) => TlsHandshakeType::ClientHello,
            Self::ServerHello(_) => TlsHandshakeType::ServerHello,
            Self::NewSessionTicket(_) => TlsHandshakeType::NewSessionTicket,
            Self::Certificates(_) => TlsHandshakeType::Certificates,
            Self::ServerKeyExchange(_) => TlsHandshakeType::ServerKeyExchange,
            Self::ServerHelloDone => TlsHandshakeType::ServerHelloDone,
            Self::ClientKeyExchange(_) => TlsHandshakeType::ClientKeyExchange,
            Self::Finished(_) => TlsHandshakeType::Finished,
        }
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
            Self::Certificates(h) => h.write_to(&mut writer),
            Self::ServerKeyExchange(_) => unimplemented!(),
            Self::ServerHelloDone => unimplemented!(),
            Self::ClientKeyExchange(_) => unimplemented!(),
            Self::Finished(_) => unimplemented!(),
        }

        writer.finalize_length_prefix();
    }

    fn read_from(reader: &mut Reader) -> Result<Self, CodingError> {
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
                Certificate::read_from(&mut subreader).map(TlsHandshake::Certificates)
            }
            TlsHandshakeType::ServerKeyExchange => unimplemented!(),
            TlsHandshakeType::ServerHelloDone => unimplemented!(),
            TlsHandshakeType::ClientKeyExchange => unimplemented!(),
            TlsHandshakeType::Finished => unimplemented!(),
            _ => unimplemented!(),
        }
    }
}

#[derive(Debug)]
pub enum TlsMessage {
    Handshake(TlsHandshake),
    Alert(TLSAlert),
    ChangeCipherSpec,
    ApplicationData(Vec<u8>),
}

#[derive(Clone)]
pub struct TLSPlaintext {
    pub content_type: TLSContentType,
    pub version: ProtocolVersion,
    pub fragment: Vec<u8>,
}

impl TLSPlaintext {
    pub fn new(content_type: TLSContentType, fragment: Vec<u8>) -> Self {
        Self {
            content_type,
            version: ProtocolVersion { major: 3, minor: 3 },
            fragment,
        }
    }
}

pub struct TLSCiphertext {
    pub content_type: TLSContentType,
    pub version: ProtocolVersion,
    pub fragment: Vec<u8>,
}

impl TLSCiphertext {
    pub fn new(content_type: TLSContentType, fragment: Vec<u8>) -> Self {
        Self {
            content_type,
            version: ProtocolVersion { major: 3, minor: 3 },
            fragment,
        }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::<u8>::new();
        bytes.push(self.content_type as u8);
        bytes.extend_from_slice(&[self.version.major, self.version.minor]);
        bytes.extend_from_slice(&(self.fragment.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.fragment);
        bytes
    }
}

pub fn try_parse_handshake(buf: &[u8]) -> TLSResult<(TlsHandshake, usize)> {
    if buf.len() < 4 {
        return Err(TLSError::NeedData.into());
    }

    let length = u32::from_be_bytes([0, buf[1], buf[2], buf[3]]) as usize;

    if buf.len() < 4 + length {
        return Err(TLSError::NeedData.into());
    }

    let handshake = TlsHandshakeType::try_from(buf[0])
        .map_err(|e| e.into())
        .and_then(|handshake_type| match handshake_type {
            TlsHandshakeType::ServerHello => {
                ServerHello::try_from(&buf[4..]).map(TlsHandshake::ServerHello)
            }
            TlsHandshakeType::NewSessionTicket => {
                NewSessionTicket::try_from(&buf[4..]).map(TlsHandshake::NewSessionTicket)
            }
            TlsHandshakeType::Certificates => {
                Certificate::try_from(&buf[4..]).map(TlsHandshake::Certificates)
            }
            TlsHandshakeType::ServerHelloDone => Ok(TlsHandshake::ServerHelloDone),
            TlsHandshakeType::Finished => {
                let verify_data = buf[4..4 + length].to_vec();
                Ok(TlsHandshake::Finished(Finished { verify_data }))
            }
            TlsHandshakeType::ServerKeyExchange => {
                ServerKeyExchange::try_from(&buf[4..]).map(TlsHandshake::ServerKeyExchange)
            }
            _ => unimplemented!(),
        })?;

    Ok((handshake, length + 4))
}

pub fn handshake_bytes(handshake_type: TlsHandshakeType, content: &[u8]) -> Vec<u8> {
    let mut handshake = Vec::<u8>::new();
    handshake.push(u8::from(handshake_type));
    handshake.extend(utils::u24_be_bytes(content.len()));
    handshake.extend(content);
    handshake
}
