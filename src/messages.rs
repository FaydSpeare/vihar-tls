use crate::alert::TLSAlert;
use crate::ciphersuite::CipherSuiteId;
use crate::encoding::{
    CodingError, LengthPrefixWriter, LengthPrefixedVec, MaybeEmpty, NonEmpty, Reader, TlsCodable,
    VecLen, u24,
};
use crate::extensions::{
    Extension, Extensions, HashAlgo, SecureRenegotationExt, SigAlgo, SignatureAlgorithmsExt,
};
use crate::utils;

#[derive(Debug, Clone, Copy)]
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
            return Err(CodingError::LengthTooLarge(Self::MAX_LEN, session_id.len()));
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
            return Err(CodingError::LengthTooLarge(Self::MAX_LEN, session_id.len()));
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

impl From<ClientHello> for TlsHandshake {
    fn from(value: ClientHello) -> Self {
        Self::ClientHello(value)
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

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ServerHello {
    pub server_version: ProtocolVersion,
    pub random: Random,
    pub session_id: SessionId,
    pub cipher_suite: CipherSuiteId,
    pub compression_method: CompressionMethodId,
    pub extensions: Extensions,
}

impl ServerHello {
    pub fn new(cipher_suite: CipherSuiteId) -> Self {
        Self {
            server_version: ProtocolVersion { major: 3, minor: 3 },
            random: Random {
                unix_time: utils::get_unix_time(),
                random_bytes: utils::get_random_bytes(28).try_into().unwrap(),
            },
            session_id: SessionId(vec![].try_into().unwrap()),
            cipher_suite,
            compression_method: CompressionMethodId::Null,
            extensions: Extensions::new(vec![SecureRenegotationExt::Initial.into()]).unwrap(),
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
        // println!("Server Extensions: {:#?}", extensions);
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
}

impl From<Certificate> for TlsHandshake {
    fn from(value: Certificate) -> Self {
        Self::Certificates(value)
    }
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

type DHParam = LengthPrefixedVec<u16, u8, NonEmpty>;
type Signature = LengthPrefixedVec<u16, u8, MaybeEmpty>;

#[derive(Debug, Clone)]
pub struct ServerKeyExchange {
    pub p: DHParam,
    pub g: DHParam,
    pub server_pubkey: DHParam,
    pub hash_algo: HashAlgo,
    pub sig_algo: SigAlgo,
    pub signature: Signature,
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

impl From<ServerKeyExchange> for TlsHandshake {
    fn from(value: ServerKeyExchange) -> Self {
        Self::ServerKeyExchange(value)
    }
}

impl TlsCodable for ServerKeyExchange {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        self.p.write_to(bytes);
        self.g.write_to(bytes);
        self.server_pubkey.write_to(bytes);
        self.hash_algo.write_to(bytes);
        self.sig_algo.write_to(bytes);
        self.signature.write_to(bytes);
    }
    fn read_from(reader: &mut Reader) -> Result<Self, CodingError> {
        let p = DHParam::read_from(reader)?;
        let g = DHParam::read_from(reader)?;
        let server_pubkey = DHParam::read_from(reader)?;
        let hash_algo = HashAlgo::read_from(reader)?;
        let sig_algo = SigAlgo::read_from(reader)?;
        let signature = Signature::read_from(reader)?;
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

// TODO: split into enum
#[derive(Debug, Clone)]
pub struct ClientKeyExchange {
    pub enc_pre_master_secret: Vec<u8>,
}

impl ClientKeyExchange {
    pub fn new(enc_pre_master_secret: &[u8]) -> Self {
        Self {
            enc_pre_master_secret: enc_pre_master_secret.to_vec(),
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
        bytes.extend((self.enc_pre_master_secret.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.enc_pre_master_secret);
    }
    fn read_from(reader: &mut Reader) -> Result<Self, CodingError> {
        let len = u16::read_from(reader)?;
        let secret = reader.consume(len.into())?;
        Ok(Self {
            enc_pre_master_secret: secret.to_vec(),
        })
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
    fn read_from(reader: &mut Reader) -> Result<Self, CodingError> {
        let verify_data = reader.consume_rest()?.to_vec();
        Ok(Self { verify_data })
    }
}

impl From<Finished> for TlsHandshake {
    fn from(value: Finished) -> Self {
        Self::Finished(value)
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

impl From<NewSessionTicket> for TlsHandshake {
    fn from(value: NewSessionTicket) -> Self {
        Self::NewSessionTicket(value)
    }
}

tls_codable_enum! {
    #[repr(u8)]
    pub enum TLSContentType {
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
        ServerHelloDone = 14,
        ClientKeyExchange = 16,
        Finished = 20,
        VerifyCertificate = 15
    }
}

#[derive(Debug, Clone)]
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
            Self::ServerKeyExchange(h) => h.write_to(&mut writer),
            Self::ServerHelloDone => {}
            Self::ClientKeyExchange(h) => h.write_to(&mut writer),
            Self::Finished(h) => h.write_to(&mut writer),
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
            _ => unimplemented!(),
        }
    }
}

impl TryFrom<TlsHandshake> for TlsPlaintext {
    type Error = CodingError;

    fn try_from(value: TlsHandshake) -> Result<Self, Self::Error> {
        TlsPlaintext::new(TLSContentType::Handshake, value.get_encoding())
    }
}

#[derive(Debug)]
pub enum TlsMessage {
    Handshake(TlsHandshake),
    Alert(TLSAlert),
    ChangeCipherSpec,
    ApplicationData(Vec<u8>),
}

impl TlsMessage {
    pub fn new_appdata(bytes: Vec<u8>) -> Self {
        Self::ApplicationData(bytes)
    }
}

// TODO restore 16384
u16_vec_len_with_max!(PlaintextFragmentLen, 17_384);
u16_vec_len_with_max!(CompressedFragmentLen, 17_384 + 1024);
u16_vec_len_with_max!(CiphertextFragmentLen, 17_384 + 2048);

type PlaintextFragment = LengthPrefixedVec<PlaintextFragmentLen, u8, MaybeEmpty>;

#[derive(Debug, Clone)]
pub struct TlsPlaintext {
    pub content_type: TLSContentType,
    pub version: ProtocolVersion,
    pub fragment: PlaintextFragment,
}

impl TlsPlaintext {
    pub fn new(content_type: TLSContentType, fragment: Vec<u8>) -> Result<Self, CodingError> {
        Ok(Self {
            content_type,
            version: ProtocolVersion { major: 3, minor: 3 },
            fragment: fragment.try_into()?,
        })
    }
}

impl TryFrom<TlsMessage> for TlsPlaintext {
    type Error = CodingError;

    fn try_from(value: TlsMessage) -> Result<Self, Self::Error> {
        match value {
            TlsMessage::ChangeCipherSpec => {
                TlsPlaintext::new(TLSContentType::ChangeCipherSpec, vec![1])
            }
            TlsMessage::Alert(alert) => TlsPlaintext::try_from(alert),
            TlsMessage::Handshake(msg) => TlsPlaintext::try_from(msg),
            TlsMessage::ApplicationData(data) => {
                TlsPlaintext::new(TLSContentType::ApplicationData, data)
            }
        }
    }
}
type CompressedFragment = LengthPrefixedVec<CompressedFragmentLen, u8, MaybeEmpty>;

#[derive(Debug, Clone)]
pub struct TlsCompressed {
    pub content_type: TLSContentType,
    pub version: ProtocolVersion,
    pub fragment: CompressedFragment,
}

type CiphertextFragment = LengthPrefixedVec<CiphertextFragmentLen, u8, MaybeEmpty>;

pub struct TLSCiphertext {
    pub content_type: TLSContentType,
    pub version: ProtocolVersion,
    pub fragment: CiphertextFragment,
}

impl TlsCodable for TLSCiphertext {
    fn read_from(reader: &mut Reader) -> Result<Self, CodingError> {
        let content_type = TLSContentType::read_from(reader)?;
        let version = ProtocolVersion::read_from(reader)?;
        let fragment = CiphertextFragment::read_from(reader)?;
        Ok(TLSCiphertext {
            content_type,
            version,
            fragment,
        })
    }

    fn write_to(&self, bytes: &mut Vec<u8>) {
        self.content_type.write_to(bytes);
        self.version.write_to(bytes);
        self.fragment.write_to(bytes);
    }
}
