use crate::alert::TLSAlert;
use crate::ciphersuite::CipherSuiteId;
use crate::encoding::{CodingError, LengthPrefixedVec, MaybeEmpty, NonEmpty, Reader, TlsCodable};
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

#[derive(Debug, Clone)]
pub struct ClientHello {
    pub client_version: ProtocolVersion,
    pub random: Random,
    pub session_id: SessionId,
    pub cipher_suites: LengthPrefixedVec<u16, CipherSuiteId, NonEmpty>,
    pub compression_methods: LengthPrefixedVec<u8, CompressionMethodId, NonEmpty>,
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

    pub fn includes_session_ticket(&self) -> bool {
        false
        // self.extensions
        //     .iter()
        //     .any(|ext| matches!(ext, Extension::SessionTicket(ext) if ext.ticket.is_some()))
    }

    pub fn session_ticket(&self) -> Option<Vec<u8>> {
        None
        // self.extensions.iter().find_map(|ext| {
        //     if let Extension::SessionTicket(ticket_ext) = ext {
        //         ticket_ext.ticket.clone()
        //     } else {
        //         None
        //     }
        // })
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
        handshake_bytes(TLSHandshakeType::ClientHello, &bytes)
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
        TlsMessage::Handshake(TLSHandshake::ClientHello(value))
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
        false
        //self.extensions
        //    .iter()
        //    .any(|x| matches!(x, Extension::SessionTicket(_)))
    }
    pub fn supports_extended_master_secret(&self) -> bool {
        false
        //self.extensions
        //    .iter()
        //    .any(|x| matches!(x, Extension::ExtendedMasterSecret(_)))
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
        handshake_bytes(TLSHandshakeType::ServerHello, &bytes)
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

#[derive(Debug)]
pub struct Certificate {
    pub bytes: Vec<u8>,
}

#[derive(Debug)]
pub struct Certificates {
    pub list: Vec<Certificate>,
}

impl ToBytes for Certificates {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::<u8>::new();

        let cert_bytes = self.list.iter().map(|x| 3 + x.bytes.len()).sum();
        bytes.extend_from_slice(&utils::u24_be_bytes(cert_bytes));

        for cert in &self.list {
            bytes.extend_from_slice(&utils::u24_be_bytes(cert.bytes.len()));
            bytes.extend_from_slice(&cert.bytes);
        }
        handshake_bytes(TLSHandshakeType::Certificates, &bytes)
    }
}

impl TryFrom<&[u8]> for Certificates {
    type Error = Box<dyn std::error::Error>;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        let cert_bytes = u32::from_be_bytes([0, buf[0], buf[1], buf[2]]) as usize;

        let slice = &buf[3..];
        if cert_bytes > slice.len() {
            return Err(TLSError::NeedData.into());
        }

        let mut idx = 0;
        let mut certs: Vec<Certificate> = vec![];

        while idx < cert_bytes {
            let cert_len =
                u32::from_be_bytes([0, slice[idx], slice[idx + 1], slice[idx + 2]]) as usize;
            certs.push(Certificate {
                bytes: slice[idx + 3..idx + 3 + cert_len].to_vec(),
            });
            idx += 3 + cert_len;
        }

        return Ok(Self { list: certs });
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
        handshake_bytes(TLSHandshakeType::ServerKeyExchange, &bytes)
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
        handshake_bytes(TLSHandshakeType::ClientKeyExchange, &bytes)
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
        TlsMessage::Handshake(TLSHandshake::ClientKeyExchange(value))
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
        TlsMessage::Handshake(TLSHandshake::Finished(value))
    }
}

impl ToBytes for Finished {
    fn to_bytes(&self) -> Vec<u8> {
        handshake_bytes(TLSHandshakeType::Finished, &self.verify_data)
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

#[derive(Hash, Eq, PartialEq, Debug, Clone)]
pub struct NewSessionTicket {
    lifetime_hint: u32,
    pub ticket: Vec<u8>,
}

impl TryFrom<&[u8]> for NewSessionTicket {
    type Error = Box<dyn std::error::Error>;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        let lifetime_hint = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);

        let ticket_len = u16::from_be_bytes([buf[4], buf[5]]) as usize;
        let ticket = buf[6..6 + ticket_len].to_vec();

        Ok(Self {
            lifetime_hint,
            ticket,
        })
    }
}

impl ToBytes for NewSessionTicket {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::<u8>::new();
        bytes.extend_from_slice(&self.lifetime_hint.to_be_bytes());
        bytes.extend_from_slice(&(self.ticket.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.ticket);
        handshake_bytes(TLSHandshakeType::NewSessionTicket, &bytes)
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

#[derive(Debug, TryFromPrimitive)]
#[repr(u8)]
pub enum TLSHandshakeType {
    ClientHello = 1,
    ServerHello = 2,
    NewSessionTicket = 4,
    Certificates = 11,
    ServerKeyExchange = 12,
    ServerHelloDone = 14,
    ClientKeyExchange = 16,
    Finished = 20,
    VerifyCertificate = 15,
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum TLSHandshake {
    ClientHello(ClientHello),
    ServerHello(ServerHello),
    NewSessionTicket(NewSessionTicket),
    Certificates(Certificates),
    ServerKeyExchange(ServerKeyExchange),
    ServerHelloDone,
    ClientKeyExchange(ClientKeyExchange),
    Finished(Finished),
}

#[derive(Debug)]
pub enum TlsMessage {
    Handshake(TLSHandshake),
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

pub fn try_parse_handshake(buf: &[u8]) -> TLSResult<(TLSHandshake, usize)> {
    if buf.len() < 4 {
        return Err(TLSError::NeedData.into());
    }

    let length = u32::from_be_bytes([0, buf[1], buf[2], buf[3]]) as usize;

    if buf.len() < 4 + length {
        return Err(TLSError::NeedData.into());
    }

    let handshake = TLSHandshakeType::try_from(buf[0])
        .map_err(|e| e.into())
        .and_then(|handshake_type| match handshake_type {
            TLSHandshakeType::ServerHello => {
                ServerHello::try_from(&buf[4..]).map(TLSHandshake::ServerHello)
            }
            TLSHandshakeType::NewSessionTicket => {
                NewSessionTicket::try_from(&buf[4..]).map(TLSHandshake::NewSessionTicket)
            }
            TLSHandshakeType::Certificates => {
                Certificates::try_from(&buf[4..]).map(TLSHandshake::Certificates)
            }
            TLSHandshakeType::ServerHelloDone => Ok(TLSHandshake::ServerHelloDone),
            TLSHandshakeType::Finished => {
                let verify_data = buf[4..4 + length].to_vec();
                Ok(TLSHandshake::Finished(Finished { verify_data }))
            }
            TLSHandshakeType::ServerKeyExchange => {
                ServerKeyExchange::try_from(&buf[4..]).map(TLSHandshake::ServerKeyExchange)
            }
            _ => unimplemented!(),
        })?;

    Ok((handshake, length + 4))
}

pub fn handshake_bytes(handshake_type: TLSHandshakeType, content: &[u8]) -> Vec<u8> {
    let mut handshake = Vec::<u8>::new();
    handshake.push(handshake_type as u8);
    handshake.extend(utils::u24_be_bytes(content.len()));
    handshake.extend(content);
    handshake
}
