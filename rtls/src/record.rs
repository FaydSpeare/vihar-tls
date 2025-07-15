use crate::alert::TLSAlert;
use crate::ciphersuite::{get_cipher_suite, CipherSuite};
use crate::extensions::{
    decode_extensions, EncodeExtension, Extension, HashAlgo, SecureRenegotationExt, SigAlgo, SignatureAlgorithmsExt
};
use crate::utils;
use crate::{TLSError, TLSResult};
use num_enum::TryFromPrimitive;

#[derive(Debug, Clone)]
pub struct ProtocolVersion {
    pub major: u8,
    pub minor: u8,
}

#[derive(Debug, Clone)]
pub struct Random {
    unix_time: u32,
    random_bytes: [u8; 28],
}

impl Random {
    pub fn as_bytes(&self) -> [u8; 32] {
        let mut bytes = [0; 32];
        bytes[..4].copy_from_slice(&self.unix_time.to_be_bytes());
        bytes[4..].copy_from_slice(&self.random_bytes);
        bytes
    }
}

#[derive(Debug)]
pub struct ClientHello {
    pub client_version: ProtocolVersion,
    pub random: Random,
    #[allow(dead_code)]
    pub session_id: Vec<u8>,
    pub cipher_suites: Vec<[u8; 2]>,
    #[allow(dead_code)]
    pub compression_methods: Vec<u8>,
    #[allow(dead_code)]
    pub extensions: Vec<Extension>
}

impl ClientHello {
    pub fn new(suites: &[Box<dyn CipherSuite>], mut extensions: Vec<Extension>) -> Self {
        let cipher_suites = suites.iter().map(|x| x.encode()).collect();
        extensions.push(
            SignatureAlgorithmsExt::new_from_product(
                vec![SigAlgo::Rsa],
                vec![HashAlgo::Sha, HashAlgo::Sha256],
            ).into()
        );
        ClientHello {
            client_version: ProtocolVersion { major: 3, minor: 3 },
            random: Random {
                unix_time: utils::get_unix_time(),
                random_bytes: utils::get_random_bytes(28).try_into().unwrap(),
            },
            session_id: vec![],
            cipher_suites,
            compression_methods: vec![0],
            extensions,
        }
    }
}

impl ToBytes for ClientHello {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::<u8>::new();
        bytes.extend([self.client_version.major, self.client_version.minor]); // ProtocolVersion
        bytes.extend_from_slice(&self.random.as_bytes());

        bytes.push(self.session_id.len() as u8); // SessionId
        bytes.extend_from_slice(&self.session_id); // SessionId bytes

        bytes.extend(((2 * self.cipher_suites.len()) as u16).to_be_bytes());
        for suite in &self.cipher_suites {
            bytes.extend(suite);
        }

        bytes.push(1); // Compression methods
        bytes.push(0);
        
        let extensions_bytes: Vec<u8> = self.extensions.iter().map(|x| x.encode()).flatten().collect();
        let extensions_len = extensions_bytes.len() as u16;

        bytes.extend_from_slice(&extensions_len.to_be_bytes());
        bytes.extend_from_slice(&extensions_bytes);

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

#[allow(dead_code)]
#[derive(Debug)]
pub struct ServerHello {
    pub server_version: ProtocolVersion,
    pub random: Random,
    pub session_id: Vec<u8>,
    pub cipher_suite: Box<dyn CipherSuite>,
    pub compression_method: u8,
    pub extensions: Vec<Extension>
}

impl ServerHello {

    pub fn supports_secure_renegotiation(&self) -> bool {
        self.extensions.iter().any(|x| matches!(x, Extension::SecureRenegotiation(_)))
    }

}

impl TryFrom<&[u8]> for ServerHello {
    type Error = Box<dyn std::error::Error>;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        let major = buf[0];
        let minor = buf[1];

        let unix_time = u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]);
        //CipherSuiteId::try_from(u16::from_be_bytes([buf[idx], buf[idx + 1]])).unwrap();
        // println!("Unix: {unix_time}");

        let random_bytes: [u8; 28] = buf[6..34].try_into().unwrap();
        // println!("Random: {:?}", random_bytes);

        let session_len = buf[34] as usize;
        let session_id = buf[35..35 + session_len].to_vec();
        // println!("Session: {:?}", session_id);

        let idx = 35 + session_len;
        let cipher_suite_id = u16::from_be_bytes([buf[idx], buf[idx + 1]]);
        let cipher_suite = get_cipher_suite(cipher_suite_id)?;
        // println!("cipher_suite: 0x{:02X}{:02X}", buf[idx], buf[idx + 1]);

        let compression_method = buf[idx + 2];
        // println!("compression: 0x{:02X}", slice[pos + 2]);
        
        let extensions = if buf.len() > idx + 3 {
            decode_extensions(&buf[idx + 5..])?
        } else {
            vec![]
        };

        Ok(Self {
            server_version: ProtocolVersion { major, minor },
            random: Random {
                unix_time,
                random_bytes,
            },
            session_id,
            cipher_suite,
            compression_method,
            extensions
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

impl IntoBytes for ChangeCipherSpec {
    fn into_bytes(self) -> Vec<u8> {
        vec![1]
    }
}

impl From<ChangeCipherSpec> for TLSPlaintext {
    fn from(value: ChangeCipherSpec) -> Self {
        TLSPlaintext::new(TLSContentType::ChangeCipherSpec, value.into_bytes())
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
    Certificates = 11,
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
    Certificates(Certificates),
    ServerHelloDone,
    Finished(Finished),
}

impl TLSHandshake {
    pub fn into_bytes(self) -> Vec<u8> {
        match self {
            TLSHandshake::ClientHello(hello) => hello.into_bytes(),
            _ => unimplemented!(),
        }
    }
}

#[derive(Debug)]
pub enum TLSRecord {
    Handshake(TLSHandshake),
    Alert(TLSAlert),
    ChangeCipherSuite,
    ApplicationData(Vec<u8>),
}

#[derive(Clone)]
pub struct TLSPlaintext {
    pub content_type: TLSContentType,
    pub version: ProtocolVersion,
    pub fragment: Vec<u8>,
}

impl TLSPlaintext {
    fn new(content_type: TLSContentType, fragment: Vec<u8>) -> Self {
        Self {
            content_type,
            version: ProtocolVersion { major: 3, minor: 1 },
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

impl TLSRecord {
    pub fn into_bytes(self) -> Vec<u8> {
        match self {
            TLSRecord::Handshake(handshake) => {
                record_bytes(TLSContentType::Handshake, &handshake.into_bytes())
            }
            TLSRecord::Alert(alert) => unimplemented!(),
            TLSRecord::ChangeCipherSuite => unimplemented!(),
            TLSRecord::ApplicationData(data) => unimplemented!(),
        }
    }

    pub fn fragment_bytes(self) -> Vec<u8> {
        match self {
            TLSRecord::Handshake(handshake) => handshake.into_bytes(),
            TLSRecord::Alert(alert) => unimplemented!(),
            TLSRecord::ChangeCipherSuite => unimplemented!(),
            TLSRecord::ApplicationData(data) => unimplemented!(),
        }
    }
}

pub fn parse_handshake(buf: &[u8]) -> TLSResult<TLSHandshake> {
    if buf.len() < 4 {
        return Err(TLSError::NeedData.into());
    }

    let length = u32::from_be_bytes([0, buf[1], buf[2], buf[3]]) as usize;

    if buf.len() < 4 + length {
        return Err(TLSError::NeedData.into());
    }

    // println!("Handshake length: {length}");
    TLSHandshakeType::try_from(buf[0])
        .map_err(|e| e.into())
        .and_then(|handshake_type| match handshake_type {
            TLSHandshakeType::ServerHello => {
                ServerHello::try_from(&buf[4..]).map(TLSHandshake::ServerHello)
            }
            TLSHandshakeType::Certificates => {
                Certificates::try_from(&buf[4..]).map(TLSHandshake::Certificates)
            }
            TLSHandshakeType::ServerHelloDone => Ok(TLSHandshake::ServerHelloDone),
            TLSHandshakeType::Finished => {
                let verify_data = buf[4..4 + length].to_vec();
                Ok(TLSHandshake::Finished(Finished { verify_data }))
            }
            _ => unimplemented!(),
        })
}

pub fn handshake_bytes(handshake_type: TLSHandshakeType, content: &[u8]) -> Vec<u8> {
    let mut handshake = Vec::<u8>::new();
    handshake.push(handshake_type as u8);
    handshake.extend(utils::u24_be_bytes(content.len()));
    handshake.extend(content);
    handshake
}

pub fn change_cipher_spec_bytes() -> Vec<u8> {
    record_bytes(TLSContentType::ChangeCipherSpec, &[1])
}

pub fn record_bytes(content_type: TLSContentType, content: &[u8]) -> Vec<u8> {
    let mut record = Vec::<u8>::new();
    record.push(content_type as u8);
    record.extend([3, 3]);
    record.extend((content.len() as u16).to_be_bytes());
    record.extend(content);
    record
}

pub fn client_key_exchange_bytes(enc_pre_master_secret: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::<u8>::new();
    bytes.extend((enc_pre_master_secret.len() as u16).to_be_bytes());
    bytes.extend_from_slice(enc_pre_master_secret);
    let handshake = handshake_bytes(TLSHandshakeType::ClientKeyExchange, &bytes);
    let record = record_bytes(TLSContentType::Handshake, &handshake);
    record
}
