use crate::alert::TLSAlert;
use crate::utils;
use crate::{TLSError, TLSResult};
use num_enum::TryFromPrimitive;

#[allow(non_camel_case_types)]
#[derive(Clone, Debug, TryFromPrimitive)]
#[repr(u16)]
pub enum CipherSuiteId {
    TLS_RSA_WITH_AES_128_CBC_SHA = 0x002f,
    TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x003c,
    TLS_RSA_WITH_AES_256_CBC_SHA256 = 0x003d,
}

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

#[derive(Debug, Clone)]
pub struct ClientHello {
    pub client_version: ProtocolVersion,
    pub random: Random,
    #[allow(dead_code)]
    pub session_id: Vec<u8>,
    pub cipher_suites: Vec<[u8; 2]>,
    #[allow(dead_code)]
    pub compression_methods: Vec<u8>,
}


impl From<ClientHello> for Vec<u8> {

    fn from(value: ClientHello) -> Vec<u8> {
        let mut bytes = Vec::<u8>::new();
        bytes.extend([value.client_version.major, value.client_version.minor]); // ProtocolVersion
        bytes.extend_from_slice(&value.random.as_bytes());
        bytes.push(0); // SessionId
        bytes.extend((2 * value.cipher_suites.len() as u16).to_be_bytes());
        for suite in &value.cipher_suites {
            bytes.extend(suite);
        }

        bytes.push(1); // Compression methods
        bytes.push(0);

        let signature_algorithms_ext = [
            0x00, 0x0d, // Extension type: signature_algorithms (13)
            0x00, 0x06, // Extension length: 6 bytes
            0x00, 0x04, // Supported algorithms list length: 4 bytes
            0x04, 0x01, // sha256 + rsa
            0x02, 0x01, // sha1 + rsa (optional)
        ];

        // let sni_ext = [
        //     0x00, 0x00,              // Extension type: server_name (0)
        //     0x00, 0x0f,              // Extension length: 16 bytes
        //     0x00, 0x0d,              // Server Name list length: 14 bytes
        //     0x00,                 // Name Type: host_name (0)
        //     0x00, 0x0a,              // Hostname length: 11 bytes
        //     0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d
        // ];
        let extensions_len = ((signature_algorithms_ext.len()) as u16).to_be_bytes();
        bytes.extend_from_slice(&extensions_len);
        bytes.extend_from_slice(&signature_algorithms_ext);
        //bytes.extend_from_slice(&sni_ext);

        let handshake = handshake_bytes(TLSHandshakeType::ClientHello, &bytes);
        record_bytes(TLSContentType::Handshake, &handshake) 
    }

}

impl ClientHello {
    pub fn new() -> Self {
        ClientHello {
            client_version: ProtocolVersion { major: 3, minor: 3 },
            random: Random {
                unix_time: utils::get_unix_time(),
                random_bytes: utils::get_random_bytes(28).try_into().unwrap(),
            },
            session_id: vec![],
            cipher_suites: vec![(CipherSuiteId::TLS_RSA_WITH_AES_128_CBC_SHA as u16).to_be_bytes()],
            compression_methods: vec![0],
        }
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct ServerHello {
    pub server_version: ProtocolVersion,
    pub random: Random,
    pub session_id: Vec<u8>,
    pub cipher_suite: CipherSuiteId,
    pub compression_method: u8,
}


impl TryFrom<&[u8]> for ServerHello {
    type Error = Box<dyn std::error::Error>;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        let major = buf[0];
        let minor = buf[1];

        let unix_time = u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]);
        //println!("Unix: {unix_time}");

        let random_bytes: [u8; 28] = buf[6..34].try_into().unwrap();
        // println!("Random: {:?}", random_bytes);

        let session_len = buf[34] as usize;
        let session_id = buf[35..35 + session_len].to_vec();
        // println!("Session: {:?}", session_id);

        let idx = 35 + session_len;
        let cipher_suite =
            CipherSuiteId::try_from(u16::from_be_bytes([buf[idx], buf[idx + 1]])).unwrap();
        // println!("ciphersuite: 0x{:02X}{:02X}", buf[idx], buf[idx + 1]);

        let compression_method = buf[idx + 2];
        // println!("compression: 0x{:02X}", slice[pos + 2]);

        Ok(Self {
            server_version: ProtocolVersion { major, minor },
            random: Random {
                unix_time,
                random_bytes,
            },
            session_id,
            cipher_suite,
            compression_method,
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
            let cert_len = u32::from_be_bytes([0, slice[idx], slice[idx + 1], slice[idx + 2]]) as usize;
            certs.push(Certificate {
                bytes: slice[idx + 3..idx + 3 + cert_len].to_vec(),
            });
            idx += 3 + cert_len;
        }

        return Ok(Self { list: certs }); 
    }

}

#[allow(dead_code)]
#[derive(Debug)]
pub struct Finished {
    verify_data: Vec<u8>,
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
    ServerHello(ServerHello),
    Certificates(Certificates),
    ServerHelloDone,
    Finished(Finished),
}

#[derive(Debug)]
pub enum TLSRecord {
    Handshake(TLSHandshake),
    Alert(TLSAlert),
    ChangeCipherSuite,
    ApplicationData(Vec<u8>),
}

pub struct TLSCiphertext {
    pub content_type: TLSContentType,
    pub version: ProtocolVersion,
    pub fragment: Vec<u8>
}

impl TLSCiphertext {
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::<u8>::new();
        bytes.push(self.content_type as u8);
        bytes.push(self.version.major);
        bytes.push(self.version.minor);
        bytes.extend_from_slice(&(self.fragment.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.fragment);
        bytes
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
