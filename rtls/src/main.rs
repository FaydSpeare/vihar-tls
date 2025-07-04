use rand::Rng;
use rsa::rand_core::{OsRng, RngCore};
use std::convert::TryInto;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use num_enum::TryFromPrimitive;
use rsa::pkcs8::DecodePublicKey;
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};
use thiserror::Error;
use x509_parser::asn1_rs::ToDer;
use x509_parser::parse_x509_certificate;

mod prf;

fn get_unix_time() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() as u32
}

fn get_random_bytes(len: usize) -> Vec<u8> {
    let mut rng = rand::rng();
    (0..len).map(|_| rng.random()).collect()
}

#[derive(Debug)]
struct ProtocolVersion {
    major: u8,
    minor: u8,
}

#[derive(Debug)]
struct Random {
    unix_time: u32,
    random_bytes: [u8; 28],
}

#[allow(non_camel_case_types)]
#[derive(Debug, TryFromPrimitive)]
#[repr(u16)]
enum CipherSuite {
    TLS_RSA_WITH_AES_128_CBC_SHA = 0x002f,
    TLS_RSA_WITH_AES_256_CBC_SHA256 = 0x003d,
}

struct ClientHello {
    client_version: ProtocolVersion,
    random: Random,
    session_id: Vec<u8>,
    cipher_suites: Vec<[u8; 2]>,
    compression_methods: Vec<u8>,
}

#[derive(Debug, TryFromPrimitive)]
#[repr(u8)]
enum TLSContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

#[derive(Debug, TryFromPrimitive)]
#[repr(u8)]
enum TLSHandshakeType {
    ClientHello = 1,
    ServerHello = 2,
    Certificates = 11,
    ServerHelloDone = 14,
    ClientKeyExchange = 16,
}

#[allow(dead_code)]
#[derive(Debug)]
struct ServerHello {
    server_version: ProtocolVersion,
    random: Random,
    session_id: Vec<u8>,
    cipher_suite: CipherSuite,
    compression_method: u8,
}

#[derive(Debug)]
struct Certificate {
    bytes: Vec<u8>,
}

#[allow(dead_code)]
#[derive(Debug)]
struct Certificates {
    list: Vec<Certificate>,
}

#[allow(dead_code)]
#[derive(Debug)]
enum TLSHandshake {
    ServerHello(ServerHello),
    Certificates(Certificates),
    ServerHelloDone,
}

#[derive(Debug)]
enum TLSRecord {
    Handshake(TLSHandshake),
    Alert,
}

type TLSResult<T> = Result<T, Box<dyn std::error::Error>>;

fn parse_certificates(buf: &[u8], pos: usize, _len: usize) -> TLSResult<(Certificates, usize)> {
    let mut slice = &buf[pos..];
    println!("{:?}", &slice[0..20]);

    let cert_bytes = u32::from_be_bytes([0, slice[0], slice[1], slice[2]]) as usize;
    println!("total certs length: {cert_bytes}");
    println!("slice length: {}", slice.len());

    slice = &slice[3..];
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
        println!("{cert_len} {}", certs.last().unwrap().bytes.len());
        idx += 3 + cert_len;
    }

    return Ok((Certificates { list: certs }, pos + 3 + idx));
}

fn parse_server_hello(buf: &[u8], pos: usize, _len: usize) -> TLSResult<(ServerHello, usize)> {
    let slice = &buf[pos..];
    let major = slice[0];
    let minor = slice[1];
    // println!("ServerVersion: {major}.{minor}");

    let unix_time = u32::from_be_bytes([slice[2], slice[3], slice[4], slice[5]]);
    // println!("Unix: {unix_time}");

    let random_bytes: [u8; 28] = slice[6..34].try_into().unwrap();
    // println!("Random: {:?}", random_bytes);

    let session_len = slice[34] as usize;
    let session_id = slice[34..34 + session_len].to_vec();
    // println!("Session: {:?}", session_id);

    let idx = 35 + session_len;
    let cipher_suite =
        CipherSuite::try_from(u16::from_be_bytes([slice[idx], slice[idx + 1]])).unwrap();
    // println!("ciphersuite: 0x{:02X}{:02X}", slice[pos], slice[pos + 1]);

    let compression_method = slice[idx + 2];
    // println!("compression: 0x{:02X}", slice[pos + 2]);

    Ok((
        ServerHello {
            server_version: ProtocolVersion { major, minor },
            random: Random {
                unix_time,
                random_bytes,
            },
            session_id,
            cipher_suite,
            compression_method,
        },
        pos + idx + 3,
    ))
}

fn parse_handshake(buf: &[u8], pos: usize) -> TLSResult<(TLSHandshake, usize)> {
    let slice = &buf[pos..];
    if slice.len() < 4 {
        return Err(TLSError::NeedData.into());
    }

    let length = u32::from_be_bytes([0, slice[1], slice[2], slice[3]]) as usize;
    if slice.len() < 4 + length {
        return Err(TLSError::NeedData.into());
    }

    println!("Handshake length: {length}");
    TLSHandshakeType::try_from(slice[0])
        .map_err(|e| e.into())
        .and_then(|handshake_type| {
            println!("HandshakeType: {:?}", handshake_type);
            match handshake_type {
                TLSHandshakeType::ServerHello => parse_server_hello(buf, pos + 4, length)
                    .map(|(x, y)| (TLSHandshake::ServerHello(x), y)),
                TLSHandshakeType::Certificates => parse_certificates(buf, pos + 4, length)
                    .map(|(x, y)| (TLSHandshake::Certificates(x), y)),
                TLSHandshakeType::ServerHelloDone => Ok((TLSHandshake::ServerHelloDone, pos + 4)),
                _ => unimplemented!(),
            }
        })
}

#[derive(Error, Debug)]
pub enum TLSError {
    #[error("Buffer requires {0} more bytes")]
    NeedsMoreData(u16),

    #[error("Buffer requires more bytes")]
    NeedData,

    #[error("Invalid protocol version: {0}.{1}")]
    InvalidProtocolVersion(u8, u8),
}

fn parse_response(buf: &[u8]) -> TLSResult<(TLSRecord, usize)> {
    if buf.len() < 5 {
        return Err(TLSError::NeedsMoreData((5 - buf.len()) as u16).into());
    }
    let major = buf[1];
    let minor = buf[2];

    if !(major == 3 && minor == 3) {
        return Err(TLSError::InvalidProtocolVersion(major, minor).into());
    }
    println!("ProtocolVersion {major}.{minor}");

    let length_bytes = [buf[3], buf[4]];
    let length = u16::from_be_bytes(length_bytes) as usize;

    if buf.len() < 5 + length {
        return Err(TLSError::NeedsMoreData((5 + length - buf.len()) as u16).into());
    }

    TLSContentType::try_from(buf[0])
        .map_err(|e| e.into())
        .and_then(|content_type| {
            println!("ContentType: {:?}", content_type);
            match content_type {
                TLSContentType::ChangeCipherSpec => unimplemented!(),
                TLSContentType::Alert => {
                    println!("{:?}", &buf[..5 + length]);
                    unimplemented!();
                },
                TLSContentType::Handshake => {
                    parse_handshake(buf, 5).map(|(x, y)| (TLSRecord::Handshake(x), y))
                }
                TLSContentType::ApplicationData => unimplemented!(),
            }
        })
}

#[allow(dead_code)]
fn encrypt_pre_master_secret(cert_der: &[u8]) -> TLSResult<(Vec<u8>, Vec<u8>)> {
    // Step 1: Parse the certificate and extract the public key
    let (_, cert) = parse_x509_certificate(cert_der)?;
    let spki = &cert.tbs_certificate.subject_pki;
    let pub_key_der = spki.raw.as_ref();

    // Step 2: Load RSA public key from DER (PKCS#1 format)
    let rsa_pub = RsaPublicKey::from_public_key_der(pub_key_der)?;

    // Step 3: Generate the 48-byte pre_master_secret
    let mut pre_master = [0u8; 48];
    let mut rng = OsRng;
    pre_master[0] = 0x03;
    pre_master[1] = 0x03; // TLS 1.2
    rng.fill_bytes(&mut pre_master[2..]);

    // Step 4: Encrypt it with RSA using PKCS#1 v1.5 padding (TLS 1.2 requires this)
    let encrypted = rsa_pub.encrypt(&mut rng, Pkcs1v15Encrypt, &pre_master)?;
    Ok((pre_master.to_vec(), encrypted)) // return both raw and encrypted
}

struct TLSConnection {
    stream: TcpStream,
    buffer: Vec<u8>,
    handshakes: Vec<u8>,
}

// if let TLSRecord::Handshake(TLSHandshake::Certificates(x)) = res {
//     for cert in x.list {
//         let (x, y) = encrypt_pre_master_secret(&cert.bytes)?;
//         println!("{:?}", x);
//     }
// }
//
//
//

fn u24_be_bytes(value: usize) -> [u8; 3] {
    [
        ((value >> 16) & 0xFF) as u8,
        ((value >> 8) & 0xFF) as u8,
        (value & 0xFF) as u8,
    ]
}

fn handshake_bytes(handshake_type: TLSHandshakeType, content: &[u8]) -> Vec<u8> {
    let mut handshake = Vec::<u8>::new();
    handshake.push(handshake_type as u8);
    handshake.extend(u24_be_bytes(content.len()));
    handshake.extend(content);
    handshake
}

fn record_bytes(content_type: TLSContentType, content: &[u8]) -> Vec<u8> {
    let mut record = Vec::<u8>::new();
    record.push(content_type as u8);
    record.extend([3, 3]);
    record.extend((content.len() as u16).to_be_bytes());
    record.extend(content);
    record
}

fn change_cipher_spec_bytes() -> Vec<u8> {
    record_bytes(TLSContentType::ChangeCipherSpec, &[1])
}

fn client_hello_bytes() -> Vec<u8> {
    let hello = ClientHello {
        client_version: ProtocolVersion { major: 3, minor: 3 },
        random: Random {
            unix_time: get_unix_time(),
            random_bytes: get_random_bytes(28).try_into().unwrap(),
        },
        session_id: vec![],
        cipher_suites: vec![(CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA as u16).to_be_bytes()],
        compression_methods: vec![0],
    };

    let mut bytes = Vec::<u8>::new();
    bytes.extend([hello.client_version.major, hello.client_version.minor]); // ProtocolVersion
    bytes.extend(hello.random.unix_time.to_be_bytes());
    bytes.extend(hello.random.random_bytes);
    bytes.push(0); // SessionId
    bytes.extend((2 * hello.cipher_suites.len() as u16).to_be_bytes());
    for suite in hello.cipher_suites {
        bytes.extend(suite);
    }
    bytes.push(1); // Compression methods
    bytes.push(0);


    let ext = [
        0x00, 0x0d,       // Extension type: signature_algorithms (13)
        0x00, 0x06,       // Extension length: 6 bytes
        0x00, 0x04,       // Supported algorithms list length: 4 bytes
        0x04, 0x01,       // sha256 + rsa
        0x02, 0x01,       // sha1 + rsa (optional)
    ];

    let extensions_len = (ext.len() as u16).to_be_bytes();
    bytes.extend_from_slice(&extensions_len);
    bytes.extend_from_slice(&ext);

    let handshake = handshake_bytes(TLSHandshakeType::ClientHello, &bytes);
    let record = record_bytes(TLSContentType::Handshake, &handshake);
    record
}

fn client_key_exchange_bytes(pre_master_secret: Vec<u8>) -> Vec<u8> {
    let mut bytes = Vec::<u8>::new();
    bytes.extend((pre_master_secret.len() as u16).to_be_bytes());
    bytes.extend(pre_master_secret);
    let handshake = handshake_bytes(TLSHandshakeType::ClientKeyExchange, &bytes);
    let record = record_bytes(TLSContentType::Handshake, &handshake);
    record
}


impl TLSConnection {
    pub fn new(domain: &str) -> TLSResult<Self> {
        Ok(Self {
            stream: TcpStream::connect(format!("{domain}:443"))?,
            //stream: TcpStream::connect("localhost:8443")?,
            buffer: Vec::new(),
            handshakes: Vec::new(),
        })
    }

    fn parse_from_buffer(&mut self) -> Option<(TLSRecord, Vec<u8>)> {
        match parse_response(&self.buffer) {
            Ok((res, i)) => {
                let bytes = self.buffer[..i].to_vec();
                self.buffer.drain(0..i);
                Some((res, bytes))
            }
            Err(e) => {
                // println!("{}", e);
                None
            }
        }
    }

    pub fn next_record(&mut self) -> TLSResult<(TLSRecord, Vec<u8>)> {
        loop {
            if let Some((record, bytes)) = self.parse_from_buffer() {
                return Ok((record, bytes));
            }

            let mut buf = [0u8; 8096];
            let n = self.stream.read(&mut buf)?;
            // println!("Received {} bytes", n);
            self.buffer.extend_from_slice(&buf[..n]);
        }
    }

    pub fn send_handshake(&mut self, bytes: &[u8]) -> TLSResult<()> {
        self.handshakes.extend_from_slice(&bytes[9..]);
        self.stream.write_all(bytes)?;
        Ok(())
    }
}

fn main() -> TLSResult<()> {
    let mut connection = TLSConnection::new("google.com")?;
    connection.send_handshake(&client_hello_bytes())?;

    let mut secret: Option<Vec<u8>> = None;
    loop {
        let (record, bytes) = connection.next_record()?;
        println!("{:?}", record);

        if let TLSRecord::Handshake(_) = record {
            connection.handshakes.extend_from_slice(&bytes[9..]);
        }

        if let TLSRecord::Handshake(TLSHandshake::Certificates(certs)) = record {
            let cert = certs.list.last().unwrap();
            let (_, encrypted_secret) = encrypt_pre_master_secret(&cert.bytes)?; 
            secret = Some(encrypted_secret);

        }

        else if let TLSRecord::Handshake(TLSHandshake::ServerHelloDone) = record {
            connection.send_handshake(&client_key_exchange_bytes(secret.clone().unwrap()))?;
            // connection.send(&change_cipher_spec_bytes())?;
        }


    }

    // Ok(())
}
