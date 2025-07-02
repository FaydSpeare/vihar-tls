use rand::Rng;
use std::convert::TryInto;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{SystemTime, UNIX_EPOCH};

use num_enum::TryFromPrimitive;
use thiserror::Error;

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

enum HandshakeType {
    ClientHello = 1,
    ServerHello = 2,
}
struct Handshake {
    htype: HandshakeType,
    length: u32,
    body: u8,
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
    ServerHello = 2,
}

#[derive(Debug)]
struct ServerHello {
    server_version: ProtocolVersion,
    random: Random,
    session_id: Vec<u8>,
    cipher_suite: CipherSuite,
    compression_method: u8,
}

#[derive(Debug)]
enum TLSHandshake {
    ServerHello(ServerHello),
}

#[derive(Debug)]
enum TLSRecord {
    Handshake(TLSHandshake),
}

type TLSResult<T> = Result<T, Box<dyn std::error::Error>>;

fn parse_server_hello(buf: &[u8], pos: usize, _len: usize) -> TLSResult<ServerHello> {
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

    let pos = 35 + session_len;
    let cipher_suite =
        CipherSuite::try_from(u16::from_be_bytes([slice[pos], slice[pos + 1]])).unwrap();
    // println!("ciphersuite: 0x{:02X}{:02X}", slice[pos], slice[pos + 1]);

    let compression_method = slice[pos + 2];
    // println!("compression: 0x{:02X}", slice[pos + 2]);

    Ok(ServerHello {
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

fn parse_handshake(buf: &[u8], pos: usize) -> TLSResult<TLSHandshake> {
    let slice = &buf[pos..];
    if slice.len() < 4 {
        panic!("buffer contents too short")
    }

    let length = u32::from_be_bytes([0, slice[1], slice[2], slice[3]]) as usize;
    if slice.len() < 4 + length {
        panic!("buffer contents too short")
    }

    TLSHandshakeType::try_from(slice[0])
        .map_err(|e| e.into())
        .and_then(|handshake_type| {
            println!("HandshakeType: {:?}", handshake_type);
            match handshake_type {
                TLSHandshakeType::ServerHello => {
                    parse_server_hello(buf, pos + 4, length).map(TLSHandshake::ServerHello)
                }
            }
        })
}

#[derive(Error, Debug)]
pub enum TLSError {
    #[error("Buffer doesn't contain enough data")]
    NotEnoughData,

    #[error("Invalid protocol version: {0}.{1}")]
    InvalidProtocolVersion(u8, u8),
}

fn parse_response(buf: &[u8]) -> TLSResult<TLSRecord> {
    let major = buf.get(1).ok_or(TLSError::NotEnoughData)?;
    let minor = buf.get(2).ok_or(TLSError::NotEnoughData)?;

    if !(*major == 3 && *minor == 3) {
        return Err(TLSError::InvalidProtocolVersion(*major, *minor).into());
    }
    println!("ProtocolVersion {major}.{minor}");

    let length_bytes = [
        *buf.get(3).ok_or(TLSError::NotEnoughData)?,
        *buf.get(4).ok_or(TLSError::NotEnoughData)?,
    ];
    let length = u16::from_be_bytes(length_bytes) as usize;

    if buf.len() < 5 + length {
        return Err(TLSError::NotEnoughData.into());
    }

    TLSContentType::try_from(buf[0])
        .map_err(|e| e.into())
        .and_then(|content_type| {
            println!("ContentType: {:?}", content_type);
            match content_type {
                TLSContentType::ChangeCipherSpec => unimplemented!(),
                TLSContentType::Alert => unimplemented!(),
                TLSContentType::Handshake => parse_handshake(buf, 5).map(TLSRecord::Handshake),
                TLSContentType::ApplicationData => unimplemented!(),
            }
        })
}

fn main() -> TLSResult<()> {
    let body = ClientHello {
        client_version: ProtocolVersion { major: 3, minor: 3 },
        random: Random {
            unix_time: get_unix_time(),
            random_bytes: get_random_bytes(28).try_into().unwrap(),
        },
        session_id: vec![],
        cipher_suites: vec![(CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA as u16).to_be_bytes()],
        compression_methods: vec![0],
    };

    let mut bodybytes = Vec::<u8>::new();
    bodybytes.extend([body.client_version.major, body.client_version.minor]); // ProtocolVersion
    bodybytes.extend(body.random.unix_time.to_be_bytes());
    bodybytes.extend(body.random.random_bytes);
    bodybytes.push(0); // SessionId
    bodybytes.extend((2 * body.cipher_suites.len() as u16).to_be_bytes());
    for suite in body.cipher_suites {
        bodybytes.extend(suite);
    }
    bodybytes.push(1); // Compression methods
    bodybytes.push(0);

    let mut bytes = Vec::<u8>::new();
    bytes.push(HandshakeType::ClientHello as u8);

    let value = bodybytes.len();
    bytes.push(((value >> 16) & 0xFF) as u8);
    bytes.push(((value >> 8) & 0xFF) as u8);
    bytes.push((value & 0xFF) as u8);

    bytes.extend(bodybytes);

    let mut record = Vec::<u8>::new();
    record.push(22);
    record.extend([3, 3]);
    record.extend((bytes.len() as u16).to_be_bytes());
    record.extend(bytes);

    let mut stream = TcpStream::connect("google.com:443")?;
    stream.write_all(&record)?;
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf)?;
    println!("Received {} bytes", n);

    let res = parse_response(&buf)?;
    println!("{:#?}", res);

    // let hlen = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    // let server_hello = &buf[5..hlen + 5];
    // println!("{:?} {}", server_hello, server_hello.len());
    // let sh = &server_hello[6..];

    Ok(())
}
