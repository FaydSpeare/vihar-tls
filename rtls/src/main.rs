use rand::Rng;
use rsa::rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::convert::TryInto;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{SystemTime, UNIX_EPOCH};
use base64::{encode, decode};

use num_enum::TryFromPrimitive;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};
use thiserror::Error;
use x509_parser::parse_x509_certificate;

use aes::Aes128;
use aes::cipher::{BlockCipher, BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};

mod alert;
mod prf;

const MASTER_SECRET_LEN: usize = 48;

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

impl Random {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::<u8>::new();
        bytes.extend(self.unix_time.to_be_bytes());
        bytes.extend(self.random_bytes);
        bytes
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, TryFromPrimitive)]
#[repr(u16)]
enum CipherSuite {
    TLS_RSA_WITH_AES_128_CBC_SHA = 0x002f,
    TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x003c,
    TLS_RSA_WITH_AES_256_CBC_SHA256 = 0x003d,
}

struct ClientHello {
    client_version: ProtocolVersion,
    random: Random,
    session_id: Vec<u8>,
    cipher_suites: Vec<[u8; 2]>,
    compression_methods: Vec<u8>,
}

impl ClientHello {
    fn new() -> Self {
        ClientHello {
            client_version: ProtocolVersion { major: 3, minor: 3 },
            random: Random {
                unix_time: get_unix_time(),
                random_bytes: get_random_bytes(28).try_into().unwrap(),
            },
            session_id: vec![],
            cipher_suites: vec![(CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA256 as u16).to_be_bytes()],
            compression_methods: vec![0],
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::<u8>::new();
        bytes.extend([self.client_version.major, self.client_version.minor]); // ProtocolVersion

        bytes.extend_from_slice(&self.random.to_bytes());

        bytes.push(0); // SessionId

        bytes.extend((2 * self.cipher_suites.len() as u16).to_be_bytes());
        for suite in &self.cipher_suites {
            bytes.extend(suite);
        }

        bytes.push(1); // Compression methods
        bytes.push(0);

        let ext = [
            0x00, 0x0d, // Extension type: signature_algorithms (13)
            0x00, 0x04, // Extension length: 6 bytes
            0x00, 0x02, // Supported algorithms list length: 4 bytes
            0x04, 0x01, // sha256 + rsa
            //0x02, 0x01, // sha1 + rsa (optional)
        ];
        let extensions_len = (ext.len() as u16).to_be_bytes();
        bytes.extend_from_slice(&extensions_len);
        bytes.extend_from_slice(&ext);

        let handshake = handshake_bytes(TLSHandshakeType::ClientHello, &bytes);
        record_bytes(TLSContentType::Handshake, &handshake)
    }
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
    Finished = 20,
    VerifyCertificate = 15,
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
struct Finished {
    verify_data: Vec<u8>,
}

#[allow(dead_code)]
#[derive(Debug)]
enum TLSHandshake {
    ServerHello(ServerHello),
    Certificates(Certificates),
    ServerHelloDone,
    Finished(Finished),
}

#[derive(Debug)]
enum TLSRecord {
    Handshake(TLSHandshake),
    Alert(alert::TLSAlert),
    ChangeCipherSuite,
}

type TLSResult<T> = Result<T, Box<dyn std::error::Error>>;

fn parse_certificates(buf: &[u8], pos: usize, _len: usize) -> TLSResult<(Certificates, usize)> {
    let mut slice = &buf[pos..];
    let cert_bytes = u32::from_be_bytes([0, slice[0], slice[1], slice[2]]) as usize;

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
        idx += 3 + cert_len;
    }

    return Ok((Certificates { list: certs }, pos + 3 + idx));
}

fn parse_server_hello(buf: &[u8], pos: usize, _len: usize) -> TLSResult<(ServerHello, usize)> {
    let slice = &buf[pos..];
    let major = slice[0];
    let minor = slice[1];
    println!("ServerVersion: {major}.{minor}");

    let unix_time = u32::from_be_bytes([slice[2], slice[3], slice[4], slice[5]]);
    println!("Unix: {unix_time}");

    let random_bytes: [u8; 28] = slice[6..34].try_into().unwrap();
    // println!("Random: {:?}", random_bytes);

    let session_len = slice[34] as usize;
    let session_id = slice[35..35 + session_len].to_vec();
    // println!("Session: {:?}", session_id);

    let idx = 35 + session_len;
    let cipher_suite =
        CipherSuite::try_from(u16::from_be_bytes([slice[idx], slice[idx + 1]])).unwrap();
    println!("ciphersuite: 0x{:02X}{:02X}", slice[idx], slice[idx + 1]);

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
    println!("handshake length: {}", length);
    if slice.len() < 4 + length {
        return Err(TLSError::NeedData.into());
    }

    // println!("Handshake length: {length}");
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
                TLSHandshakeType::Finished => {
                    let verify_data = slice[4..4 + length].to_vec();
                    Ok((TLSHandshake::Finished(Finished { verify_data }), pos + length))
                },
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

fn parse_response(buf: &mut [u8], encrypted: bool, key: &Option<TLSKeys>) -> TLSResult<(TLSRecord, usize)> {
    if buf.len() < 5 {
        return Err(TLSError::NeedsMoreData((5 - buf.len()) as u16).into());
    }

    let major = buf[1];
    let minor = buf[2];

    if !(major == 3 && minor == 3) {
        return Err(TLSError::InvalidProtocolVersion(major, minor).into());
    }
    // println!("ProtocolVersion {major}.{minor}");

    let length_bytes = [buf[3], buf[4]];
    let length = u16::from_be_bytes(length_bytes) as usize;

    if buf.len() < 5 + length {
        return Err(TLSError::NeedsMoreData((5 + length - buf.len()) as u16).into());
    }

    let mut pos = 5;
    if encrypted {
        let mut plaintext = Vec::<u8>::new();
        let ciphertext = &buf[5 + 16..5 + length];

        let iv = &buf[5..5 + 16];
        let mut state = iv;
        let cipher = Aes128::new(&GenericArray::from_slice(&key.clone().unwrap().server_write_key));
        let num_blocks = ciphertext.len() / 16;

        for i in 0..num_blocks {
            let ct_block = &ciphertext[i * 16..(i + 1) * 16];
            let mut block = GenericArray::clone_from_slice(ct_block);
            cipher.decrypt_block(&mut block);
            let pt_block = prf::xor_bytes(&block, &state);
            plaintext.extend_from_slice(&pt_block);
            state = ct_block;
        }

        println!("CT {:?}", ciphertext);
        println!("PT {:?}", plaintext);
        for i in 0..(length - 16) {
            buf[5 + 16 + i] = plaintext[i];
        }

        pos += 16;
    }

    TLSContentType::try_from(buf[0])
        .map_err(|e| e.into())
        .and_then(|content_type| {
            println!("ContentType: {:?}", content_type);
            match content_type {
                TLSContentType::ChangeCipherSpec => Ok((TLSRecord::ChangeCipherSuite, 6)),
                TLSContentType::Alert => {
                    alert::parse_alert(buf, 5).map(|(x, y)| (TLSRecord::Alert(x), y))
                }
                TLSContentType::Handshake => {
                    parse_handshake(buf, pos).map(|(x, y)| (TLSRecord::Handshake(x), 5 + length))
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
    //let rsa_pub = RsaPublicKey::from_pkcs1_der(pub_key_der)?;
    //RsaPublicKey::from_pkcs1_der
    let encoded = encode(pub_key_der);
    // println!("Encoded: {:?}");

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

#[derive(Clone)]
struct TLSKeys {
    client_write_mac_key: Vec<u8>,
    server_write_mac_key: Vec<u8>,
    client_write_key: Vec<u8>,
    server_write_key: Vec<u8>,
}

struct TLSConnection {
    stream: TcpStream,
    buffer: Vec<u8>,
    handshakes: Vec<u8>,
    client_random: Option<Vec<u8>>,
    server_random: Option<Vec<u8>>,
    // Saved temporarily to be sent later in ClientKeyExchange
    enc_pre_master_secret: Option<Vec<u8>>,
    master_secret: Option<Vec<u8>>,
    sequence_num_write: u64,
    sequence_num_read: u64,
    keys: Option<TLSKeys>,
    encrypted: bool,
}

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

fn client_finished_bytes(seq_num: u64, write_key: &[u8], mac_write_key: &[u8], verify_data: &[u8]) -> (Vec<u8>, Vec<u8>) {
    println!("SEQ {}", seq_num);

    let mut bytes = Vec::<u8>::new();
    bytes.extend_from_slice(verify_data);
    let handshake = handshake_bytes(TLSHandshakeType::Finished, &bytes);

    let mut bytes = Vec::<u8>::new();
    bytes.extend_from_slice(&seq_num.to_be_bytes());
    bytes.push(TLSContentType::Handshake as u8);
    bytes.extend([3, 3]);
    bytes.extend((handshake.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&handshake);

    let mac = prf::hmac(&mac_write_key, &bytes);

    let mut padding_len = 16 - ((handshake.len() + mac.len() + 1) % 16);
    if padding_len == 16 {
        padding_len = 16;
    }
    
    let mut padding = Vec::<u8>::new();
    for _ in 0..padding_len {
        padding.push(padding_len as u8);
    }

    let mut plaintext = Vec::<u8>::new();
    plaintext.extend_from_slice(&handshake);
    plaintext.extend_from_slice(&mac);
    plaintext.extend_from_slice(&padding);
    plaintext.push(padding_len as u8);
    
    println!("handshake length: {}", handshake.len());
    println!("mac length: {}", mac.len());
    println!("padding length: {}", padding_len);
    println!("plaintext length: {}", plaintext.len());
    println!("plaintext: {:?}", plaintext);

    // Encrypt
    let mut ciphertext = Vec::<u8>::new();
    let iv = get_random_bytes(16);
    let mut state = iv.clone();
    let cipher = Aes128::new(&GenericArray::from_slice(write_key));
    let num_blocks = plaintext.len() / 16;
    for i in 0..num_blocks {
        let pt_block = &plaintext[i * 16..(i + 1) * 16];
        let input_block = prf::xor_bytes(pt_block, &state);
        let mut block = GenericArray::clone_from_slice(&input_block);
        cipher.encrypt_block(&mut block);
        ciphertext.extend_from_slice(&block);
        state = block.to_vec();
    }

    println!("Ciphertext: {:?} {}", ciphertext, ciphertext.len());
    let mut encrypted = Vec::<u8>::new();
    encrypted.extend_from_slice(&iv); 
    encrypted.extend_from_slice(&ciphertext);
    println!("Encrypted length: {}", encrypted.len());

    let record = record_bytes(TLSContentType::Handshake, &encrypted);
    (handshake, record)
}

fn client_key_exchange_bytes(enc_pre_master_secret: Vec<u8>) -> Vec<u8> {
    let mut bytes = Vec::<u8>::new();
    bytes.extend((enc_pre_master_secret.len() as u16).to_be_bytes());
    bytes.extend(enc_pre_master_secret);
    println!("keyex {}", bytes.len());
    let handshake = handshake_bytes(TLSHandshakeType::ClientKeyExchange, &bytes);
    let record = record_bytes(TLSContentType::Handshake, &handshake);
    record
}

impl TLSConnection {
    pub fn new(domain: &str) -> TLSResult<Self> {
        Ok(Self {
            //stream: TcpStream::connect(format!("{domain}:443"))?,
            stream: TcpStream::connect("localhost:8443")?,
            buffer: Vec::new(),
            handshakes: Vec::new(),
            client_random: None,
            server_random: None,
            enc_pre_master_secret: None,
            master_secret: None,
            sequence_num_write: 0,
            sequence_num_read: 0,
            keys: None,
            encrypted: false,
        })
    }

    fn parse_from_buffer(&mut self) -> Option<(TLSRecord, Vec<u8>)> {
        match parse_response(&mut self.buffer, self.encrypted, &self.keys) {
            Ok((res, i)) => {
                let bytes = self.buffer[..i].to_vec();
                println!("bytes: {}", bytes.len());
                self.buffer.drain(0..i);
                Some((res, bytes))
            }
            Err(e) => {
                println!("{}", e);
                None
            }
        }
    }

    pub fn next_record(&mut self) -> TLSResult<(TLSRecord, Vec<u8>)> {
        loop {
            if let Some((record, bytes)) = self.parse_from_buffer() {

                // Building up the handshake messages for ClientFinished
                if let TLSRecord::Handshake(x) = &record {
                    match x {
                        TLSHandshake::Finished(_) => {},
                        _ => {
                            println!("adding to handshakes: {}", bytes.len() - 5);
                            self.handshakes.extend_from_slice(&bytes[5..]);
                        }
                    }
                }

                if let TLSRecord::ChangeCipherSuite = &record {
                    self.encrypted = true;
                }

                if let TLSRecord::Handshake(TLSHandshake::ServerHello(hello)) = &record {
                    self.server_random = Some(hello.random.to_bytes());
                }

                if let TLSRecord::Handshake(TLSHandshake::Certificates(certs)) = &record {
                    let cert = certs.list.last().unwrap();

                    let (pre_master_secret, encrypted_secret) =
                        encrypt_pre_master_secret(&cert.bytes)?;
                    self.enc_pre_master_secret = Some(encrypted_secret);

                    let mut concat_random = Vec::<u8>::new();
                    concat_random.extend_from_slice(self.client_random.as_ref().unwrap());
                    concat_random.extend_from_slice(self.server_random.as_ref().unwrap());
                    println!("RAND LEN: {}", concat_random.len());

                    // ORDER DOUBLE CHECKED
                    self.master_secret = Some(prf::prf(
                        &pre_master_secret,
                        b"master secret",
                        &concat_random,
                        MASTER_SECRET_LEN,
                    ));

                    let mut concat_random_rev = Vec::<u8>::new();
                    concat_random_rev.extend_from_slice(self.server_random.as_ref().unwrap());
                    concat_random_rev.extend_from_slice(self.client_random.as_ref().unwrap());

                    // ARGS DOUBLE CHECKED
                    let key_block = prf::prf(
                        self.master_secret.as_ref().unwrap(),
                        b"key expansion",
                        &concat_random_rev,
                        96,
                    );

                    // ORDER DOUBLE CHECKED
                    let client_write_mac_key = key_block[..32].to_vec();
                    let server_write_mac_key = key_block[32..64].to_vec();
                    let client_write_key = key_block[64..80].to_vec();
                    let server_write_key = key_block[80..96].to_vec();
                    self.keys = Some(TLSKeys {
                        client_write_mac_key,
                        server_write_mac_key,
                        client_write_key,
                        server_write_key,
                    });
                }

                self.sequence_num_read += 1;
                return Ok((record, bytes));
            }

            let mut buf = [0u8; 8096];
            let n = self.stream.read(&mut buf)?;
            // println!("Received {} bytes", n);
            self.buffer.extend_from_slice(&buf[..n]);
        }
    }

    pub fn send_handshake(&mut self, bytes: &[u8]) -> TLSResult<()> {
        self.handshakes.extend_from_slice(&bytes[5..]);
        println!("adding to handshakes: {}", bytes.len() - 5);
        self.send(bytes)
    }

    pub fn send(&mut self, bytes: &[u8]) -> TLSResult<()> {
        self.sequence_num_write += 1;
        self.stream.write_all(bytes)?;
        Ok(())
    }

    pub fn send_client_hello(&mut self) -> TLSResult<()> {
        let client_hello = ClientHello::new();
        self.client_random = Some(client_hello.random.to_bytes());
        self.send_handshake(&client_hello.to_bytes())
    }
}

fn main() -> TLSResult<()> {
    let mut connection = TLSConnection::new("google.com")?;
    connection.send_client_hello()?;
    println!("Sent ClientHello");

    loop {
        let (record, _) = connection.next_record()?;
        println!();
        // println!("{:?}", record);

        if let TLSRecord::Alert(a) = record {
            println!("{:?}", a);
            return Ok(());
        } else if let TLSRecord::Handshake(TLSHandshake::ServerHelloDone) = record {
            connection.send_handshake(&client_key_exchange_bytes(
                connection.enc_pre_master_secret.clone().unwrap(),
            ))?;
            println!("Sent ClientKeyExchange");
            //return Ok(());

            connection.send(&change_cipher_spec_bytes())?;
            println!("Sent ChangeCipherSpec");
            // return Ok(());

            println!("handshakes bytes len: {}", connection.handshakes.len());
            let seed = Sha256::digest(connection.handshakes.clone()).to_vec();
            let verify_data = prf::prf(
                connection.master_secret.as_ref().unwrap(),
                b"client finished",
                &seed,
                12,
            );

            /*
            println!(
                "master_secret {:?}",
                connection.master_secret.clone().unwrap()
            );
            println!("verify_data {:?}", verify_data);
            */

            let keys = &connection.keys.clone().unwrap();
            let (pt_handshake, record) = client_finished_bytes(
                //connection.sequence_num_write,
                0,
                &keys.client_write_key,
                &keys.client_write_mac_key,
                &verify_data,
            );
            connection.send(&record)?;
            connection.handshakes.extend_from_slice(&pt_handshake);

            println!("Sent ClientFinished");
        } else if let TLSRecord::Handshake(TLSHandshake::Finished(finished)) = record {
            println!("{:?}", finished.verify_data);

            println!("handshakes bytes len: {}", connection.handshakes.len());
            let seed = Sha256::digest(connection.handshakes.clone()).to_vec();
            let verify_data = prf::prf(
                connection.master_secret.as_ref().unwrap(),
                b"server finished",
                &seed,
                12,
            );
            println!("{:?}", verify_data);
        }
    }

    // Ok(())
}

// ClientFinished:
// verify_data do we need length? I don't think so 
// do we use client_write_key for encryption?
