use base64::{decode, encode};
use rand::Rng;
use rsa::rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::convert::TryInto;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{SystemTime, UNIX_EPOCH};

use num_enum::TryFromPrimitive;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};
use thiserror::Error;
use x509_parser::parse_x509_certificate;

use aes::Aes128;
use aes::cipher::{BlockCipher, BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};

mod alert;
mod ciphersuite;
mod prf;

const MASTER_SECRET_LEN: usize = 48;
const VERBOSE: bool = false;

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
#[derive(Clone, Debug, TryFromPrimitive)]
#[repr(u16)]
enum CipherSuiteId {
    TLS_RSA_WITH_AES_128_CBC_SHA = 0x002f,
    TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x003c,
    TLS_RSA_WITH_AES_256_CBC_SHA256 = 0x003d,
}

#[allow(dead_code)]
struct CipherSuite {
    id: u16,
    enc_key_length: u8,
    block_length: u8,
    iv_length: u8,
    mac_length: u8,
    mac_key_length: u8,
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
            cipher_suites: vec![
                (CipherSuiteId::TLS_RSA_WITH_AES_128_CBC_SHA256 as u16).to_be_bytes(),
            ],
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
            0x04,
            0x01, // sha256 + rsa
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
    cipher_suite: CipherSuiteId,
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
    ApplicationData(Vec<u8>),
}

type TLSResult<T> = Result<T, Box<dyn std::error::Error>>;

fn parse_certificates(buf: &[u8]) -> TLSResult<Certificates> {
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

    return Ok(Certificates { list: certs });
}

fn parse_server_hello(buf: &[u8]) -> TLSResult<ServerHello> {
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

fn parse_handshake(buf: &[u8]) -> TLSResult<TLSHandshake> {
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
                parse_server_hello(&buf[4..]).map(TLSHandshake::ServerHello)
            }
            TLSHandshakeType::Certificates => {
                parse_certificates(&buf[4..]).map(TLSHandshake::Certificates)
            }
            TLSHandshakeType::ServerHelloDone => Ok(TLSHandshake::ServerHelloDone),
            TLSHandshakeType::Finished => {
                let verify_data = buf[4..4 + length].to_vec();
                Ok(TLSHandshake::Finished(Finished { verify_data }))
            }
            _ => unimplemented!(),
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

const AES128_BLOCKSIZE: usize = 16;

fn decrypt_aes_128_cbc(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut plaintext = Vec::<u8>::new();
    let mut state = iv;
    let cipher = Aes128::new(&GenericArray::from_slice(key));
    let num_blocks = ciphertext.len() / AES128_BLOCKSIZE;

    for i in 0..num_blocks {
        let ct_block = &ciphertext[i * AES128_BLOCKSIZE..(i + 1) * AES128_BLOCKSIZE];
        let mut block = GenericArray::clone_from_slice(ct_block);
        cipher.decrypt_block(&mut block);
        let pt_block = prf::xor_bytes(&block, state);
        plaintext.extend_from_slice(&pt_block);
        state = ct_block;
    }

    plaintext
}

fn encrypt_aes_128_cbc(plaintext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut ciphertext = Vec::<u8>::new();
    let mut state = iv.to_vec();
    let cipher = Aes128::new(&GenericArray::from_slice(key));
    let num_blocks = plaintext.len() / AES128_BLOCKSIZE;
    for i in 0..num_blocks {
        let pt_block = &plaintext[i * AES128_BLOCKSIZE..(i + 1) * AES128_BLOCKSIZE];
        let input_block = prf::xor_bytes(pt_block, &state);
        let mut block = GenericArray::clone_from_slice(&input_block);
        cipher.encrypt_block(&mut block);
        ciphertext.extend_from_slice(&block);
        state = block.to_vec();
    }
    ciphertext
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
    states: ConnectionStates,
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

fn change_cipher_spec_bytes() -> Vec<u8> {
    record_bytes(TLSContentType::ChangeCipherSpec, &[1])
}

fn encrypt_fragment(
    seq_num: u64,
    write_key: &[u8],
    mac_write_key: &[u8],
    fragment: &[u8],
    content_type: TLSContentType,
) -> Vec<u8> {
    let mut bytes = Vec::<u8>::new();
    bytes.extend_from_slice(&seq_num.to_be_bytes());
    bytes.push(content_type as u8);
    bytes.extend([3, 3]);
    bytes.extend((fragment.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&fragment);

    let mac = prf::hmac(&mac_write_key, &bytes, false);

    let mut padding_len = 16 - ((fragment.len() + mac.len() + 1) % 16);
    if padding_len == 16 {
        padding_len = 16;
    }

    let mut padding = Vec::<u8>::new();
    for _ in 0..padding_len {
        padding.push(padding_len as u8);
    }

    let mut plaintext = Vec::<u8>::new();
    plaintext.extend_from_slice(&fragment);
    plaintext.extend_from_slice(&mac);
    plaintext.extend_from_slice(&padding);
    plaintext.push(padding_len as u8);

    // Encrypt
    let iv = get_random_bytes(16);
    let ciphertext = encrypt_aes_128_cbc(&plaintext, write_key, &iv);

    let mut encrypted = Vec::<u8>::new();
    encrypted.extend_from_slice(&iv);
    encrypted.extend_from_slice(&ciphertext);
    encrypted
}

fn record_bytes(content_type: TLSContentType, content: &[u8]) -> Vec<u8> {
    let mut record = Vec::<u8>::new();
    record.push(content_type as u8);
    record.extend([3, 3]);
    record.extend((content.len() as u16).to_be_bytes());
    record.extend(content);
    record
}

fn application_data_bytes(
    seq_num: u64,
    write_key: &[u8],
    mac_write_key: &[u8],
    msg: &[u8],
) -> Vec<u8> {
    let encrypted = encrypt_fragment(
        seq_num,
        write_key,
        mac_write_key,
        &msg,
        TLSContentType::ApplicationData,
    );
    record_bytes(TLSContentType::ApplicationData, &encrypted)
}

fn client_finished_bytes(
    seq_num: u64,
    write_key: &[u8],
    mac_write_key: &[u8],
    verify_data: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let mut bytes = Vec::<u8>::new();
    bytes.extend_from_slice(verify_data);
    let handshake = handshake_bytes(TLSHandshakeType::Finished, &bytes);

    let encrypted = encrypt_fragment(
        seq_num,
        write_key,
        mac_write_key,
        &handshake,
        TLSContentType::Handshake,
    );
    let record = record_bytes(TLSContentType::Handshake, &encrypted);
    (handshake, record)
}

fn client_key_exchange_bytes(enc_pre_master_secret: Vec<u8>) -> Vec<u8> {
    let mut bytes = Vec::<u8>::new();
    bytes.extend((enc_pre_master_secret.len() as u16).to_be_bytes());
    bytes.extend(enc_pre_master_secret);
    let handshake = handshake_bytes(TLSHandshakeType::ClientKeyExchange, &bytes);
    let record = record_bytes(TLSContentType::Handshake, &handshake);
    record
}

struct SecurityParams {
    enc_key_length: u8,
    block_length: u8,
    iv_length: u8,
    mac_length: u8,
    mac_key_length: u8,

    master_secret: [u8; 48],
    client_random: [u8; 32],
    server_random: [u8; 32],
}

#[derive(Debug, Default)]
struct PendingConnectionState {
    enc_key_length: Option<u8>,
    block_length: Option<u8>,
    iv_length: Option<u8>,
    mac_length: Option<u8>,
    mac_key_length: Option<u8>,
    master_secret: Option<[u8; 48]>,
    client_random: Option<[u8; 32]>,
    server_random: Option<[u8; 32]>,
}

#[derive(Debug)]
struct ConnectionState {
    enc_key_length: u8,
    block_length: u8,
    iv_length: u8,
    mac_length: u8,
    mac_key_length: u8,
    master_secret: [u8; 48],
    client_random: [u8; 32],
    server_random: [u8; 32],
    sequence_num: u64,
}

impl ConnectionState {
    fn from_pending_state(state: &PendingConnectionState) -> TLSResult<Self> {
        Ok(Self {
            enc_key_length: state.enc_key_length.ok_or("")?,
            block_length: state.block_length.ok_or("")?,
            iv_length: state.iv_length.ok_or("")?,
            mac_length: state.mac_length.ok_or("")?,
            mac_key_length: state.mac_key_length.ok_or("")?,
            master_secret: state.master_secret.ok_or("")?,
            client_random: state.client_random.ok_or("")?,
            server_random: state.server_random.ok_or("")?,
            sequence_num: 0,
        })
    }
}

#[derive(Debug, Default)]
struct ConnectionStates {
    current: Option<ConnectionState>,
    pending: PendingConnectionState,
}

impl ConnectionStates {
    fn instate_pending(&mut self) -> TLSResult<()> {
        self.current = Some(ConnectionState::from_pending_state(&self.pending)?);
        self.pending = PendingConnectionState::default();
        Ok(())
    }
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
            states: ConnectionStates::default(),
        })
    }

    fn parse_record(&mut self) -> TLSResult<(TLSRecord, usize)> {
        let buf = &mut self.buffer;
        if buf.len() < 5 {
            return Err(TLSError::NeedsMoreData((5 - buf.len()) as u16).into());
        }

        let major = buf[1];
        let minor = buf[2];

        if !(major == 3 && minor == 3) {
            return Err(TLSError::InvalidProtocolVersion(major, minor).into());
        }

        let length_bytes = [buf[3], buf[4]];
        let length = u16::from_be_bytes(length_bytes) as usize;

        if buf.len() < 5 + length {
            return Err(TLSError::NeedsMoreData((5 + length - buf.len()) as u16).into());
        }

        let mut pos = 5;
        if self.encrypted {
            let plaintext = decrypt_aes_128_cbc(
                &buf[5 + AES128_BLOCKSIZE..5 + length],
                &self.keys.clone().unwrap().server_write_key,
                &buf[5..5 + AES128_BLOCKSIZE],
            );

            for i in 0..(length - 16) {
                buf[5 + 16 + i] = plaintext[i];
            }
            pos += 16;
        }

        let record = TLSContentType::try_from(buf[0])
            .map_err(|e| e.into())
            .and_then(|content_type| {
                // println!("ContentType: {:?}", content_type);
                match content_type {
                    TLSContentType::ChangeCipherSpec => Ok(TLSRecord::ChangeCipherSuite),
                    TLSContentType::Alert => alert::parse_alert(&buf[pos..]).map(TLSRecord::Alert),
                    TLSContentType::Handshake => {
                        parse_handshake(&buf[pos..]).map(TLSRecord::Handshake)
                    }
                    TLSContentType::ApplicationData => {
                        let padding = buf[5 + length - 1] as usize;
                        let data = buf[5 + 16..length - padding - 1 - 32].to_vec();
                        Ok(TLSRecord::ApplicationData(data))
                    }
                }
            })?;

        return Ok((record, 5 + length));
    }

    fn parse_from_buffer(&mut self) -> Option<(TLSRecord, Vec<u8>)> {
        match self.parse_record() {
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
                // Building up the handshake messages for ClientFinished
                if let TLSRecord::Handshake(x) = &record {
                    match x {
                        TLSHandshake::Finished(_) => {}
                        _ => {
                            self.handshakes.extend_from_slice(&bytes[5..]);
                        }
                    }
                }

                if let TLSRecord::ChangeCipherSuite = &record {
                    if VERBOSE { println!("Received ChangeCipherSuite"); }
                    self.encrypted = true;
                } else if let TLSRecord::Handshake(TLSHandshake::ServerHello(hello)) = &record {
                    if VERBOSE { println!("Received ServerHello"); }

                    self.server_random = Some(hello.random.to_bytes());
                    // println!("CipherSuite: {:?}", hello.cipher_suite);
                    // let suite =
                    //     ciphersuite::CipherSuiteEnum::try_from(hello.cipher_suite.clone() as u16)
                    //         .unwrap()
                    //         .suite();
                    // println!("CipherSuite: {:?}", suite.params());
                    self.states.pending.server_random =
                        Some(hello.random.to_bytes().try_into().unwrap());

                } else if let TLSRecord::Handshake(TLSHandshake::ServerHelloDone) = &record {

                    if VERBOSE { println!("Received ServerHelloDone"); }
                    self.send_handshake(&client_key_exchange_bytes(
                        self.enc_pre_master_secret.clone().unwrap(),
                    ))?;
                    if VERBOSE { println!("Sent ClientKeyExchange"); }

                    self.send(&change_cipher_spec_bytes())?;
                    if VERBOSE { println!("Sent ChangeCipherSpec"); }

                    let seed = Sha256::digest(self.handshakes.clone()).to_vec();
                    let verify_data = prf::prf(
                        self.master_secret.as_ref().unwrap(),
                        b"client finished",
                        &seed,
                        12,
                    );

                    let keys = &self.keys.clone().unwrap();
                    let (pt_handshake, record) = client_finished_bytes(
                        0,
                        &keys.client_write_key,
                        &keys.client_write_mac_key,
                        &verify_data,
                    );
                    self.send(&record)?;
                    self.handshakes.extend_from_slice(&pt_handshake);

                    if VERBOSE { println!("Sent ClientFinished"); }
                } else if let TLSRecord::Handshake(TLSHandshake::Certificates(certs)) = &record {
                    if VERBOSE { println!("Received ServerCertificates"); }
                    let cert = certs.list.last().unwrap();

                    let (pre_master_secret, encrypted_secret) =
                        encrypt_pre_master_secret(&cert.bytes)?;
                    self.enc_pre_master_secret = Some(encrypted_secret);

                    let mut concat_random = Vec::<u8>::new();
                    concat_random.extend_from_slice(self.client_random.as_ref().unwrap());
                    concat_random.extend_from_slice(self.server_random.as_ref().unwrap());

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
                } else if let TLSRecord::Handshake(TLSHandshake::Finished(_)) = &record {
                    if VERBOSE { println!("Received ServerFinished"); }

                    let seed = Sha256::digest(self.handshakes.clone()).to_vec();
                    let verify_data = prf::prf(
                        self.master_secret.as_ref().unwrap(),
                        b"server finished",
                        &seed,
                        12,
                    );

                }

                self.sequence_num_read += 1;
                return Ok((record, bytes));
            }

            let mut buf = [0u8; 8096];

            let mut n = self.stream.read(&mut buf)?;
            while n == 0 {
                n = self.stream.read(&mut buf)?;
            }
            // println!("Received {} bytes", n);
            self.buffer.extend_from_slice(&buf[..n]);
        }
    }

    pub fn send_handshake(&mut self, bytes: &[u8]) -> TLSResult<()> {
        self.handshakes.extend_from_slice(&bytes[5..]);
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
        self.states.pending.client_random =
            Some(client_hello.random.to_bytes().try_into().unwrap());
        self.send_handshake(&client_hello.to_bytes())
    }

    pub fn handshake(&mut self) -> TLSResult<()> {
        self.send_client_hello()?;
        if VERBOSE { println!("Sent ClientHello"); }

        loop {
            let (record, _) = self.next_record()?;

            if let TLSRecord::Alert(a) = record {
                println!("{:?}", a);
                return Err("Received alert during handshake".into());

            } else if let TLSRecord::Handshake(TLSHandshake::Finished(_)) = record {
                println!("Handshake complete");
                return Ok(());
            }
        }
    }

    pub fn send_app_data(&mut self, bytes: &[u8]) -> TLSResult<()> {
        let keys = &self.keys.clone().unwrap();
        let record = application_data_bytes(
            1,
            &keys.client_write_key,
            &keys.client_write_mac_key,
            bytes,
        );
        self.send(&record)?;
        println!("Sent AppData: {:?}", String::from_utf8_lossy(bytes));
        Ok(())
    }

    pub fn next_app_data(&mut self) -> TLSResult<Vec<u8>> {
        loop {
            let (record, _) = self.next_record()?;

            if let TLSRecord::Alert(a) = record {
                println!("{:?}", a);
                return Err("Received alert".into());

            } else if let TLSRecord::ApplicationData(x) = record {
                return Ok(x);
            }
        }
    }
}

fn main() -> TLSResult<()> {
    let mut connection = TLSConnection::new("google.com")?;
    connection.handshake()?;
    connection.send_app_data(b"Connection Established")?;

    loop {
        let bytes = connection.next_app_data()?;
        println!(
            "Received ApplicationData {:?}",
            String::from_utf8(bytes).unwrap()
        );
    }
}
