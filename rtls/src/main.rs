use env_logger;
use extensions::SecureRenegotationExt;
use log::{error, info, trace};
use state_machine::TlsStateMachine;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Instant;

//use rsa::rand_core::{OsRng, RngCore, CryptoRng};
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::{RngCore, SeedableRng};

use rsa::pkcs8::DecodePublicKey;
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};
use thiserror::Error;
use x509_parser::parse_x509_certificate;

mod alert;
mod ciphersuite;
mod connection;
mod extensions;
mod prf;
mod record;
mod state_machine;
mod utils;

use ciphersuite::{CipherSuite, RsaAes128CbcSha};
use record::*;

#[derive(Error, Debug)]
pub enum TLSError {
    #[error("Buffer requires {0} more bytes")]
    NeedsMoreData(u16),

    #[error("Buffer requires more bytes")]
    NeedData,

    #[error("Invalid protocol version: {0}.{1}")]
    InvalidProtocolVersion(u8, u8),
}

type TLSResult<T> = Result<T, Box<dyn std::error::Error>>;

fn encrypt_pre_master_secret(cert_der: &[u8]) -> TLSResult<(Vec<u8>, Vec<u8>)> {
    // Step 1: Parse the certificate and extract the public key
    let (_, cert) = parse_x509_certificate(cert_der)?;
    let spki = &cert.tbs_certificate.subject_pki;
    let pub_key_der = spki.raw.as_ref();

    // Step 2: Load RSA public key from DER (PKCS#1 format)
    let rsa_pub = RsaPublicKey::from_public_key_der(pub_key_der)?;

    // Step 3: Generate the 48-byte pre_master_secret
    let mut pre_master = [0u8; 48];
    let mut rng = ChaCha20Rng::seed_from_u64(12345);
    //let mut rng = OsRng;
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
    sm: TlsStateMachine,
}

impl TLSConnection {
    pub fn new(_domain: &str) -> TLSResult<Self> {
        Ok(Self {
            stream: TcpStream::connect(format!("{_domain}:443"))?,
            //stream: TcpStream::connect("localhost:8443")?,
            buffer: Vec::new(),
            sm: TlsStateMachine::new(),
        })
    }

    fn parse_record(&mut self) -> TLSResult<(TLSRecord, Vec<u8>, usize)> {
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

        let state = self.sm.read_state();
        let plaintext = state.decrypt(&buf[5..5 + length]);
        let fragment = match state.params() {
            None => plaintext.clone(),
            Some(params) => {
                let len = plaintext.len();
                let padding = plaintext[len - 1] as usize;
                let mac_len = params.mac_algorithm.mac_length();
                plaintext[..len - padding - 1 - mac_len].to_vec()
            }
        };

        let record = TLSContentType::try_from(buf[0])
            .map_err(|e| e.into())
            .and_then(|content_type| match content_type {
                TLSContentType::ChangeCipherSpec => Ok(TLSRecord::ChangeCipherSuite),
                TLSContentType::Alert => alert::parse_alert(&fragment).map(TLSRecord::Alert),
                TLSContentType::Handshake => parse_handshake(&fragment).map(TLSRecord::Handshake),
                TLSContentType::ApplicationData => Ok(TLSRecord::ApplicationData(fragment.clone())),
            })?;

        return Ok((record, fragment, 5 + length));
    }

    fn parse_from_buffer(&mut self) -> Option<(TLSRecord, Vec<u8>)> {
        match self.parse_record() {
            Ok((res, plaintext, i)) => {
                self.buffer.drain(0..i);
                Some((res, plaintext))
            }
            Err(e) => {
                trace!("ParseRecordErr: {}", e);
                None
            }
        }
    }

    fn send_encrypted<T: Into<TLSPlaintext>>(&mut self, plaintext: T) -> TLSResult<()> {
        let mut state = self.sm.write_state_mut();
        let ciphertext = state.encrypt(plaintext);
        self.send_bytes(&ciphertext.into_bytes())
    }

    pub fn next_record(&mut self) -> TLSResult<TLSRecord> {
        loop {
            if let Some((record, _)) = self.parse_from_buffer() {

                match &record {
                    TLSRecord::ApplicationData(_) | TLSRecord::Alert(_) => {}
                    _ => {
                        let messages_to_send = self.sm.step(&record)?;
                        for message in messages_to_send {
                            self.send_bytes(&message.into_bytes())?;
                        }
                    }
                }

                return Ok(record);
            }

            let mut buf = [0u8; 8096];

            let mut n = self.stream.read(&mut buf)?;
            while n == 0 {
                n = self.stream.read(&mut buf)?;
            }
            trace!("Received {} bytes", n);
            self.buffer.extend_from_slice(&buf[..n]);
        }
    }

    pub fn send_bytes(&mut self, bytes: &[u8]) -> TLSResult<()> {
        self.stream.write_all(bytes)?;
        Ok(())
    }

    pub fn handshake(&mut self, cipher_suites: &[Box<dyn CipherSuite>]) -> TLSResult<()> {
        let start_time = Instant::now();
        let extensions = vec![SecureRenegotationExt::initial().into()];
        let client_hello = ClientHello::new(cipher_suites, extensions);

        self.sm.step(&client_hello.clone().into())?;
        self.send_encrypted(client_hello)?;

        loop {
            let record = self.next_record()?;

            if let TLSRecord::Alert(a) = record {
                println!("{:?}", a);
                return Err("Received alert during handshake".into());
            }
            if self.sm.is_established() {
                let elapsed = Instant::now() - start_time;
                println!("elapsed: {} seconds", elapsed.as_secs_f64());
                return Ok(());
            }
        }
    }

    #[allow(dead_code)]
    #[allow(unused)]
    pub fn send_app_data(&mut self, bytes: &[u8]) -> TLSResult<()> {
        let application_data = ApplicationData::new(bytes.to_vec());
        self.send_encrypted(application_data);
        println!("Sent AppData: {:?}", String::from_utf8_lossy(bytes));
        Ok(())
    }

    pub fn next_app_data(&mut self) -> TLSResult<Vec<u8>> {
        loop {
            let record = self.next_record()?;

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
    env_logger::init();

    let suites: Vec<Box<dyn CipherSuite>> = vec![Box::new(RsaAes128CbcSha {})];

    let mut connection = TLSConnection::new("facebook.com")?;
    connection.handshake(&suites)?;

    Ok(())

    // connection.send_app_data(b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n")?;
    // loop {
    //     let bytes = connection.next_app_data()?;
    //     print!("{}", String::from_utf8_lossy(&bytes));
    // }
}
