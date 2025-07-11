use env_logger;
use log::{debug, error, info, trace, warn};
use rsa::rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::TcpStream;

use rsa::pkcs8::DecodePublicKey;
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};
use thiserror::Error;
use x509_parser::parse_x509_certificate;

mod alert;
mod ciphersuite;
mod connection;
mod prf;
mod record;
mod utils;

use ciphersuite::CipherSuiteEnum;
use connection::ConnStates;
use record::*;

const MAC_SIZE: usize = 20;
const USE_SHA1: bool = MAC_SIZE == 20;

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

struct TLSConnection {
    stream: TcpStream,
    buffer: Vec<u8>,
    handshakes: Vec<u8>,
    states: ConnStates,
}

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

impl TLSConnection {
    pub fn new(_domain: &str) -> TLSResult<Self> {
        Ok(Self {
            stream: TcpStream::connect(format!("{_domain}:443"))?,
            //stream: TcpStream::connect("localhost:8443")?,
            buffer: Vec::new(),
            handshakes: Vec::new(),
            states: ConnStates::default(),
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

        let plaintext = self.states.read_state().decrypt(&buf[5..5 + length]);

        let record = TLSContentType::try_from(buf[0])
            .map_err(|e| e.into())
            .and_then(|content_type| match content_type {
                TLSContentType::ChangeCipherSpec => Ok(TLSRecord::ChangeCipherSuite),
                TLSContentType::Alert => alert::parse_alert(&plaintext).map(TLSRecord::Alert),
                TLSContentType::Handshake => parse_handshake(&plaintext).map(TLSRecord::Handshake),
                TLSContentType::ApplicationData => {
                    let len = plaintext.len();
                    let padding = plaintext[len - 1] as usize;
                    let state = self.states.as_synchronised()?;
                    let mac_len = state.read.params.mac_algorithm.mac_length();
                    let data = plaintext[..len - padding - 1 - mac_len].to_vec();
                    Ok(TLSRecord::ApplicationData(data))
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
                trace!("ParseRecordErr: {}", e);
                None
            }
        }
    }

    fn handle_handshake(&mut self, handshake: &TLSHandshake) -> TLSResult<()> {
        match handshake {
            TLSHandshake::ServerHello(hello) => {
                info!("Received ServerHello");

                let suite_id = hello.cipher_suite.clone() as u16;
                let suite = CipherSuiteEnum::try_from(suite_id)?.suite();
                let params = suite.params();

                self.states.set_server_random(hello.random.as_bytes())?;
                self.states.set_cipher_params(&params)?;
            }
            TLSHandshake::Certificates(certs) => {
                info!("Received ServerCertificates");
                let (pre_master_secret, encrypted_secret) =
                    encrypt_pre_master_secret(&certs.list[0].bytes)?;

                self.states
                    .set_enc_pre_master_secret(encrypted_secret.clone())?;
                self.states.set_pre_master_secret(pre_master_secret)?;
            }
            TLSHandshake::ServerHelloDone => {
                info!("Received ServerHelloDone");

                let state = self.states.as_negotating()?;
                let params = state.negotiated_params();
                self.send_handshake(&client_key_exchange_bytes(
                    &params.enc_pre_master_secret.as_ref().unwrap(),
                ))?;
                info!("Sent ClientKeyExchange");

                self.send(&change_cipher_spec_bytes())?;
                self.states = self.states.transition_write_state()?;
                info!("Sent ChangeCipherSpec");

                let state = self.states.as_transitioning()?;
                let params = state.write_params();
                let seed = Sha256::digest(&self.handshakes).to_vec();
                let verify_data =
                    prf::prf_sha256(&params.master_secret, b"client finished", &seed, 12);

                let (pt_handshake, record) = self.client_finished_bytes(&verify_data)?;

                self.send(&record)?;
                info!("Sent ClientFinished");

                self.handshakes.extend_from_slice(&pt_handshake);
            }
            TLSHandshake::Finished(_) => {
                info!("Received ServerFinished");

                // let seed = Sha256::digest(self.handshakes.clone()).to_vec();
                // let _verify_data = prf::prf(
                //     &self.states.current.as_ref().unwrap().master_secret,
                //     b"server finished",
                //     &seed,
                //     12,
                // );
            }
            _ => {}
        };
        Ok(())
    }

    pub fn next_record(&mut self) -> TLSResult<(TLSRecord, Vec<u8>)> {
        loop {
            if let Some((record, bytes)) = self.parse_from_buffer() {
                // Building up the handshake messages for ClientFinished
                if !matches!(record, TLSRecord::Handshake(TLSHandshake::Finished(_))) {
                    self.handshakes.extend_from_slice(&bytes[5..]);
                }

                match record {
                    TLSRecord::ChangeCipherSuite => {
                        info!("Received ChangeCipherSuite");
                        self.states = self.states.transition_read_state()?;
                    }
                    TLSRecord::Handshake(ref x) => self.handle_handshake(x)?,
                    _ => {}
                }

                return Ok((record, bytes));
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

    pub fn send_handshake(&mut self, bytes: &[u8]) -> TLSResult<()> {
        self.handshakes.extend_from_slice(&bytes[5..]);
        self.send(bytes)
    }

    pub fn send(&mut self, bytes: &[u8]) -> TLSResult<()> {
        self.stream.write_all(bytes)?;
        self.states.write_state().inc_seq_num();
        Ok(())
    }

    pub fn send_client_hello(&mut self) -> TLSResult<()> {
        let client_hello = ClientHello::new();
        self.states
            .set_client_random(client_hello.random.as_bytes())?;
        self.send_handshake(<Vec<u8>>::from(client_hello).as_slice())
    }

    pub fn handshake(&mut self) -> TLSResult<()> {
        self.send_client_hello()?;
        info!("Sent ClientHello");

        loop {
            let (record, _) = self.next_record()?;

            if let TLSRecord::Alert(a) = record {
                println!("{:?}", a);
                return Err("Received alert during handshake".into());
            } else if let TLSRecord::Handshake(TLSHandshake::Finished(_)) = record {
                info!("Handshake complete");
                return Ok(());
            }
        }
    }

    pub fn client_finished_bytes(&self, verify_data: &[u8]) -> TLSResult<(Vec<u8>, Vec<u8>)> {
        let mut bytes = Vec::<u8>::new();
        bytes.extend_from_slice(verify_data);
        let handshake = handshake_bytes(TLSHandshakeType::Finished, &bytes);
        let state = self.states.as_transitioning()?;
        let encrypted = state
            .write
            .encrypt_fragment(TLSContentType::Handshake, &handshake);
        let record = record_bytes(TLSContentType::Handshake, &encrypted);
        Ok((handshake, record))
    }

    #[allow(dead_code)]
    #[allow(unused)]
    pub fn send_app_data(&mut self, bytes: &[u8]) -> TLSResult<()> {
        let state = self.states.as_synchronised()?;
        let encrypted = state
            .write
            .encrypt_fragment(TLSContentType::ApplicationData, bytes);
        let record = record_bytes(TLSContentType::ApplicationData, &encrypted);
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
    env_logger::init();

    let mut connection = TLSConnection::new("example.com")?;
    connection.handshake()?;

    // connection.send_app_data(b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n")?;
    // loop {
    //     let bytes = connection.next_app_data()?;
    //     print!("{}", String::from_utf8_lossy(&bytes));
    // }

    Ok(())
}
