use env_logger;
use extensions::SecureRenegotationExt;
use log::{debug, error, info, trace, warn};
use sha2::{Digest, Sha256};
use state_machine::{TlsState, TlsStateMachine};
use std::io::{Read, Write};
use std::net::TcpStream;

//use rsa::rand_core::{OsRng, RngCore, CryptoRng};
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::{SeedableRng, RngCore};


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
mod utils;
mod state_machine;

use ciphersuite::{CipherSuite, RsaAes128CbcSha, RsaAes128CbcSha256, RsaAes256CbcSha, RsaNullSha};
use connection::ConnStates;
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

struct TLSConnection {
    stream: TcpStream,
    buffer: Vec<u8>,
    handshakes: Vec<u8>,
    states: ConnStates,
    secure_renegotiation: bool,
    sm: Option<TlsStateMachine>
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
    let mut rng = ChaCha20Rng::seed_from_u64(12345);
    //let mut rng = OsRng;
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
            //stream: TcpStream::connect(format!("{_domain}:443"))?,
            stream: TcpStream::connect("localhost:8443")?,
            buffer: Vec::new(),
            handshakes: Vec::new(),
            states: ConnStates::default(),
            secure_renegotiation: false,
            sm: None
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

        let plaintext = self.states.read_state().decrypt(&buf[5..5 + length]);

        let state = self.states.read_state();
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
                TLSContentType::ApplicationData => Ok(TLSRecord::ApplicationData(fragment.clone()))
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

    fn handle_handshake(&mut self, handshake: &TLSHandshake) -> TLSResult<()> {
        match handshake {
            TLSHandshake::ServerHello(hello) => {
                info!("Received ServerHello");

                let params = hello.cipher_suite.params();
                debug!("Selected CipherSuite: {:?}", hello.cipher_suite);

                self.states.set_server_random(hello.random.as_bytes())?;
                self.states.set_cipher_params(&params)?;
                self.secure_renegotiation = hello.supports_secure_renegotiation();
                info!("Secure Renegotiation: {}", self.secure_renegotiation);
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
                let enc_pre_master_secret = params
                    .enc_pre_master_secret
                    .as_ref()
                    .expect("encrypted pre-master secret not found");

                self.send_encrypted_handshake(ClientKeyExchange::new(&enc_pre_master_secret))?;
                info!("Sent ClientKeyExchange");

                self.send_encrypted(ChangeCipherSpec::new())?;
                self.states = self.states.transition_write_state()?;
                info!("Sent ChangeCipherSpec");

                let state = self.states.as_transitioning()?;
                let params = state.write_params();
                let seed = Sha256::digest(&self.handshakes).to_vec();
                let verify_data =
                    prf::prf_sha256(&params.master_secret, b"client finished", &seed, 12);
                println!("Master: {:?}", &params.master_secret);
                println!("VerifyData: {:?}", &verify_data);

                let finished = Finished::new(verify_data.clone());
                self.handshakes.extend_from_slice(&finished.to_bytes());
                self.send_encrypted(finished)?;
                info!("Sent ClientFinished");

                let state = self.states.as_transitioning_mut()?;
                state.write.verify_data = Some(verify_data);
            }
            TLSHandshake::Finished(finished) => {
                info!("Received ServerFinished");

                let state = self.states.as_synchronised_mut()?;
                state.read.verify_data = Some(finished.verify_data.clone());

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

    fn send_encrypted<T: Into<TLSPlaintext>>(&mut self, plaintext: T) -> TLSResult<()> {
        let ciphertext = self.states.write_state().encrypt(plaintext);
        self.send_bytes(&ciphertext.into_bytes())
    }

    fn send_encrypted_handshake<T: Into<TLSPlaintext> + ToBytes>(
        &mut self,
        plaintext: T,
    ) -> TLSResult<()> {
        self.handshakes.extend_from_slice(&plaintext.to_bytes());
        self.send_encrypted(plaintext)
    }

    pub fn next_record(&mut self) -> TLSResult<TLSRecord> {
        loop {
            if let Some((record, plaintext)) = self.parse_from_buffer() {
                let _messages_to_send = self.sm.as_mut().unwrap().step(&record)?;
                
                // Building up the handshake messages for ClientFinished
                if !matches!(record, TLSRecord::Handshake(TLSHandshake::Finished(_))) {
                    self.handshakes.extend_from_slice(&plaintext);
                }

                match record {
                    TLSRecord::ChangeCipherSuite => {
                        info!("Received ChangeCipherSuite");
                        self.states = self.states.transition_read_state()?;
                    }
                    TLSRecord::Handshake(ref x) => self.handle_handshake(x)?,
                    _ => {}
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
        self.states.write_state_mut().inc_seq_num();
        Ok(())
    }

    pub fn send_client_hello(&mut self, client_hello: ClientHello) -> TLSResult<()> {
        let client_random = client_hello.random.as_bytes();
        self.states.set_client_random(client_random)?;
        self.send_encrypted_handshake(client_hello)
    }

    pub fn handshake(&mut self, cipher_suites: &[Box<dyn CipherSuite>]) -> TLSResult<()> {

        let extensions = match &self.states {
            ConnStates::Negotating(_) => vec![SecureRenegotationExt::initial().into()],
            ConnStates::Synchronised(state) => {
                let verify_data = state.write.verify_data.clone().unwrap();
                vec![SecureRenegotationExt::renegotiation(&verify_data).into()]
            },
            _ => return Err("Cannot begin new handshake while handshake under way".into())
        };

        let client_hello = ClientHello::new(cipher_suites, extensions);


        self.sm.replace(TlsStateMachine::new(&client_hello));

        self.handshakes.clear();
        self.states = self.states.start_handshake()?;
        self.send_client_hello(client_hello)?;
        info!("Sent ClientHello");

        loop {
            let record = self.next_record()?;

            if let TLSRecord::Alert(a) = record {
                println!("{:?}", a);
                return Err("Received alert during handshake".into());
            } else if let TLSRecord::Handshake(TLSHandshake::Finished(_)) = record {
                info!("Handshake complete");
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

    let mut connection = TLSConnection::new("example.com")?;
    connection.handshake(&suites)?;

    //println!();
    //connection.handshake(&suites)?;
    //println!();
    //connection.handshake(&suites)?;
    Ok(())

    // connection.send_app_data(b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n")?;
    // loop {
    //     let bytes = connection.next_app_data()?;
    //     print!("{}", String::from_utf8_lossy(&bytes));
    // }
}
