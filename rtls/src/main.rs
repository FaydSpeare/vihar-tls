use alert::{TLSAlert, TLSAlertDesc, TLSAlertLevel};
use connection::ConnState;
use env_logger;
use extensions::{SecureRenegotationExt, SessionTicketExt};
use log::{error, trace};
use state_machine::{ConnStates, TlsAction, TlsContext, TlsEntity, TlsHandshakeStateMachine, TlsState};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Instant;

use rsa::rand_core::{OsRng, RngCore};
// use rand_chacha::ChaCha20Rng;
// use rand_chacha::rand_core::{RngCore, SeedableRng};

use rsa::pkcs8::DecodePublicKey;
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};
use thiserror::Error;
use x509_parser::parse_x509_certificate;

mod alert;
mod ciphersuite;
mod connection;
mod extensions;
mod messages;
mod prf;
mod state_machine;
mod utils;

use ciphersuite::{
    CipherSuite, RsaAes128CbcSha256, RsaAes128CbcSha, RsaAes256CbcSha256, RsaAes256CbcSha,
};
use messages::*;

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
    //let mut rng = ChaCha20Rng::seed_from_u64(12345);
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
    pub handshake_state_machine: TlsHandshakeStateMachine,
    conn_states: ConnStates,
}

impl TLSConnection {
    pub fn new(domain: &str) -> TLSResult<Self> {
        let port = if domain == "localhost" { "4433" } else { "443" };
        Ok(Self {
            stream: TcpStream::connect(format!("{domain}:{port}"))?,
            buffer: Vec::new(),
            handshake_state_machine: TlsHandshakeStateMachine::new(),
            conn_states: ConnStates::new(),
        })
    }

    pub fn new_with_context(domain: &str, ctx: TlsContext) -> TLSResult<Self> {
        let port = if domain == "localhost" { "4433" } else { "443" };
        Ok(Self {
            stream: TcpStream::connect(format!("{domain}:{port}"))?,
            buffer: Vec::new(),
            handshake_state_machine: TlsHandshakeStateMachine::from_context(ctx),
            conn_states: ConnStates::new(),
        })
    }

    pub fn notify_close(&mut self) -> TLSResult<()> {
        let alert = TLSAlert::new(TLSAlertLevel::Warning, TLSAlertDesc::CloseNotify);
        let ciphertext = self.conn_states.write.encrypt(alert);
        self.send_bytes(&ciphertext.into_bytes())?;
        Ok(())
    }

    fn parse_message(&mut self) -> TLSResult<(TlsMessage, usize)> {
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

        let state = &mut self.conn_states.read;
        let plaintext = state.decrypt(&buf[5..5 + length]);

        let fragment = match state {
            ConnState::Initial(_) => plaintext.clone(),
            ConnState::Secure(secure_state) => {
                let len = plaintext.len();
                let padding = plaintext[len - 1] as usize;
                let mac_len = secure_state.params.mac_algorithm.mac_length();
                let fragment = plaintext[..len - padding - 1 - mac_len].to_vec();
                let mac = plaintext[len - padding - 1 - mac_len..len - padding - 1].to_vec();

                let mut bytes = Vec::<u8>::new();
                bytes.extend_from_slice(&(secure_state.seq_num - 1).to_be_bytes());
                bytes.push(buf[0]);
                bytes.extend([3, 3]);
                bytes.extend((fragment.len() as u16).to_be_bytes());
                bytes.extend_from_slice(&fragment);

                assert_eq!(
                    secure_state
                        .params
                        .mac_algorithm
                        .mac(&secure_state.mac_key, &bytes),
                    mac,
                    "bad_record_mac"
                );
                fragment
            }
        };

        let message = TLSContentType::try_from(buf[0])
            .map_err(|e| e.into())
            .and_then(|content_type| match content_type {
                TLSContentType::ChangeCipherSpec => Ok(TlsMessage::ChangeCipherSpec),
                TLSContentType::Alert => alert::parse_alert(&fragment).map(TlsMessage::Alert),
                TLSContentType::Handshake => parse_handshake(&fragment).map(TlsMessage::Handshake),
                TLSContentType::ApplicationData => {
                    Ok(TlsMessage::ApplicationData(fragment.clone()))
                }
            })?;

        return Ok((message, 5 + length));
    }

    fn parse_message_from_buffer(&mut self) -> Option<TlsMessage> {
        match self.parse_message() {
            Ok((msg, i)) => {
                self.buffer.drain(0..i);
                Some(msg)
            }
            Err(e) => {
                trace!("ParseRecordErr: {}", e);
                None
            }
        }
    }

    fn next_message(&mut self) -> TLSResult<TlsMessage> {
        loop {
            if let Some(msg) = self.parse_message_from_buffer() {
                match &msg {
                    TlsMessage::ApplicationData(_) | TlsMessage::Alert(_) => {}
                    _ => self.process_message(&msg)?,
                }

                return Ok(msg);
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

    fn send_bytes(&mut self, bytes: &[u8]) -> TLSResult<()> {
        self.stream.write_all(bytes)?;
        Ok(())
    }

    fn process_message(&mut self, msg: &TlsMessage) -> TLSResult<()> {
        for action in self.handshake_state_machine.transition(msg)? {
            match action {
                TlsAction::ChangeCipherSpec(TlsEntity::Client, write) => {
                    self.conn_states.write = write
                }
                TlsAction::ChangeCipherSpec(TlsEntity::Server, read) => {
                    self.conn_states.read = read
                }
                TlsAction::SendPlaintext(plaintext) => {
                    let ciphertext = self.conn_states.write.encrypt(plaintext);
                    self.send_bytes(&ciphertext.into_bytes())?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub fn handshake(
        &mut self,
        cipher_suites: &[CipherSuite],
        session_id: Option<Vec<u8>>,
        session_ticket: Option<Vec<u8>>,
    ) -> TLSResult<Vec<u8>> {
        let mut extensions = match self.handshake_state_machine.state.as_ref().unwrap() {
            TlsState::Established(s) => {
                vec![SecureRenegotationExt::renegotiation(&s.client_verify_data).into()]
            }
            _ => vec![SecureRenegotationExt::initial().into()],
        };

        match session_ticket {
            None => extensions.push(SessionTicketExt::new().into()),
            Some(ticket) => extensions.push(SessionTicketExt::resume(ticket).into()),
        }

        let client_hello = ClientHello::new(cipher_suites, extensions, session_id);

        let start_time = Instant::now();
        self.process_message(&client_hello.into())?;

        while !self.handshake_state_machine.is_established() {
            if let TlsMessage::Alert(a) = self.next_message()? {
                println!("{:?}", a);
                return Err("Received alert during handshake".into());
            }
        }

        let elapsed = Instant::now() - start_time;
        println!("elapsed: {} seconds", elapsed.as_secs_f64());

        let state = self
            .handshake_state_machine
            .state
            .as_ref()
            .unwrap()
            .as_established()?;
        return Ok(state.session_id.clone());
    }

    #[allow(dead_code)]
    pub fn write(&mut self, bytes: &[u8]) -> TLSResult<()> {
        let ciphertext = self.conn_states.write.encrypt(ApplicationData::new(bytes.to_vec()));
        self.send_bytes(&ciphertext.into_bytes())?;
        //self.process_message(&TlsMessage::ApplicationData(bytes.to_vec()))?;
        println!("Sent AppData: {:?}", String::from_utf8_lossy(bytes));
        Ok(())
    }

    #[allow(dead_code)]
    pub fn read(&mut self) -> TLSResult<Vec<u8>> {
        loop {
            let msg = self.next_message()?;
            match msg {
                TlsMessage::ApplicationData(bytes) => {
                    return Ok(bytes);
                }
                _ => {
                    println!("{:?}", msg);
                    return Err("Received unexpected message".into());
                }
            }
        }
    }
}

/*
* TODO:
* session ticket extension
* DH cipher suites
* record layer to allow fragmentation
*
* DESIGN:
* add direction to handle method of states
*/

fn main() -> TLSResult<()> {
    env_logger::init();

    let suites: Vec<CipherSuite> = vec![RsaAes128CbcSha.into()];

    let domain = "google.com";
    //let domain = "localhost";

    let mut connection = TLSConnection::new(domain)?;
    let session_id = connection.handshake(&suites, None, None)?;

    // println!("{:?}", connection.handshake_state_machine.ctx);

    let ctx = connection.handshake_state_machine.ctx.clone();
    let session_ticket = ctx.session_tickets.keys().last().cloned();
    connection.notify_close()?;

    match session_ticket {
        Some(session_ticket) => {
            let mut connection = TLSConnection::new_with_context(domain, ctx)?;
            connection.handshake(&suites, None, Some(session_ticket.to_vec()))?;
        },
        None => {}
    }
    //connection.handshake(&suites, Some(session_id))?;

    Ok(())

    // connection.write(format!("GET / HTTP/1.1\r\nHost: {domain}\r\n\r\n").as_ref())?;
    // loop {
    //     let bytes = connection.read()?;
    //     print!("{}", String::from_utf8_lossy(&bytes));
    // }
}
