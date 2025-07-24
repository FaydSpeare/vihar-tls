use alert::{TLSAlert, TLSAlertDesc, TLSAlertLevel};
use env_logger;
use extensions::{ALPNExt, ExtendedMasterSecretExt, SecureRenegotationExt, SessionTicketExt};
use log::{error, info, trace};
use record::RecordLayer;
use state_machine::{
    ConnStates, TlsAction, TlsContext, TlsEntity, TlsHandshakeStateMachine, TlsState,
};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Instant;
use thiserror::Error;

mod alert;
mod ciphersuite;
mod connection;
mod extensions;
mod messages;
mod prf;
mod record;
mod signature;
mod state_machine;
mod utils;
mod gcm;

use ciphersuite::{
    CipherSuite, DheDssAes128CbcSha, DheRsaAes128CbcSha, DheRsaAes128CbcSha256, DheRsaAes128GcmSha256, RsaAes128CbcSha, RsaAes128CbcSha256, RsaAes128GcmSha256, RsaAes256CbcSha, RsaAes256CbcSha256, RsaAes256GcmSha384
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

struct TLSConnection {
    stream: TcpStream,
    pub handshake_state_machine: TlsHandshakeStateMachine,
    conn_states: ConnStates,
    record_layer: RecordLayer,
}

impl TLSConnection {
    pub fn new(domain: &str) -> TLSResult<Self> {
        info!("Establishing TLS with {}", domain);
        let port = if domain == "localhost" { "4433" } else { "443" };
        Ok(Self {
            stream: TcpStream::connect(format!("{domain}:{port}"))?,
            handshake_state_machine: TlsHandshakeStateMachine::new(),
            conn_states: ConnStates::new(),
            record_layer: RecordLayer::new(),
        })
    }

    pub fn new_with_context(domain: &str, ctx: TlsContext) -> TLSResult<Self> {
        info!("Establishing TLS with {}", domain);
        let port = if domain == "localhost" { "4433" } else { "443" };
        Ok(Self {
            stream: TcpStream::connect(format!("{domain}:{port}"))?,
            handshake_state_machine: TlsHandshakeStateMachine::from_context(ctx),
            conn_states: ConnStates::new(),
            record_layer: RecordLayer::new(),
        })
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

    fn next_message(&mut self) -> TLSResult<TlsMessage> {
        loop {
            if let Ok(msg) = self
                .record_layer
                .try_parse_message(&mut self.conn_states.read)
            {
                match &msg {
                    TlsMessage::Handshake(_) | TlsMessage::ChangeCipherSpec => {
                        self.process_message(&msg)?
                    }
                    _ => {}
                }
                return Ok(msg);
            }

            let mut buf = [0u8; 8096];
            let mut n = self.stream.read(&mut buf)?;
            while n == 0 {
                n = self.stream.read(&mut buf)?;
            }

            trace!("Received {} bytes", n);
            self.record_layer.feed(&buf[..n]);
        }
    }

    fn send_bytes(&mut self, bytes: &[u8]) -> TLSResult<()> {
        self.stream.write_all(bytes)?;
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

        //extensions.push(ExtendedMasterSecretExt::new().into());
        extensions.push(ALPNExt::new(vec!["http/1.1".to_string()]).into());

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
        let ciphertext = self
            .conn_states
            .write
            .encrypt(ApplicationData::new(bytes.to_vec()));
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

    pub fn notify_close(&mut self) -> TLSResult<()> {
        let alert = TLSAlert::new(TLSAlertLevel::Warning, TLSAlertDesc::CloseNotify);
        let ciphertext = self.conn_states.write.encrypt(alert);
        self.send_bytes(&ciphertext.into_bytes())?;
        Ok(())
    }
}

/*
* Not TODO:
* DH key exchange - not supported (doesn't provide forward secrecy)
* DSS not support these days. Working with openssl locally however.
* RC4 prohibited. Why?
*
* TODO:
* 3DES_EDE_CBC encryption?
* Certificate Request
* Client Certificate
* Certificate Verify
*
* avoid duplicate hex codes for extensions
*
* RFC5116 - AEAD
* RFC5288 - AES-GCM
* RFC5289 - Stronger SHA algorithms for EC
* RFC4492 - Elliptic curve cipher suites
*
* DESIGN:
* add direction to handle method of states
*/

fn main() -> TLSResult<()> {
    env_logger::init();

    //let x = gcm::gf_mul(3, 1 << 51);

    //gcm::main();
    //return Ok(());

    let suites: Vec<CipherSuite> = vec![
        //RsaAes128CbcSha.into(),
        //DheRsaAes128CbcSha.into(),
        //DheDssAes128CbcSha.into()
        // DheRsaAes128CbcSha256.into(),
        // DhRsaAes128CbcSha.into()
        //RsaAes128GcmSha256.into(),
        RsaAes256GcmSha384.into(),
        //DheRsaAes128GcmSha256.into()
    ];

    let domain = "facebook.com";
    //let domain = "localhost";

    let mut connection = TLSConnection::new(domain)?;
    let session_id = connection.handshake(&suites, None, None)?;
    let ctx = connection.handshake_state_machine.ctx.clone();

    // println!("{:?}", connection.handshake_state_machine.ctx);

    //let session_ticket = ctx.session_tickets.keys().last().cloned();

    //match session_ticket {
    //    Some(session_ticket) => {
    //        connection.notify_close()?;
    //        connection = TLSConnection::new_with_context(domain, ctx)?;
    //        connection.handshake(&suites, None, Some(session_ticket.to_vec()))?;
    //    }
    //    None => {}
    //}

    let mut connection = TLSConnection::new_with_context(domain, ctx)?;
    connection.handshake(&suites, Some(session_id), None)?;

    let msg = connection.next_message()?;
    println!("{:?}", msg);

    Ok(())

    //connection.write(b"HEY")?;
    //connection.write(format!("GET / HTTP/1.1\r\nHost: {domain}\r\n\r\n").as_ref())?;
    //loop {
    //    let bytes = connection.read()?;
    //    print!("{}", String::from_utf8_lossy(&bytes));
    //}
}
