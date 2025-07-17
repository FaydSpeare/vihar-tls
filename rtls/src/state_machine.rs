#![allow(unused)]
use enum_dispatch::enum_dispatch;
use sha2::{Digest, Sha256};

use crate::{
    TLSResult,
    ciphersuite::{CipherSuite, get_cipher_suite},
    connection::{ConnState, InitialConnState, SecureConnState, SecurityParams},
    extensions::Extension,
    prf,
    record::{
        ChangeCipherSpec, ClientHello, ClientKeyExchange, Finished, IntoBytes, Random, ServerHello,
        TLSHandshake, TLSHandshakeType, TLSRecord, ToBytes, handshake_bytes,
    },
};

pub struct TlsStateMachine {
    state: Option<TlsState>,
}

impl TlsStateMachine {
    pub fn step(&mut self, msg: &TLSRecord) -> TLSResult<Vec<TLSRecord>> {
        let (new_state, messages) = self.state.take().unwrap().handle(msg)?;
        self.state = Some(new_state);
        Ok(messages)
    }

    pub fn new(client_hello: &ClientHello) -> Self {
        Self {
            state: Some(
                AwaitingServerHelloState {
                    read: ConnState::Initial(InitialConnState::default()),
                    write: ConnState::Initial(InitialConnState::default()),
                    handshakes: client_hello.to_bytes(),
                    session_id: client_hello.session_id.clone(),
                    client_random: client_hello.random.as_bytes(),
                }
                .into(),
            ),
        }
    }
}

// RequestCertificate optionally sent aftee ServerKeyExchange if present otherwise after ServerCeritificate
//

#[enum_dispatch]
#[derive(Debug)]
pub enum TlsState {
    AwaitingClientHello(AwaitingClientHelloState),
    AwaitingServerHello(AwaitingServerHelloState),
    AwaitingServerCertificate(AwaitingServerCertificateState),
    AwaitingServerHelloDone(AwaitingServerHelloDoneState),
    // AwaitingClientKeyExchange,
    // AwaitingClientChangeCipherSpec,
    // AwaitingClientFinished,
    AwaitingServerChangeCipher(AwaitingServerChangeCipherState),
    AwaitingServerFinished(AwaitingServerFinishedState),
    Established(EstablishedState),
    /*
    ServerHelloProcessed, // here we can accept any of the below 3
    // ServerCertificatesProcessed,
    // ServerKeyExchanged
    // ClientCertificateRequested
    ServerHelloDoneProcessed,
    // ClientCertificateProcessed
    ClientKeyExchanged, // this state would be skipped unless waiting for CertificateVerify
    // CeritificateVerifySent,
    //
    ReadyToChangeCipherSpec,

    ClientChangedCipherSpec,
    ClientFinished,
    ServerChangedCipherSpec,
    ServerFinished,

    ClientChangedCipherSpecAbbr,
    ClientFinishedAbbr,
    ServerChangedCipherSpecAbbr,
    ServerFinishedAbbr,

    Established
    */
}

#[enum_dispatch(TlsState)]
pub trait HandleRecord {
    fn handle(self, msg: &TLSRecord) -> TLSResult<(TlsState, Vec<TLSRecord>)>;
}

#[derive(Debug)]
pub struct AwaitingClientHelloState {
    read: ConnState,
    write: ConnState,
}

impl HandleRecord for AwaitingClientHelloState {
    fn handle(mut self, msg: &TLSRecord) -> TLSResult<(TlsState, Vec<TLSRecord>)> {
        if let TLSRecord::Handshake(TLSHandshake::ClientHello(hello)) = msg {
            println!("Transitioning to AwaitingServerHello");

            return Ok((
                AwaitingServerHelloState {
                    read: self.read,
                    write: self.write,
                    handshakes: hello.to_bytes(),
                    client_random: hello.random.as_bytes(),
                    session_id: hello.session_id.clone(),
                }
                .into(),
                vec![],
            ));
        }
        panic!("invalid transition");
    }
}

#[derive(Debug)]
pub struct AwaitingServerHelloState {
    read: ConnState,
    write: ConnState,
    handshakes: Vec<u8>,
    client_random: [u8; 32],
    session_id: Vec<u8>,
}

impl HandleRecord for AwaitingServerHelloState {
    fn handle(mut self, msg: &TLSRecord) -> TLSResult<(TlsState, Vec<TLSRecord>)> {
        if let TLSRecord::Handshake(TLSHandshake::ServerHello(value)) = msg {
            println!("Transitioning to AwaitingServerCertificate");

            self.handshakes.extend_from_slice(&value.to_bytes());
            return Ok((
                AwaitingServerCertificateState {
                    read: self.read,
                    write: self.write,
                    handshakes: self.handshakes,
                    client_random: self.client_random,
                    server_random: value.random.as_bytes(),
                    secure_renegotiation: value.supports_secure_renegotiation(),
                    cipher_suite: value.cipher_suite.encode(),
                }
                .into(),
                vec![],
            ));
        }
        panic!("invalid transition");
    }
}

#[derive(Debug)]
pub struct AwaitingServerCertificateState {
    read: ConnState,
    write: ConnState,
    handshakes: Vec<u8>,
    client_random: [u8; 32],
    server_random: [u8; 32],
    cipher_suite: [u8; 2],
    secure_renegotiation: bool,
}

impl HandleRecord for AwaitingServerCertificateState {
    fn handle(mut self, msg: &TLSRecord) -> TLSResult<(TlsState, Vec<TLSRecord>)> {
        if let TLSRecord::Handshake(TLSHandshake::Certificates(certs)) = msg {
            println!("Transitioning to AwaitingServerHelloDone");

            let (pre_master_secret, enc_pre_master_secret) =
                crate::encrypt_pre_master_secret(&certs.list[0].bytes)?;

            let master_secret: [u8; 48] = crate::prf::prf_sha256(
                &pre_master_secret,
                b"master secret",
                &[self.client_random.as_slice(), self.server_random.as_slice()].concat(),
                48,
            )
            .try_into()
            .unwrap();

            self.handshakes.extend_from_slice(&certs.to_bytes());
            return Ok((
                AwaitingServerHelloDoneState {
                    read: self.read,
                    write: self.write,
                    handshakes: self.handshakes,
                    master_secret,
                    enc_pre_master_secret,
                    client_random: self.client_random,
                    server_random: self.server_random,
                    secure_renegotiation: self.secure_renegotiation,
                    cipher_suite: self.cipher_suite,
                }
                .into(),
                vec![],
            ));
        }
        panic!("invalid transition");
    }
}

#[derive(Debug)]
pub struct AwaitingServerHelloDoneState {
    read: ConnState,
    write: ConnState,
    handshakes: Vec<u8>,
    client_random: [u8; 32],
    server_random: [u8; 32],
    cipher_suite: [u8; 2],
    secure_renegotiation: bool,
    master_secret: [u8; 48],
    enc_pre_master_secret: Vec<u8>,
}

impl HandleRecord for AwaitingServerHelloDoneState {
    fn handle(mut self, msg: &TLSRecord) -> TLSResult<(TlsState, Vec<TLSRecord>)> {
        if let TLSRecord::Handshake(TLSHandshake::ServerHelloDone) = msg {
            println!("Transitioning to AwaitingServerHelloDone");

            self.handshakes
                .extend_from_slice(&handshake_bytes(TLSHandshakeType::ServerHelloDone, &[]));

            let client_key_exchange = ClientKeyExchange::new(&self.enc_pre_master_secret);
            self.handshakes
                .extend_from_slice(&client_key_exchange.to_bytes());

            let change_cipher_spec = ChangeCipherSpec::new();
            println!("SM Master: {:?}", &self.master_secret);

            // Update write state
            let ciphersuite = get_cipher_suite(u16::from_be_bytes(self.cipher_suite))?;
            let params = SecurityParams {
                client_random: self.client_random,
                server_random: self.server_random,
                master_secret: self.master_secret,
                mac_algorithm: ciphersuite.params().mac_algorithm,
                enc_algorithm: ciphersuite.params().enc_algorithm,
            };
            let keys = params.derive_keys();
            let write = SecureConnState::new(
                params,
                keys.client_enc_key,
                keys.client_mac_key,
            );

            let seed = Sha256::digest(&self.handshakes).to_vec();
            let verify_data = prf::prf_sha256(&self.master_secret, b"client finished", &seed, 12);
            let finished = Finished::new(verify_data.clone());
            self.handshakes.extend_from_slice(&finished.to_bytes());
            println!("SM VerifyData: {:?}", verify_data);

            return Ok((
                AwaitingServerChangeCipherState {
                    read: self.read,
                    write,
                    secure_renegotiation: self.secure_renegotiation,
                }
                .into(),
                vec![
                    client_key_exchange.into(),
                    change_cipher_spec.into(),
                    finished.into(),
                ],
            ));
        }
        panic!("invalid transition");
    }
}
#[derive(Debug)]
pub struct AwaitingServerChangeCipherState {
    read: ConnState,
    write: SecureConnState,
    secure_renegotiation: bool,
}

impl HandleRecord for AwaitingServerChangeCipherState {
    fn handle(mut self, msg: &TLSRecord) -> TLSResult<(TlsState, Vec<TLSRecord>)> {
        println!("Transitioning to AwaitingServerFinished");

        if let TLSRecord::ChangeCipherSuite = msg {

            // Update read state
            let keys = self.write.params.derive_keys();
            let read = SecureConnState::new(self.write.params.clone(), keys.server_enc_key, keys.server_mac_key);

            return Ok((
                AwaitingServerFinishedState {
                    read,
                    write: self.write,
                    secure_renegotiation: self.secure_renegotiation,
                }
                .into(),
                vec![],
            ));
        }
        panic!("invalid transition");
    }
}

#[derive(Debug)]
pub struct AwaitingServerFinishedState {
    read: SecureConnState,
    write: SecureConnState,
    secure_renegotiation: bool,
}

impl HandleRecord for AwaitingServerFinishedState {
    fn handle(mut self, msg: &TLSRecord) -> TLSResult<(TlsState, Vec<TLSRecord>)> {
        println!("Transitioning to Established");

        if let TLSRecord::Handshake(TLSHandshake::Finished(finished)) = msg {

            return Ok((
                EstablishedState {
                    read: self.read,
                    write: self.write,
                    secure_renegotiation: self.secure_renegotiation,
                    verify_data: finished.verify_data.clone(),
                }
                .into(),
                vec![],
            ));
        }
        panic!("invalid transition");
    }
}

#[derive(Debug)]
pub struct EstablishedState {
    read: SecureConnState,
    write: SecureConnState,
    secure_renegotiation: bool,
    verify_data: Vec<u8>,
}

impl HandleRecord for EstablishedState {
    fn handle(mut self, msg: &TLSRecord) -> TLSResult<(TlsState, Vec<TLSRecord>)> {
        if let TLSRecord::Handshake(TLSHandshake::ServerHelloDone) = msg {
            unimplemented!()
        }
        panic!("invalid transition");
    }
}
