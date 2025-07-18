use enum_dispatch::enum_dispatch;
use log::info;
use sha2::{Digest, Sha256};

use crate::{
    TLSResult,
    ciphersuite::get_cipher_suite,
    connection::{ConnState, ConnStateRef, InitialConnState, SecureConnState, SecurityParams},
    prf,
    record::{
        ApplicationData, ChangeCipherSpec, ClientKeyExchange, Finished, TLSCiphertext,
        TLSHandshake, TLSHandshakeType, TlsMessage, ToBytes, handshake_bytes,
    },
};

pub struct TlsStateMachine {
    state: Option<TlsState>,
}

impl TlsStateMachine {
    pub fn step(&mut self, msg: &TlsMessage) -> TLSResult<Vec<TLSCiphertext>> {
        let (new_state, ciphertexts) = self.state.take().unwrap().handle(msg)?;
        self.state = Some(new_state);
        Ok(ciphertexts)
    }

    pub fn new() -> Self {
        Self {
            state: Some(
                AwaitingClientHelloState {
                    read: ConnState::Initial(InitialConnState::default()),
                    write: ConnState::Initial(InitialConnState::default()),
                }
                .into(),
            ),
        }
    }

    pub fn is_established(&self) -> bool {
        match self.state.as_ref().unwrap() {
            TlsState::Established(_) => true,
            _ => false,
        }
    }

    pub fn read_state(&self) -> ConnStateRef<'_> {
        self.state.as_ref().unwrap().read_state()
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

impl TlsState {
    pub fn read_state(&self) -> ConnStateRef<'_> {
        match self {
            Self::AwaitingClientHello(s) => s.read.as_ref(),
            Self::AwaitingServerHello(s) => s.read.as_ref(),
            Self::AwaitingServerCertificate(s) => s.read.as_ref(),
            Self::AwaitingServerHelloDone(s) => s.read.as_ref(),
            Self::AwaitingServerChangeCipher(s) => s.read.as_ref(),
            Self::AwaitingServerFinished(s) => ConnStateRef::Secure(&s.read),
            Self::Established(s) => ConnStateRef::Secure(&s.read),
        }
    }
}

#[enum_dispatch(TlsState)]
pub trait HandleRecord {
    fn handle(self, msg: &TlsMessage) -> TLSResult<(TlsState, Vec<TLSCiphertext>)>;
}

#[derive(Debug)]
pub struct AwaitingClientHelloState {
    read: ConnState,
    write: ConnState,
}

impl HandleRecord for AwaitingClientHelloState {
    fn handle(mut self, msg: &TlsMessage) -> TLSResult<(TlsState, Vec<TLSCiphertext>)> {
        if let TlsMessage::Handshake(TLSHandshake::ClientHello(hello)) = msg {
            info!("Sent ClientHello");

            let ch_ciphertext = self.write.encrypt(hello.clone());

            return Ok((
                AwaitingServerHelloState {
                    read: self.read,
                    write: self.write,
                    handshakes: hello.to_bytes(),
                    client_random: hello.random.as_bytes(),
                    session_id: hello.session_id.clone(),
                }
                .into(),
                vec![ch_ciphertext],
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
    fn handle(mut self, msg: &TlsMessage) -> TLSResult<(TlsState, Vec<TLSCiphertext>)> {
        if let TlsMessage::Handshake(TLSHandshake::ServerHello(value)) = msg {
            info!("Received ServerHello");

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
    fn handle(mut self, msg: &TlsMessage) -> TLSResult<(TlsState, Vec<TLSCiphertext>)> {
        if let TlsMessage::Handshake(TLSHandshake::Certificates(certs)) = msg {
            info!("Received ServerCertificate");

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
    fn handle(mut self, msg: &TlsMessage) -> TLSResult<(TlsState, Vec<TLSCiphertext>)> {
        if let TlsMessage::Handshake(TLSHandshake::ServerHelloDone) = msg {
            info!("Received ServerHelloDone");

            self.handshakes
                .extend_from_slice(&handshake_bytes(TLSHandshakeType::ServerHelloDone, &[]));

            let client_key_exchange = ClientKeyExchange::new(&self.enc_pre_master_secret);
            self.handshakes
                .extend_from_slice(&client_key_exchange.to_bytes());
            let cke_ciphertext = self.write.encrypt(client_key_exchange);

            let change_cipher_spec = ChangeCipherSpec::new();
            let ccs_ciphertext = self.write.encrypt(change_cipher_spec);

            let ciphersuite = get_cipher_suite(u16::from_be_bytes(self.cipher_suite))?;
            let params = SecurityParams {
                client_random: self.client_random,
                server_random: self.server_random,
                master_secret: self.master_secret,
                mac_algorithm: ciphersuite.params().mac_algorithm,
                enc_algorithm: ciphersuite.params().enc_algorithm,
            };
            let keys = params.derive_keys();
            let mut write = SecureConnState::new(params, keys.client_enc_key, keys.client_mac_key);

            let seed = Sha256::digest(&self.handshakes).to_vec();
            let verify_data = prf::prf_sha256(&self.master_secret, b"client finished", &seed, 12);
            let finished = Finished::new(verify_data.clone());
            self.handshakes.extend_from_slice(&finished.to_bytes());
            let f_ciphertext = write.encrypt(finished.into());

            info!("Sent ClientKeyExchange");
            info!("Sent ChangeCipherSuite");
            info!("Sent ClientFinished");
            return Ok((
                AwaitingServerChangeCipherState {
                    read: self.read,
                    write,
                    secure_renegotiation: self.secure_renegotiation,
                }
                .into(),
                vec![cke_ciphertext, ccs_ciphertext, f_ciphertext],
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
    fn handle(self, msg: &TlsMessage) -> TLSResult<(TlsState, Vec<TLSCiphertext>)> {
        if let TlsMessage::ChangeCipherSuite = msg {
            info!("Received ChangeCipherSuite");

            let keys = self.write.params.derive_keys();
            let read = SecureConnState::new(
                self.write.params.clone(),
                keys.server_enc_key,
                keys.server_mac_key,
            );

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
    fn handle(self, msg: &TlsMessage) -> TLSResult<(TlsState, Vec<TLSCiphertext>)> {
        if let TlsMessage::Handshake(TLSHandshake::Finished(finished)) = msg {
            info!("Received ServerFinished");
            info!("Handshake complete!");

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
    fn handle(mut self, msg: &TlsMessage) -> TLSResult<(TlsState, Vec<TLSCiphertext>)> {
        if let TlsMessage::ApplicationData(bytes) = msg {
            let app_data = ApplicationData::new(bytes.clone());
            let ciphertext = self.write.encrypt(app_data.into());
            return Ok((self.into(), vec![ciphertext]));
        }
        panic!("invalid transition");
    }
}
