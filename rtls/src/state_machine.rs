use enum_dispatch::enum_dispatch;

use crate::record::{ClientHello, ServerHello};

enum TlsHandshake {
    ClientHello(ClientHello), 
    ServerHello(ServerHello)
}

enum TlsMessage {
    Handshake(TlsHandshake),
    ChangeCipherSpec,
    Alert,
    ApplicationData(Vec<u8>)
}

// RequestCertificate optionally sent aftee ServerKeyExchange if present otherwise after ServerCeritificate 

#[enum_dispatch]
#[derive(Debug)]
enum TlsState {
    Uninitialised(UninitialisedState),
    AwaitingServerHello(AwaitingServerHelloState),
    // AwaitingServerCertificate,
    // AwaitingServerHelloDone,
    // AwaitingClientKeyExchange,
    // AwaitingClientChangeCipherSpec,
    // AwaitingClientFinished,
    // AwaitingServerChangeCipherSpec,
    // AwaitingServerFinished,
    // Established

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
    pub fn new() -> Self {
        UninitialisedState::new().into()
    }
}

#[enum_dispatch(TlsState)]
trait HandleRecord {
    fn handle(self, msg: TlsMessage) -> TlsState;
}

#[derive(Debug)]
struct UninitialisedState {}

impl UninitialisedState {
    fn new() -> Self {
        Self {}
    }
}

impl HandleRecord for UninitialisedState {
    fn handle(self, msg: TlsMessage) -> TlsState {
        if let TlsMessage::Handshake(TlsHandshake::ClientHello(value)) = msg {
            return AwaitingServerHelloState::new(&value.session_id).into()
        }
        panic!("nope");
    }
}

#[derive(Debug)]
struct AwaitingServerHelloState {
    session_id: Vec<u8>
}

impl AwaitingServerHelloState {
    fn new(session_id: &[u8]) -> Self {
        Self { session_id: session_id.to_vec() }
    }
}

impl HandleRecord for AwaitingServerHelloState {
    fn handle(self, msg: TlsMessage) -> TlsState {
        unimplemented!()
    }
}

