use alert::{TlsAlert, TlsAlertLevel};

#[macro_use]
pub mod macros;

mod alert;
mod ca;
mod encoding;
mod errors;
mod extensions;
mod gcm;
mod messages;
mod oid;
mod prf;
mod record;
mod session_ticket;
mod signature;
mod state_machine;
mod utils;

pub mod ciphersuite;
pub mod client;
pub mod connection;
pub mod server;
pub mod storage;

pub use extensions::MaxFragmentLength;
use messages::ClientCertificateType;

pub type TlsResult<T> = Result<T, Box<dyn std::error::Error>>;

#[derive(Debug, Clone)]
pub enum UnrecognisedServerNamePolicy {
    Alert(TlsAlertLevel),
    Ignore,
}

#[derive(Debug, Clone)]
pub enum RenegotiationPolicy {
    OnlyLegacy,
    OnlySecure,
    None,
}

#[derive(Debug, Clone, PartialEq)]
pub enum MaxFragmentLengthNegotiationPolicy {
    Reject,
    Support,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ClientAuthPolicy {
    /// Server will not send a CertificateRequest during handshake.
    NoAuth,

    // Server will send a CertificateRequest during handshake, but will accept
    // a empty ClientCertificate (and absence of CertificateVerify) message.
    // 
    // Server will send a CertificateRequest during handshake, and expects a valid
    // verifiable certificate from the client. In the case of an empty client
    // certificate or failed certificate verification, the server will send a fatal
    // handshake_failure alert.
    Auth {
        certificate_types: Vec<ClientCertificateType>,
        mandatory: bool,
    },
}

#[derive(Debug, Clone)]
pub struct TlsPolicy {
    // Google just sends a fatal decode_error rather than unrecognised_name
    pub unrecognised_server_name: UnrecognisedServerNamePolicy,

    pub renegotiation: RenegotiationPolicy,

    pub max_fragment_length_negotiation: MaxFragmentLengthNegotiationPolicy,

    pub client_auth: ClientAuthPolicy,

    pub verify_server: bool,
}

impl Default for TlsPolicy {
    fn default() -> Self {
        Self {
            unrecognised_server_name: UnrecognisedServerNamePolicy::Alert(TlsAlertLevel::Fatal),
            renegotiation: RenegotiationPolicy::OnlySecure,
            max_fragment_length_negotiation: MaxFragmentLengthNegotiationPolicy::Support,
            client_auth: ClientAuthPolicy::NoAuth,
            verify_server: false,
        }
    }
}

pub trait TlsValidateable {
    fn validate(&self, policy: &TlsPolicy) -> Result<(), TlsAlert>;
}
