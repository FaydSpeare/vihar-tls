use alert::{TlsAlert, TlsAlertLevel};

#[macro_use]
pub mod macros;

mod alert;
mod encoding;
mod errors;
mod extensions;
mod gcm;
mod messages;
mod prf;
mod record;
mod signature;
mod state_machine;
mod utils;
mod session_ticket;

pub mod ciphersuite;
pub mod client;
pub mod connection;
pub mod server;
pub mod storage;

pub use extensions::MaxFragmentLength;

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

#[derive(Debug, Clone)]
pub struct TlsPolicy {
    // Google just sends a fatal decode_error rather than unrecognised_name
    pub unrecognised_server_name: UnrecognisedServerNamePolicy,

    pub renegotiation: RenegotiationPolicy,

    pub max_fragment_length_negotiation: MaxFragmentLengthNegotiationPolicy,
}

impl Default for TlsPolicy {
    fn default() -> Self {
        Self {
            unrecognised_server_name: UnrecognisedServerNamePolicy::Alert(TlsAlertLevel::Fatal),
            renegotiation: RenegotiationPolicy::OnlySecure,
            max_fragment_length_negotiation: MaxFragmentLengthNegotiationPolicy::Support,
        }
    }
}

pub trait TlsValidateable {
    fn validate(&self, policy: &TlsPolicy) -> Result<(), TlsAlert>;
}
