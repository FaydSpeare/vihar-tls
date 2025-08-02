use alert::{TlsAlert, TlsAlertLevel};
use encoding::CodingError;
use thiserror::Error;

#[macro_use]
mod macros;

mod alert;
mod encoding;
mod extensions;
mod gcm;
mod messages;
mod prf;
mod record;
mod signature;
mod state_machine;
mod utils;

pub mod ciphersuite;
pub mod client;
pub mod connection;
pub mod server;
pub mod storage;

pub type TlsResult<T> = Result<T, Box<dyn std::error::Error>>;

#[derive(Debug, Error)]
pub enum TlsError {
    #[error("Coding error: {0}")]
    Coding(#[from] CodingError),

    #[error("TlsAlert: {0:?}")]
    Alert(TlsAlert),
}

impl From<TlsAlert> for TlsError {
    fn from(value: TlsAlert) -> Self {
        Self::Alert(value)
    }
}

#[derive(Debug, Clone)]
pub enum UnrecognisedServerNamePolicy {
    Alert(TlsAlertLevel),
    Ignore,
}

#[derive(Debug, Clone)]
pub struct ValidationPolicy {

    // Google just sends a fatal decode_error rather than unrecognised_name
    pub unrecognised_server_name: UnrecognisedServerNamePolicy,
}

impl Default for ValidationPolicy {
    fn default() -> Self {
        Self {
            unrecognised_server_name: UnrecognisedServerNamePolicy::Alert(TlsAlertLevel::Fatal),
        }
    }
}

pub trait TlsValidateable {
    fn validate(&self, policy: &ValidationPolicy) -> Result<(), TlsAlert>;
}

/*
* Not TODO:
* DH key exchange - not supported (doesn't provide forward secrecy)
* DSS not support these days. Working with openssl locally however.
* RC4 prohibited. Why?
* 3DES_EDE_CBC encryption?
*
* TODO:
* Certificate Request
* Client Certificate
* Certificate Verify
*
* RFC5116 - AEAD
* RFC5288 - AES-GCM
* RFC5289 - Stronger SHA algorithms for EC
* RFC4492 - Elliptic curve cipher suites
*
* DESIGN:
* add direction to handle method of states
*/
