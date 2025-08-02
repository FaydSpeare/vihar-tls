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

pub mod client;
pub mod server;
pub mod ciphersuite;
pub mod connection;
pub mod storage;

pub type TlsResult<T> = Result<T, Box<dyn std::error::Error>>;

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

// server name
// cipher suite selection
// extended master secret
// ALPN
// secure renegotiation
// session tickets
//
