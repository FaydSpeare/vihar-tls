use thiserror::Error;

use crate::alert::Alert;

#[derive(Debug, Error)]
pub enum InvalidEncodingError {
    #[error("Invalid session ticket mac")]
    InvalidSessionTicketMac,

    #[error("Invalid extension length")]
    InvalidExtensionLength,

    #[error("Shorter length required (expected <= {0}, actual = {1})")]
    LengthTooLarge(usize, usize),

    #[error("Longer length required. (expected >= {0}, actual = {1})")]
    LengthTooSmall(usize, usize),
}

#[derive(Debug, Error)]
pub enum DecodingError {
    #[error("Need more data to finish decoding")]
    RanOutOfData,

    #[error("Invalid decoding: {0}")]
    InvalidEncoding(#[from] InvalidEncodingError),
}

#[derive(Debug, Error)]
pub enum TlsError {
    #[error("Decoding error: {0}")]
    Decoding(#[from] DecodingError),

    #[error("TlsAlert: {0:?}")]
    Alert(Alert),

    #[error("Connection has been closed")]
    ConnectionClosed,
}

impl From<Alert> for TlsError {
    fn from(value: Alert) -> Self {
        Self::Alert(value)
    }
}

#[derive(Debug, Error)]
pub enum AnError {
    #[error("Failed to parse certificate")]
    FailedToParseCertificate,
}
