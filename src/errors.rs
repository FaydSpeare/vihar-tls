use thiserror::Error;

use crate::alert::TlsAlert;

#[derive(Debug, Error)]
pub enum InvalidEncodingError {
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
    Alert(TlsAlert),
}

impl From<TlsAlert> for TlsError {
    fn from(value: TlsAlert) -> Self {
        Self::Alert(value)
    }
}
