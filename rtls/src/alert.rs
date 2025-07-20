use crate::{messages::{TLSContentType, TLSPlaintext}, TLSResult};
use num_enum::TryFromPrimitive;

#[derive(Debug, TryFromPrimitive)]
#[repr(u8)]
pub enum TLSAlertDesc {
    CloseNotify = 0,
    BadRecordMac = 20,
    RecordOverflow = 22,
    DecompressionFailure = 30,
    HandshakeFailure = 40,
    BadCertificate = 42,
    UnsupportedCertificate = 43,
    CertificateRevoked = 44,
    CertificateExpired = 45,
    CertificateUnknown = 46,
    IllegalParameter = 47,
    UnknownCa = 48,
    AccessDenied = 49,
    DecodeError = 50,
    DecryptError = 51,
    ProtocolVersion = 70,
    InsufficientSecurity = 71,
    InternalError = 80,
    UserCanceled = 90,
    NoRenegotiation = 100,
    UnsupportedExtension = 110,
}

#[derive(Debug, TryFromPrimitive)]
#[repr(u8)]
pub enum TLSAlertLevel {
    Warning = 1,
    Fatal = 2,
}

#[derive(Debug)]
pub struct TLSAlert {
    level: TLSAlertLevel,
    description: TLSAlertDesc,
}

impl TLSAlert {
    pub fn new(level: TLSAlertLevel, description: TLSAlertDesc) -> Self {
        Self { level, description }
    }
}

impl From<TLSAlert> for TLSPlaintext {
    fn from(value: TLSAlert) -> Self {
        let bytes: Vec<u8> = vec![value.level as u8, value.description as u8]; 
        TLSPlaintext::new(TLSContentType::Alert, bytes)
    }
}

pub fn try_parse_alert(buf: &[u8]) -> TLSResult<TLSAlert> {
    let alert = TLSAlert {
        level: TLSAlertLevel::try_from(buf[0])?,
        description: TLSAlertDesc::try_from(buf[1])?,
    };
    Ok(alert)
}
