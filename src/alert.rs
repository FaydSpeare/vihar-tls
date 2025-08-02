use crate::{
    encoding::{CodingError, Reader, TlsCodable},
    messages::{TlsContentType, TlsPlaintext},
};

tls_codable_enum! {
    #[repr(u8)]
    pub enum TlsAlertDesc {
        CloseNotify = 0,
        UnexpectedMessage = 10,
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
        UnrecognisedName = 112 // SNI
    }
}

tls_codable_enum! {
    #[repr(u8)]
    pub enum TlsAlertLevel {
        Warning = 1,
        Fatal = 2,
    }
}

#[derive(Debug)]
pub struct TlsAlert {
    level: TlsAlertLevel,
    description: TlsAlertDesc,
}

impl TlsAlert {
    pub fn new(level: TlsAlertLevel, description: TlsAlertDesc) -> Self {
        Self { level, description }
    }
    pub fn fatal(description: TlsAlertDesc) -> Self {
        Self {
            level: TlsAlertLevel::Fatal,
            description,
        }
    }

    pub fn warning(description: TlsAlertDesc) -> Self {
        Self {
            level: TlsAlertLevel::Warning,
            description,
        }
    }
}

impl TlsCodable for TlsAlert {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        self.level.write_to(bytes);
        self.description.write_to(bytes);
    }
    fn read_from(reader: &mut Reader) -> Result<Self, CodingError> {
        Ok(Self {
            level: TlsAlertLevel::read_from(reader)?,
            description: TlsAlertDesc::read_from(reader)?,
        })
    }
}

impl TryFrom<TlsAlert> for TlsPlaintext {
    type Error = CodingError;

    fn try_from(value: TlsAlert) -> Result<Self, Self::Error> {
        TlsPlaintext::new(TlsContentType::Alert, value.get_encoding())
    }
}
