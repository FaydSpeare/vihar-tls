use crate::{
    encoding::{Reader, TlsCodable},
    errors::DecodingError,
    messages::{TlsContentType, TlsPlaintext},
};

tls_codable_enum! {
    #[repr(u8)]
    pub enum AlertDesc {
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
    pub enum AlertLevel {
        Warning = 1,
        Fatal = 2,
    }
}

#[derive(Debug, Clone)]
pub struct Alert {
    pub level: AlertLevel,
    pub description: AlertDesc,
}

impl Alert {
    pub fn new(level: AlertLevel, description: AlertDesc) -> Self {
        Self { level, description }
    }
    pub fn fatal(description: AlertDesc) -> Self {
        Self {
            level: AlertLevel::Fatal,
            description,
        }
    }

    pub fn warning(description: AlertDesc) -> Self {
        Self {
            level: AlertLevel::Warning,
            description,
        }
    }

    pub fn is_fatal(&self) -> bool {
        self.level == AlertLevel::Fatal
    }

    pub fn is_close_notification(&self) -> bool {
        self.description == AlertDesc::CloseNotify
    }
}

impl TlsCodable for Alert {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        self.level.write_to(bytes);
        self.description.write_to(bytes);
    }
    fn read_from(reader: &mut Reader) -> Result<Self, DecodingError> {
        Ok(Self {
            level: AlertLevel::read_from(reader)?,
            description: AlertDesc::read_from(reader)?,
        })
    }
}

impl TryFrom<Alert> for TlsPlaintext {
    type Error = DecodingError;

    fn try_from(value: Alert) -> Result<Self, Self::Error> {
        TlsPlaintext::new(TlsContentType::Alert, value.get_encoding())
    }
}
