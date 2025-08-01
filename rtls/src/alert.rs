use crate::{
    encoding::{CodingError, Reader, TlsCodable},
    messages::{TLSContentType, TlsHandshake, TlsPlaintext},
};

tls_codable_enum! {
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
}

tls_codable_enum! {
    #[repr(u8)]
    pub enum TLSAlertLevel {
        Warning = 1,
        Fatal = 2,
    }
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

impl TlsCodable for TLSAlert {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        self.level.write_to(bytes);
        self.description.write_to(bytes);
    }
    fn read_from(reader: &mut Reader) -> Result<Self, CodingError> {
        Ok(Self {
            level: TLSAlertLevel::read_from(reader)?,
            description: TLSAlertDesc::read_from(reader)?,
        })
    }
}

impl From<TLSAlert> for TlsPlaintext {
    fn from(value: TLSAlert) -> Self {
        TlsPlaintext::new(TLSContentType::Alert, value.get_encoding())
    }
}
