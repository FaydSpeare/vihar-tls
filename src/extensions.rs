use log::{error, warn};
use std::fmt::Debug;

use crate::encoding::{
    CodingError, LengthPrefixWriter, LengthPrefixedVec, MaybeEmpty, NonEmpty, Reader,
    Reconstrainable, TlsCodable,
};

type UnknownExtensionBytes = LengthPrefixedVec<u16, u8, MaybeEmpty>;

#[derive(Debug, Clone)]
pub enum Extension {
    SecureRenegotiation(SecureRenegotationExt),
    SignatureAlgorithms(SignatureAlgorithmsExt),
    SessionTicket(SessionTicketExt),
    ExtendedMasterSecret(ExtendedMasterSecretExt),
    ALPN(ALPNExt),
    Unknown(u16, UnknownExtensionBytes),
}

impl TlsCodable for Extension {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        match self {
            Self::SecureRenegotiation(ext) => ext.write_to(bytes),
            Self::SignatureAlgorithms(ext) => ext.write_to(bytes),
            Self::SessionTicket(ext) => ext.write_to(bytes),
            Self::ExtendedMasterSecret(ext) => ext.write_to(bytes),
            Self::ALPN(ext) => ext.write_to(bytes),
            Self::Unknown(ext_type, ext) => {
                ext_type.write_to(bytes);
                ext.write_to(bytes)
            }
        }
    }
    fn read_from(reader: &mut Reader) -> Result<Self, CodingError> {
        let ext_type = u16::read_from(reader)?;
        let ext: Extension = match ext_type {
            SignatureAlgorithmsExt::TYPE => SignatureAlgorithmsExt::read_from(reader)?.into(),
            SecureRenegotationExt::TYPE => SecureRenegotationExt::read_from(reader)?.into(),
            SessionTicketExt::TYPE => SessionTicketExt::read_from(reader)?.into(),
            ExtendedMasterSecretExt::TYPE => ExtendedMasterSecretExt::read_from(reader)?.into(),
            ALPNExt::TYPE => ALPNExt::read_from(reader)?.into(),
            ext_type => {
                warn!("unknown extension: {}", ext_type);
                Self::Unknown(ext_type, UnknownExtensionBytes::read_from(reader)?)
            }
        };
        Ok(ext)
    }
}

impl From<SecureRenegotationExt> for Extension {
    fn from(value: SecureRenegotationExt) -> Self {
        Self::SecureRenegotiation(value)
    }
}

impl From<SignatureAlgorithmsExt> for Extension {
    fn from(value: SignatureAlgorithmsExt) -> Self {
        Self::SignatureAlgorithms(value)
    }
}

impl From<SessionTicketExt> for Extension {
    fn from(value: SessionTicketExt) -> Self {
        Self::SessionTicket(value)
    }
}

impl From<ExtendedMasterSecretExt> for Extension {
    fn from(value: ExtendedMasterSecretExt) -> Self {
        Self::ExtendedMasterSecret(value)
    }
}

impl From<ALPNExt> for Extension {
    fn from(value: ALPNExt) -> Self {
        Self::ALPN(value)
    }
}

#[derive(Debug, Clone)]
pub struct Extensions(pub Option<LengthPrefixedVec<u16, Extension, NonEmpty>>);

impl Extensions {
    pub fn new(extensions: Vec<Extension>) -> Result<Self, CodingError> {
        if extensions.len() == 0 {
            return Ok(Self::empty());
        }
        Ok(Self(Some(extensions.try_into()?)))
    }

    pub fn empty() -> Self {
        Self(None)
    }

    pub fn includes_secure_renegotiation(&self) -> bool {
        match &self.0 {
            None => false,
            Some(extensions) => extensions
                .iter()
                .any(|x| matches!(x, Extension::SecureRenegotiation(_))),
        }
    }

    pub fn includes_extended_master_secret(&self) -> bool {
        match &self.0 {
            None => false,
            Some(extensions) => extensions
                .iter()
                .any(|x| matches!(x, Extension::ExtendedMasterSecret(_))),
        }
    }

    pub fn includes_session_ticket(&self) -> bool {
        match &self.0 {
            None => false,
            Some(extensions) => extensions
                .iter()
                .any(|x| matches!(x, Extension::SessionTicket(_))),
        }
    }

    pub fn get_session_ticket(&self) -> Option<Vec<u8>> {
        match &self.0 {
            None => None,
            Some(extensions) => extensions.iter().find_map(|ext| {
                if let Extension::SessionTicket(SessionTicketExt::Resumption(ticket)) = ext {
                    Some(ticket.to_vec())
                } else {
                    None
                }
            }),
        }
    }
}

impl TlsCodable for Extensions {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        if let Some(extensions) = &self.0 {
            extensions.write_to(bytes);
        }
    }
    fn read_from(reader: &mut Reader) -> Result<Self, CodingError> {
        if reader.is_consumed() {
            return Ok(Self(None));
        }

        let extensions_len = u16::read_from(reader)?.into();
        let mut sub_reader = reader.consume(extensions_len).map(Reader::new)?;
        let mut extensions = vec![];
        while !sub_reader.is_consumed() {
            extensions.push(Extension::read_from(&mut sub_reader)?);
        }
        Ok(Self(Some(extensions.try_into()?)))
    }
}

pub trait TlsExtensionType {
    const TYPE: u16;
}

#[derive(Debug, Clone)]
pub enum SecureRenegotationExt {
    Initial,
    Renegotiation(LengthPrefixedVec<u8, u8, NonEmpty>),
}

impl SecureRenegotationExt {
    pub fn initial() -> Self {
        Self::Initial
    }
    pub fn renegotiation(renegotiation_info: &[u8]) -> Result<Self, CodingError> {
        Ok(Self::Renegotiation(renegotiation_info.to_vec().try_into()?))
    }
}

impl TlsExtensionType for SecureRenegotationExt {
    const TYPE: u16 = 0xff01;
}

impl TlsCodable for SecureRenegotationExt {
    fn read_from(reader: &mut Reader) -> Result<Self, CodingError> {
        let _ext_len = u16::read_from(reader)?;
        let renegotiation_info = LengthPrefixedVec::<u8, u8, MaybeEmpty>::read_from(reader)?;
        if renegotiation_info.len() == 0 {
            return Ok(Self::Initial);
        }
        Ok(Self::Renegotiation(renegotiation_info.reconstrain()?))
    }

    fn write_to(&self, bytes: &mut Vec<u8>) {
        Self::TYPE.write_to(bytes);
        let mut writer = LengthPrefixWriter::<u16>::new(bytes);
        match self {
            Self::Initial => writer.push(0u8),
            Self::Renegotiation(info) => info.write_to(&mut writer),
        };
        writer.finalize_length_prefix();
    }
}

type SessionTicket = LengthPrefixedVec<u16, u8, MaybeEmpty>;

#[derive(Debug, Clone)]
pub enum SessionTicketExt {
    Empty,
    Resumption(SessionTicket),
}

impl TlsExtensionType for SessionTicketExt {
    const TYPE: u16 = 0x0023;
}

impl SessionTicketExt {
    pub fn new() -> Self {
        Self::Empty
    }

    pub fn resume(ticket: Vec<u8>) -> Result<Self, CodingError> {
        Ok(Self::Resumption(ticket.try_into()?))
    }
}

impl TlsCodable for SessionTicketExt {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        Self::TYPE.write_to(bytes);
        match self {
            Self::Empty => 0u16.write_to(bytes),
            Self::Resumption(ticket) => ticket.write_to(bytes),
        };
    }
    fn read_from(reader: &mut Reader) -> Result<Self, CodingError> {
        let ext_len = u16::read_from(reader)?;
        if ext_len == 0 {
            return Ok(Self::Empty);
        }
        let ticket = SessionTicket::read_from(reader)?;
        Ok(Self::Resumption(ticket))
    }
}

#[derive(Debug, Clone)]
pub struct ExtendedMasterSecretExt {}

impl ExtendedMasterSecretExt {
    pub fn new() -> Self {
        Self {}
    }
}

impl TlsExtensionType for ExtendedMasterSecretExt {
    const TYPE: u16 = 0x0017;
}

impl TlsCodable for ExtendedMasterSecretExt {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        Self::TYPE.write_to(bytes);
        0u16.write_to(bytes);
    }
    fn read_from(reader: &mut Reader) -> Result<Self, CodingError> {
        let ext_len = u16::read_from(reader)?;
        if ext_len > 0 {
            return Err(CodingError::LengthTooLarge(0, ext_len.into()));
        }
        Ok(Self::new())
    }
}

tls_codable_enum! {
    #[repr(u8)]
    pub enum SigAlgo {
        Rsa = 1,
        Dsa = 2,
        Ecdsa = 3
    }
}

tls_codable_enum! {
    #[repr(u8)]
    pub enum HashAlgo {
        Md5 = 1,
        Sha1 = 2,
        Sha244 = 3,
        Sha256 = 4,
        Sha384 = 5,
        Sha512 = 6
    }
}

#[derive(Debug, Clone)]
struct SignatureAndHashAlgorithm {
    hash: HashAlgo,
    signature: SigAlgo,
}

impl TlsCodable for SignatureAndHashAlgorithm {
    fn read_from(reader: &mut Reader) -> Result<Self, CodingError> {
        Ok(Self {
            hash: HashAlgo::read_from(reader)?,
            signature: SigAlgo::read_from(reader)?,
        })
    }

    fn write_to(&self, bytes: &mut Vec<u8>) {
        self.hash.write_to(bytes);
        self.signature.write_to(bytes);
    }
}

#[derive(Debug, Clone)]
pub struct SignatureAlgorithmsExt {
    algorithms: LengthPrefixedVec<u16, SignatureAndHashAlgorithm, NonEmpty>,
}

impl TlsExtensionType for SignatureAlgorithmsExt {
    const TYPE: u16 = 0x000d;
}

impl TlsCodable for SignatureAlgorithmsExt {
    fn read_from(reader: &mut Reader) -> Result<Self, CodingError> {
        let _ext_len = u16::read_from(reader)?;
        let algorithm_count = (u16::read_from(reader)? / 2) as usize;

        let mut algorithms = vec![];
        for _ in 0..algorithm_count {
            algorithms.push(SignatureAndHashAlgorithm {
                hash: HashAlgo::read_from(reader)?,
                signature: SigAlgo::read_from(reader)?,
            });
        }
        Ok(Self {
            algorithms: algorithms.try_into()?,
        })
    }

    fn write_to(&self, bytes: &mut Vec<u8>) {
        Self::TYPE.write_to(bytes);
        let mut writer = LengthPrefixWriter::<u16>::new(bytes);
        self.algorithms.write_to(&mut writer);
        writer.finalize_length_prefix();
    }
}

impl SignatureAlgorithmsExt {
    pub fn new_from_product(
        signature_algorithms: Vec<SigAlgo>,
        hash_algorithms: Vec<HashAlgo>,
    ) -> Result<Self, CodingError> {
        let algorithms: Vec<SignatureAndHashAlgorithm> = signature_algorithms
            .iter()
            .flat_map(|&signature| {
                hash_algorithms
                    .iter()
                    .map(move |&hash| SignatureAndHashAlgorithm { hash, signature })
            })
            .collect();
        Ok(Self {
            algorithms: algorithms.try_into()?,
        })
    }
}

type ProtocolName = LengthPrefixedVec<u8, u8, NonEmpty>;
type ProtocolList = LengthPrefixedVec<u16, ProtocolName, NonEmpty>;

#[derive(Debug, Clone)]
pub struct ALPNExt {
    protocols: ProtocolList,
}

impl ALPNExt {
    pub fn new(names: Vec<String>) -> Result<Self, CodingError> {
        let mut protocols = vec![];
        for name in names {
            protocols.push(ProtocolName::try_from(name.into_bytes())?)
        }
        Ok(Self {
            protocols: protocols.try_into()?,
        })
    }
}

impl TlsExtensionType for ALPNExt {
    const TYPE: u16 = 0x0010;
}

impl TlsCodable for ALPNExt {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        Self::TYPE.write_to(bytes);
        let mut writer = LengthPrefixWriter::<u16>::new(bytes);
        self.protocols.write_to(&mut writer);
        writer.finalize_length_prefix();
    }
    fn read_from(reader: &mut Reader) -> Result<Self, CodingError> {
        let _ext_len = u16::read_from(reader)?;
        let protocols = ProtocolList::read_from(reader)?;
        Ok(Self { protocols })
    }
}
