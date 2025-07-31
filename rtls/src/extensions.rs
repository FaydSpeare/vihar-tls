use std::fmt::Debug;

use crate::encoding::{
    CodingError, LengthPrefixWriter, LengthPrefixedVec, MaybeEmpty, NonEmpty, Reader,
    RedefineableCardinality, TlsCodable,
};

#[derive(Debug, Clone)]
pub enum Extension {
    SecureRenegotiation(SecureRenegotationExt),
    SignatureAlgorithms(SignatureAlgorithmsExt),
    SessionTicket(SessionTicketExt),
    // ExtendedMasterSecret(ExtendedMasterSecretExt),
    // ALPN(ALPNExt),
    // SupportedGroups(SupportedGroupsExt),
}

impl TlsCodable for Extension {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        match self {
            Self::SecureRenegotiation(ext) => ext.write_to(bytes),
            Self::SignatureAlgorithms(ext) => ext.write_to(bytes),
            Self::SessionTicket(ext) => ext.write_to(bytes),
        }
    }
    fn read_from(reader: &mut Reader) -> Result<Self, CodingError> {
        let ext_type = u16::read_from(reader)?;
        let ext: Extension = match ext_type {
            SignatureAlgorithmsExt::TYPE => SignatureAlgorithmsExt::read_from(reader)?.into(),
            SecureRenegotationExt::TYPE => SecureRenegotationExt::read_from(reader)?.into(),
            SessionTicketExt::TYPE => SessionTicketExt::read_from(reader)?.into(),
            // 0x0023 => SessionTicketExt::decode(bytes),
            // 0x0017 => ExtendedMasterSecretExt::decode(bytes),
            // 0x0010 => ALPNExt::decode(bytes)?,
            // 0x000a => SupportedGroupsExt::decode(bytes)?,
            _ => return Err(CodingError::UnknownExtensionType(ext_type)),
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

#[derive(Debug, Clone)]
pub struct Extensions(Option<LengthPrefixedVec<u16, Extension, NonEmpty>>);

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
        Ok(Self::Renegotiation(
            renegotiation_info.redefine_cardinality()?,
        ))
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

// #[derive(Debug, Clone)]
// pub struct ExtendedMasterSecretExt {}
//
// impl ExtendedMasterSecretExt {
//     pub fn new() -> Self {
//         Self {}
//     }
//
//     fn decode(bytes: &[u8]) -> (Extension, usize) {
//         let extension_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
//         assert_eq!(extension_len, 0);
//         (Self {}.into(), 4 + extension_len)
//     }
// }
//
// impl EncodeExtension for ExtendedMasterSecretExt {
//     fn encode(&self) -> Vec<u8> {
//         vec![0x00, 0x17, 0x00, 0x00]
//     }
// }

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

// #[derive(Debug, Clone)]
// pub struct ALPNExt {
//     protocols: Vec<String>,
// }
//
// impl ALPNExt {
//     pub fn new(protocols: Vec<String>) -> Self {
//         Self { protocols }
//     }
//
//     fn decode(bytes: &[u8]) -> TLSResult<(Extension, usize)> {
//         let extension_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
//         let mut idx = 6;
//         let mut protocols = Vec::<String>::new();
//         while idx < 4 + extension_len {
//             let name_len = bytes[idx] as usize;
//             protocols.push(String::from_utf8(
//                 bytes[idx + 1..idx + 1 + name_len].to_vec(),
//             )?);
//             idx += 1 + name_len;
//         }
//
//         Ok((Self { protocols }.into(), 4 + extension_len))
//     }
// }
//
// impl EncodeExtension for ALPNExt {
//     fn encode(&self) -> Vec<u8> {
//         let mut protocols_bytes = Vec::<u8>::new();
//         for protocol in &self.protocols {
//             protocols_bytes.push(protocol.len() as u8);
//             protocols_bytes.extend_from_slice(protocol.as_ref());
//         }
//         let mut bytes = Vec::<u8>::new();
//         bytes.extend_from_slice(&[0x00, 0x10]);
//         bytes.extend_from_slice(&((protocols_bytes.len() + 2) as u16).to_be_bytes());
//         bytes.extend_from_slice(&(protocols_bytes.len() as u16).to_be_bytes());
//         bytes.extend_from_slice(&protocols_bytes);
//         bytes
//     }
// }
//
// #[derive(Debug, Clone)]
// pub struct SupportedGroupsExt {
//     named_groups: Vec<u16>,
// }
//
// impl SupportedGroupsExt {
//     pub fn new(named_groups: Vec<u16>) -> Self {
//         Self { named_groups }
//     }
//
//     fn decode(bytes: &[u8]) -> TLSResult<(Extension, usize)> {
//         let extension_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
//         let groups_len = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
//         let mut named_groups = Vec::<u16>::new();
//         for i in 0..(groups_len / 2) {
//             let group = u16::from_be_bytes([bytes[6 + 2 * i], bytes[7 + 2 * i]]);
//             named_groups.push(group);
//         }
//         Ok((Self { named_groups }.into(), 4 + extension_len))
//     }
// }
//
// impl EncodeExtension for SupportedGroupsExt {
//     fn encode(&self) -> Vec<u8> {
//         let groups_bytes: Vec<u8> = self
//             .named_groups
//             .iter()
//             .map(|x| x.to_be_bytes())
//             .flatten()
//             .collect();
//         let mut bytes = Vec::<u8>::new();
//         bytes.extend_from_slice(&[0x00, 0x0a]);
//         bytes.extend_from_slice(&((groups_bytes.len() + 2) as u16).to_be_bytes());
//         bytes.extend_from_slice(&(groups_bytes.len() as u16).to_be_bytes());
//         bytes.extend_from_slice(&groups_bytes);
//         bytes
//     }
// }
