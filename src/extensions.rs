use log::{trace, warn};
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};
use std::{collections::HashSet, fmt::Debug};

use crate::{
    TlsPolicy, TlsValidateable, UnrecognisedServerNamePolicy,
    alert::{TlsAlert, TlsAlertDesc},
    encoding::{
        LengthPrefixWriter, LengthPrefixedVec, MaybeEmpty, NonEmpty, Reader, Reconstrainable,
        TlsCodable,
    },
    errors::{DecodingError, InvalidEncodingError},
    signature::{dsa_sign, dsa_verify, rsa_sign, rsa_verify},
};

tls_codable_enum! {
    #[repr(u16)]
    pub enum ExtensionType {
        SignatureAlgorithms = 0x000d,
        RenegotiationInfo = 0xff01,
        SessionTicket = 0x0023,
        ExtendedMasterSecret = 0x0017,
        ServerName = 0x0000,
        ALPN = 0x0010,
        MaxFragmentLen = 0x0001,
    }
}

#[derive(Debug, Clone)]
pub enum Extension {
    SignatureAlgorithms(SignatureAlgorithmsExt),
    RenegotiationInfo(RenegotiationInfoExt),
    SessionTicket(SessionTicketExt),
    ExtendedMasterSecret(ExtendedMasterSecretExt),
    ALPN(ALPNExt),
    ServerName(ServerNameExt),
    MaxFragmentLen(MaxFragmentLenExt),
    Unknown(u16, Vec<u8>),
}

impl Extension {
    pub fn extension_type(&self) -> ExtensionType {
        match self {
            Self::SignatureAlgorithms(_) => ExtensionType::SignatureAlgorithms,
            Self::RenegotiationInfo(_) => ExtensionType::RenegotiationInfo,
            Self::SessionTicket(_) => ExtensionType::SessionTicket,
            Self::ExtendedMasterSecret(_) => ExtensionType::ExtendedMasterSecret,
            Self::ALPN(_) => ExtensionType::ALPN,
            Self::ServerName(_) => ExtensionType::ServerName,
            Self::MaxFragmentLen(_) => ExtensionType::MaxFragmentLen,
            Self::Unknown(x, _) => ExtensionType::Unknown(*x),
        }
    }
}

impl TlsCodable for Extension {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        self.extension_type().write_to(bytes);
        let mut writer = LengthPrefixWriter::<u16>::new(bytes);
        match self {
            Self::RenegotiationInfo(ext) => ext.write_to(&mut writer),
            Self::SignatureAlgorithms(ext) => ext.write_to(&mut writer),
            Self::SessionTicket(ext) => ext.write_to(&mut writer),
            Self::ExtendedMasterSecret(ext) => ext.write_to(&mut writer),
            Self::ALPN(ext) => ext.write_to(&mut writer),
            Self::ServerName(ext) => ext.write_to(&mut writer),
            Self::MaxFragmentLen(ext) => ext.write_to(&mut writer),
            Self::Unknown(_, ext_bytes) => {
                writer.extend_from_slice(&ext_bytes);
            }
        };
        writer.finalize_length_prefix();
    }
    fn read_from(reader: &mut Reader) -> Result<Self, DecodingError> {
        let ext_type = ExtensionType::read_from(reader)?;
        let ext_len = u16::read_from(reader)?;
        let mut subreader = reader.consume(ext_len.into()).map(Reader::new)?;

        let ext: Extension = match ext_type {
            ExtensionType::SignatureAlgorithms => {
                SignatureAlgorithmsExt::read_from(&mut subreader)?.into()
            }
            ExtensionType::RenegotiationInfo => {
                RenegotiationInfoExt::read_from(&mut subreader)?.into()
            }
            ExtensionType::SessionTicket => SessionTicketExt::read_from(&mut subreader)?.into(),
            ExtensionType::ExtendedMasterSecret => {
                ExtendedMasterSecretExt::read_from(&mut subreader)?.into()
            }
            ExtensionType::ALPN => ALPNExt::read_from(&mut subreader)?.into(),
            ExtensionType::ServerName => ServerNameExt::read_from(&mut subreader)?.into(),
            ExtensionType::MaxFragmentLen => MaxFragmentLenExt::read_from(&mut subreader)?.into(),
            ExtensionType::Unknown(x) => {
                warn!("unknown extension: {}", x);
                Self::Unknown(x, subreader.consume_rest().to_vec())
            }
        };
        Ok(ext)
    }
}

impl From<RenegotiationInfoExt> for Extension {
    fn from(value: RenegotiationInfoExt) -> Self {
        Self::RenegotiationInfo(value)
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

impl From<ServerNameExt> for Extension {
    fn from(value: ServerNameExt) -> Self {
        Self::ServerName(value)
    }
}

impl From<MaxFragmentLenExt> for Extension {
    fn from(value: MaxFragmentLenExt) -> Self {
        Self::MaxFragmentLen(value)
    }
}

#[derive(Debug, Clone)]
pub struct Extensions {
    list: Option<LengthPrefixedVec<u16, Extension, NonEmpty>>,
}

impl Extensions {
    pub fn new(extensions: Vec<Extension>) -> Result<Self, DecodingError> {
        if extensions.len() == 0 {
            return Ok(Self::empty());
        }
        Ok(Self {
            list: Some(extensions.try_into()?),
        })
    }

    pub fn empty() -> Self {
        Self { list: None }
    }

    pub fn validate(&self, policy: &TlsPolicy) -> Result<(), TlsAlert> {
        if let Some(extensions) = &self.list {
            for item in extensions.iter() {
                if let Extension::ServerName(ext) = item {
                    ext.validate(policy)?;
                }
                if let Extension::MaxFragmentLen(ext) = item {
                    ext.validate(policy)?;
                }
            }
        }
        Ok(())
    }

    pub fn extension_type_set(&self) -> HashSet<ExtensionType> {
        let mut set = HashSet::new();
        if let Some(extensions) = &self.list {
            for ext in extensions.iter() {
                set.insert(ext.extension_type());
            }
        }
        set
    }

    pub fn includes_secure_renegotiation(&self) -> bool {
        match &self.list {
            None => false,
            Some(extensions) => extensions
                .iter()
                .any(|x| matches!(x, Extension::RenegotiationInfo(_))),
        }
    }

    pub fn includes_extended_master_secret(&self) -> bool {
        match &self.list {
            None => false,
            Some(extensions) => extensions
                .iter()
                .any(|x| matches!(x, Extension::ExtendedMasterSecret(_))),
        }
    }

    pub fn includes_session_ticket(&self) -> bool {
        match &self.list {
            None => false,
            Some(extensions) => extensions
                .iter()
                .any(|x| matches!(x, Extension::SessionTicket(_))),
        }
    }

    pub fn get_session_ticket(&self) -> Option<Vec<u8>> {
        match &self.list {
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

    pub fn get_renegotiation_info(&self) -> Option<Vec<u8>> {
        match &self.list {
            None => None,
            Some(extensions) => extensions.iter().find_map(|ext| {
                if let Extension::RenegotiationInfo(RenegotiationInfoExt::Renegotiation(info)) = ext
                {
                    Some(info.to_vec())
                } else {
                    None
                }
            }),
        }
    }

    pub fn get_max_fragment_len(&self) -> Option<MaxFragmentLength> {
        match &self.list {
            None => None,
            Some(extensions) => extensions.iter().find_map(|ext| {
                if let Extension::MaxFragmentLen(MaxFragmentLenExt { value }) = ext {
                    Some(*value)
                } else {
                    None
                }
            }),
        }
    }

    pub fn get_signature_algorithms(&self) -> Option<Vec<SignatureAlgorithm>> {
        match &self.list {
            None => None,
            Some(extensions) => extensions.iter().find_map(|ext| {
                if let Extension::SignatureAlgorithms(SignatureAlgorithmsExt { algorithms }) = ext {
                    Some(algorithms.to_vec())
                } else {
                    None
                }
            }),
        }
    }
}

impl TlsCodable for Extensions {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        if let Some(extensions) = &self.list {
            extensions.write_to(bytes);
        }
    }
    fn read_from(reader: &mut Reader) -> Result<Self, DecodingError> {
        if reader.is_consumed() {
            return Ok(Self::empty());
        }

        let extensions_len = u16::read_from(reader)?.into();
        let mut sub_reader = reader.consume(extensions_len).map(Reader::new)?;
        let mut extensions = vec![];
        while !sub_reader.is_consumed() {
            extensions.push(Extension::read_from(&mut sub_reader)?);
        }
        Ok(Self {
            list: Some(extensions.try_into()?),
        })
    }
}

#[derive(Debug, Clone)]
pub enum RenegotiationInfoExt {
    IndicateSupport,
    Renegotiation(LengthPrefixedVec<u8, u8, NonEmpty>),
}

impl RenegotiationInfoExt {
    pub fn indicate_support() -> Self {
        Self::IndicateSupport
    }
    pub fn renegotiation(renegotiation_info: &[u8]) -> Result<Self, DecodingError> {
        Ok(Self::Renegotiation(renegotiation_info.to_vec().try_into()?))
    }
}

impl TlsCodable for RenegotiationInfoExt {
    fn read_from(reader: &mut Reader) -> Result<Self, DecodingError> {
        let renegotiation_info = LengthPrefixedVec::<u8, u8, MaybeEmpty>::read_from(reader)?;
        if renegotiation_info.len() == 0 {
            return Ok(Self::IndicateSupport);
        }
        Ok(Self::Renegotiation(renegotiation_info.reconstrain()?))
    }

    fn write_to(&self, bytes: &mut Vec<u8>) {
        match self {
            Self::IndicateSupport => bytes.push(0u8),
            Self::Renegotiation(info) => info.write_to(bytes),
        };
    }
}

#[derive(Debug, Clone)]
pub enum SessionTicketExt {
    Empty,
    Resumption(Vec<u8>),
}

impl SessionTicketExt {
    pub fn new() -> Self {
        Self::Empty
    }

    pub fn resume(ticket: Vec<u8>) -> Self {
        Self::Resumption(ticket)
    }
}

impl TlsCodable for SessionTicketExt {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        if let Self::Resumption(ticket) = self {
            bytes.extend_from_slice(&ticket);
        }
    }
    fn read_from(reader: &mut Reader) -> Result<Self, DecodingError> {
        if reader.is_consumed() {
            return Ok(Self::Empty);
        }
        Ok(Self::Resumption(reader.consume_rest().to_vec()))
    }
}

#[derive(Debug, Clone)]
pub struct ExtendedMasterSecretExt {}

impl ExtendedMasterSecretExt {
    pub fn indicate_support() -> Self {
        Self {}
    }
}

impl TlsCodable for ExtendedMasterSecretExt {
    fn write_to(&self, _bytes: &mut Vec<u8>) {}

    fn read_from(reader: &mut Reader) -> Result<Self, DecodingError> {
        if !reader.is_consumed() {
            return Err(InvalidEncodingError::InvalidExtensionLength.into());
        }
        Ok(Self::indicate_support())
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

pub fn verify(
    signature_algorithm: SigAlgo,
    hash_algorithm: HashAlgo,
    key_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, String> {
    match (signature_algorithm, hash_algorithm) {
        (SigAlgo::Dsa, HashAlgo::Sha1) => dsa_verify::<Sha1>(key_der, message, signature),
        (SigAlgo::Dsa, HashAlgo::Sha224) => dsa_verify::<Sha224>(key_der, message, signature),
        (SigAlgo::Dsa, HashAlgo::Sha256) => dsa_verify::<Sha256>(key_der, message, signature),
        (SigAlgo::Dsa, HashAlgo::Sha384) => dsa_verify::<Sha384>(key_der, message, signature),
        (SigAlgo::Dsa, HashAlgo::Sha512) => dsa_verify::<Sha512>(key_der, message, signature),
        (SigAlgo::Rsa, HashAlgo::Sha1) => rsa_verify::<Sha1>(key_der, message, signature),
        (SigAlgo::Rsa, HashAlgo::Sha224) => rsa_verify::<Sha224>(key_der, message, signature),
        (SigAlgo::Rsa, HashAlgo::Sha256) => rsa_verify::<Sha256>(key_der, message, signature),
        (SigAlgo::Rsa, HashAlgo::Sha384) => rsa_verify::<Sha384>(key_der, message, signature),
        (SigAlgo::Rsa, HashAlgo::Sha512) => rsa_verify::<Sha512>(key_der, message, signature),
        _ => Err(format!(
            "No verification available for {signature_algorithm:?} {hash_algorithm:?}"
        )),
    }
}

pub fn sign(
    signature_algorithm: SigAlgo,
    hash_algorithm: HashAlgo,
    key_der: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, String> {
    match (signature_algorithm, hash_algorithm) {
        (SigAlgo::Dsa, HashAlgo::Sha1) => dsa_sign::<Sha1>(key_der, data),
        (SigAlgo::Dsa, HashAlgo::Sha224) => dsa_sign::<Sha224>(key_der, data),
        (SigAlgo::Dsa, HashAlgo::Sha256) => dsa_sign::<Sha256>(key_der, data),
        (SigAlgo::Dsa, HashAlgo::Sha384) => dsa_sign::<Sha384>(key_der, data),
        (SigAlgo::Dsa, HashAlgo::Sha512) => dsa_sign::<Sha512>(key_der, data),
        (SigAlgo::Rsa, HashAlgo::Sha1) => rsa_sign::<Sha1>(key_der, data),
        (SigAlgo::Rsa, HashAlgo::Sha224) => rsa_sign::<Sha224>(key_der, data),
        (SigAlgo::Rsa, HashAlgo::Sha256) => rsa_sign::<Sha256>(key_der, data),
        (SigAlgo::Rsa, HashAlgo::Sha384) => rsa_sign::<Sha384>(key_der, data),
        (SigAlgo::Rsa, HashAlgo::Sha512) => rsa_sign::<Sha512>(key_der, data),
        _ => Err(format!(
            "No signing available for {signature_algorithm:?} {hash_algorithm:?}"
        )),
    }
}

tls_codable_enum! {
    #[repr(u8)]
    pub enum HashAlgo {
        Md5 = 1,
        Sha1 = 2,
        Sha224 = 3,
        Sha256 = 4,
        Sha384 = 5,
        Sha512 = 6
    }
}

#[derive(Debug, Clone)]
pub struct SignatureAlgorithm {
    pub hash: HashAlgo,
    pub signature: SigAlgo,
}

impl SignatureAlgorithm {
    pub fn rsa_with(hash: HashAlgo) -> Self {
        Self {
            signature: SigAlgo::Rsa,
            hash,
        }
    }
}

impl TlsCodable for SignatureAlgorithm {
    fn read_from(reader: &mut Reader) -> Result<Self, DecodingError> {
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
    algorithms: LengthPrefixedVec<u16, SignatureAlgorithm, NonEmpty>,
}

impl TlsCodable for SignatureAlgorithmsExt {
    fn read_from(reader: &mut Reader) -> Result<Self, DecodingError> {
        let algorithm_count = (u16::read_from(reader)? / 2) as usize;

        let mut algorithms = vec![];
        for _ in 0..algorithm_count {
            algorithms.push(SignatureAlgorithm {
                hash: HashAlgo::read_from(reader)?,
                signature: SigAlgo::read_from(reader)?,
            });
        }
        Ok(Self {
            algorithms: algorithms.try_into()?,
        })
    }

    fn write_to(&self, bytes: &mut Vec<u8>) {
        self.algorithms.write_to(bytes);
    }
}

impl SignatureAlgorithmsExt {
    pub fn new(signature_algorithms: &[SignatureAlgorithm]) -> Self {
        Self {
            algorithms: signature_algorithms.to_vec().try_into().unwrap(),
        }
    }
}

type ProtocolName = LengthPrefixedVec<u8, u8, NonEmpty>;
type ProtocolList = LengthPrefixedVec<u16, ProtocolName, NonEmpty>;

#[derive(Debug, Clone)]
pub struct ALPNExt {
    protocols: ProtocolList,
}

impl ALPNExt {
    pub fn new(names: Vec<String>) -> Result<Self, DecodingError> {
        let mut protocols = vec![];
        for name in names {
            protocols.push(ProtocolName::try_from(name.into_bytes())?)
        }
        Ok(Self {
            protocols: protocols.try_into()?,
        })
    }
}

impl TlsCodable for ALPNExt {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        self.protocols.write_to(bytes);
    }
    fn read_from(reader: &mut Reader) -> Result<Self, DecodingError> {
        let protocols = ProtocolList::read_from(reader)?;
        Ok(Self { protocols })
    }
}

type HostName = LengthPrefixedVec<u16, u8, NonEmpty>;
type UnknownName = LengthPrefixedVec<u16, u8, MaybeEmpty>;

tls_codable_enum! {
    #[repr(u8)]
    enum NameType {
        HostName = 0
    }
}

#[derive(Debug, Clone)]
enum ServerName {
    HostName(HostName),
    Unknown(u8, UnknownName),
}

impl ServerName {
    fn name_type(&self) -> NameType {
        match self {
            Self::HostName(_) => NameType::HostName,
            Self::Unknown(x, _) => NameType::from(*x),
        }
    }
}

impl TlsCodable for ServerName {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        self.name_type().write_to(bytes);
        match self {
            Self::HostName(host_name) => {
                host_name.write_to(bytes);
            }
            Self::Unknown(_, unknown_name) => {
                unknown_name.write_to(bytes);
            }
        }
    }

    fn read_from(reader: &mut Reader) -> Result<Self, DecodingError> {
        let name_type = NameType::read_from(reader)?;
        Ok(match name_type {
            NameType::HostName => Self::HostName(HostName::read_from(reader)?),
            NameType::Unknown(name_type) => {
                Self::Unknown(name_type, UnknownName::read_from(reader)?)
            }
        })
    }
}

type ServerNameList = LengthPrefixedVec<u16, ServerName, NonEmpty>;

#[derive(Debug, Clone)]
pub struct ServerNameExt {

    // Some servers respond with an empty SNI extension
    list: Option<ServerNameList>,
}

impl ServerNameExt {
    pub fn new(host_name: &str) -> Self {
        let host_name = ServerName::HostName(host_name.as_bytes().to_vec().try_into().unwrap());
        Self {
            list: Some(
                vec![
                    host_name.clone(),
                    // ServerName::Unknown(1, vec![1, 2, 3].try_into().unwrap()),
                ]
                .try_into()
                .unwrap(),
            ),
        }
    }

    pub fn validate(&self, policy: &TlsPolicy) -> Result<(), TlsAlert> {
        let mut seen = HashSet::new();

        if let Some(list) = &self.list {
            // Duplicate server names are not allowed
            if !list
                .iter()
                .all(|server_name| seen.insert(server_name.name_type()))
            {
                return Err(TlsAlert::fatal(TlsAlertDesc::DecodeError));
            }

            if let UnrecognisedServerNamePolicy::Alert(level) = policy.unrecognised_server_name {
                if list
                    .iter()
                    .any(|server_name| matches!(server_name, ServerName::Unknown(_, _)))
                {
                    return Err(TlsAlert::new(level, TlsAlertDesc::UnrecognisedName));
                }
            }
        }
        Ok(())
    }
}

// TODO:
// A server that receives a client hello containing the "server_name"
//     extension MAY use the information contained in the extension to guide
//     its selection of an appropriate certificate to return to the client,
//     and/or other aspects of security policy.  In this event, the server
//     SHALL include an extension of type "server_name" in the (extended)
//     server hello.  The "extension_data" field of this extension SHALL be
//     empty.
//
//     When the server is deciding whether or not to accept a request to
//     resume a session, the contents of a server_name extension MAY be used
//     in the lookup of the session in the session cache.  The client SHOULD
//     include the same server_name extension in the session resumption
//     request as it did in the full handshake that established the session.
//     A server that implements this extension MUST NOT accept the request
//     to resume the session if the server_name extension contains a
//     different name.  Instead, it proceeds with a full handshake to
//     establish a new session.  When resuming a session, the server MUST
//     NOT include a server_name extension in the server hello.
//
impl TlsCodable for ServerNameExt {
    fn read_from(reader: &mut Reader) -> Result<Self, DecodingError> {
        if reader.is_consumed() {
            return Ok(Self { list: None });
        }
        let list = ServerNameList::read_from(reader)?;
        Ok(Self { list: Some(list) })
    }

    fn write_to(&self, bytes: &mut Vec<u8>) {
        if let Some(list) = &self.list {
            list.write_to(bytes);
        }
    }
}

tls_codable_enum! {
    #[repr(u8)]
    pub enum MaxFragmentLength {
        Len512 = 1,  // 2^9
        Len1024 = 2, // 2^10
        Len2048 = 3, // 2^11
        Len4096 = 4, // 2^12
    }
}

impl MaxFragmentLength {
    pub const fn length(self) -> usize {
        match self {
            Self::Len512 => 512,
            Self::Len1024 => 1024,
            Self::Len2048 => 2048,
            Self::Len4096 => 4096,
            Self::Unknown(_) => panic!(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MaxFragmentLenExt {
    value: MaxFragmentLength,
}

impl MaxFragmentLenExt {
    pub fn new(value: MaxFragmentLength) -> Self {
        Self { value }
    }
}

impl TlsCodable for MaxFragmentLenExt {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        self.value.write_to(bytes);
    }
    fn read_from(reader: &mut Reader) -> Result<Self, DecodingError> {
        Ok(Self {
            value: MaxFragmentLength::read_from(reader)?,
        })
    }
}

impl TlsValidateable for MaxFragmentLenExt {
    fn validate(&self, _: &TlsPolicy) -> Result<(), TlsAlert> {
        if let MaxFragmentLength::Unknown(x) = self.value {
            trace!("Invalid max_fragment_length value: {x}");
            return Err(TlsAlert::fatal(TlsAlertDesc::IllegalParameter));
        }
        Ok(())
    }
}
