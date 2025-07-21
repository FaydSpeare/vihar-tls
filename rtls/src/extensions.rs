use std::fmt::Debug;

use enum_dispatch::enum_dispatch;
use num_enum::TryFromPrimitive;

use crate::TLSResult;

#[enum_dispatch]
#[derive(Debug, Clone)]
pub enum Extension {
    SecureRenegotiation(SecureRenegotationExt),
    SignatureAlgorithms(SignatureAlgorithmsExt),
    SessionTicket(SessionTicketExt),
    ExtendedMasterSecret(ExtendedMasterSecretExt),
    Heartbeat(HeartbeatExt),
    ALPN(ALPNExt),
}

#[enum_dispatch(Extension)]
pub trait EncodeExtension: Debug {
    fn encode(&self) -> Vec<u8>;
}

pub fn decode_extensions(bytes: &[u8]) -> TLSResult<Vec<Extension>> {
    if bytes.len() == 0 {
        return Ok(vec![]);
    }
    let id = u16::from_be_bytes([bytes[0], bytes[1]]);
    let (ext, pos) = match id {
        0x000d => SignatureAlgorithmsExt::try_decode(bytes)?,
        0xff01 => SecureRenegotationExt::decode(bytes),
        0x0023 => SessionTicketExt::decode(bytes),
        0x0017 => ExtendedMasterSecretExt::decode(bytes),
        0x000f => HeartbeatExt::decode(bytes)?,
        0x0010 => ALPNExt::decode(bytes)?,
        _ => return Err(format!("unimplemented extension type: {id:#x}").into()),
    };
    let mut extensions: Vec<Extension> = vec![ext];
    extensions.extend(decode_extensions(&bytes[pos..])?.into_iter());
    Ok(extensions)
}

#[derive(Debug, Clone)]
pub struct SecureRenegotationExt {
    verify_data: Option<Vec<u8>>,
}

impl SecureRenegotationExt {
    pub fn initial() -> Self {
        Self { verify_data: None }
    }
    pub fn renegotiation(verify_data: &[u8]) -> Self {
        Self {
            verify_data: Some(verify_data.to_vec()),
        }
    }

    fn decode(bytes: &[u8]) -> (Extension, usize) {
        let extension_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        let verify_data_len = bytes[4] as usize;
        if verify_data_len == 0 {
            return (Self { verify_data: None }.into(), 4 + extension_len);
        }
        (
            Self {
                verify_data: Some(bytes[5..5 + verify_data_len].to_vec()),
            }
            .into(),
            4 + extension_len,
        )
    }
}

impl EncodeExtension for SecureRenegotationExt {
    fn encode(&self) -> Vec<u8> {
        let verify_data_len = self.verify_data.as_ref().map_or(0, |x| x.len()) as u8;
        let extension_len = (1 + verify_data_len) as u16;

        let mut bytes = Vec::<u8>::new();
        bytes.extend_from_slice(&[0xff, 0x01]);
        bytes.extend_from_slice(&extension_len.to_be_bytes());
        bytes.push(verify_data_len);
        if let Some(verify_data) = &self.verify_data {
            bytes.extend_from_slice(verify_data);
        }
        bytes
    }
}

#[derive(Debug, Clone)]
pub struct SessionTicketExt {
    pub ticket: Option<Vec<u8>>,
}

impl SessionTicketExt {
    pub fn new() -> Self {
        Self { ticket: None }
    }

    pub fn resume(ticket: Vec<u8>) -> Self {
        Self {
            ticket: Some(ticket),
        }
    }

    fn decode(bytes: &[u8]) -> (Extension, usize) {
        let extension_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        assert_eq!(extension_len, 0);
        (Self { ticket: None }.into(), 4 + extension_len)
    }
}

impl EncodeExtension for SessionTicketExt {
    fn encode(&self) -> Vec<u8> {
        let ticket_bytes = self.ticket.as_ref().map_or(vec![], |t| t.clone());
        let mut bytes = Vec::<u8>::new();
        bytes.extend_from_slice(&[0x00, 0x23]);
        bytes.extend_from_slice(&(ticket_bytes.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&ticket_bytes);
        bytes
    }
}

#[derive(Debug, Clone)]
pub struct ExtendedMasterSecretExt {}

impl ExtendedMasterSecretExt {
    pub fn new() -> Self {
        Self {}
    }

    fn decode(bytes: &[u8]) -> (Extension, usize) {
        let extension_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        assert_eq!(extension_len, 0);
        (Self {}.into(), 4 + extension_len)
    }
}

impl EncodeExtension for ExtendedMasterSecretExt {
    fn encode(&self) -> Vec<u8> {
        vec![0x00, 0x17, 0x00, 0x00]
    }
}

#[derive(Debug, Copy, Clone, TryFromPrimitive)]
#[repr(u8)]
pub enum SigAlgo {
    Rsa = 1,
    Dsa = 2,
    Ecdsa = 3,
}

#[derive(Debug, Copy, Clone, TryFromPrimitive)]
#[repr(u8)]
pub enum HashAlgo {
    Md5 = 1,
    Sha1 = 2,
    Sha244 = 3,
    Sha256 = 4,
    Sha384 = 5,
    Sha512 = 6,
}

#[derive(Debug, Clone)]
pub struct SignatureAlgorithmsExt {
    algorithms: Vec<(HashAlgo, SigAlgo)>,
}

impl SignatureAlgorithmsExt {
    pub fn new_from_product(
        signature_algorithms: Vec<SigAlgo>,
        hash_algorithms: Vec<HashAlgo>,
    ) -> Self {
        let algorithms: Vec<(HashAlgo, SigAlgo)> = signature_algorithms
            .iter()
            .flat_map(|&s| hash_algorithms.iter().map(move |&h| (h, s)))
            .collect();
        Self { algorithms }
    }

    fn try_decode(bytes: &[u8]) -> TLSResult<(Extension, usize)> {
        let extension_len = (u16::from_be_bytes([bytes[2], bytes[3]]) / 2) as usize;
        let algorithm_count = (u16::from_be_bytes([bytes[4], bytes[5]]) / 2) as usize;
        let mut algorithms = Vec::<(HashAlgo, SigAlgo)>::new();
        for i in 0..algorithm_count {
            let hash_algo = HashAlgo::try_from_primitive(bytes[6 + 2 * i])?;
            let sig_algo = SigAlgo::try_from_primitive(bytes[6 + 2 * i + 1])?;
            algorithms.push((hash_algo, sig_algo));
        }
        Ok((Self { algorithms }.into(), 4 + extension_len))
    }
}

impl EncodeExtension for SignatureAlgorithmsExt {
    fn encode(&self) -> Vec<u8> {
        let supported_algorithms: Vec<u8> = self
            .algorithms
            .iter()
            .map(|(h, s)| [*h as u8, *s as u8])
            .flatten()
            .collect();
        let supported_algorithms_len = supported_algorithms.len() as u16;
        let extension_len = supported_algorithms_len + 2;

        let mut bytes = Vec::<u8>::new();
        bytes.extend_from_slice(&[0x00, 0x0d]); // Extension type
        bytes.extend_from_slice(&extension_len.to_be_bytes()); // Extension length
        bytes.extend_from_slice(&supported_algorithms_len.to_be_bytes()); // Algorithms length
        bytes.extend_from_slice(&supported_algorithms);
        bytes
    }
}

#[derive(Debug, Copy, Clone, TryFromPrimitive)]
#[repr(u8)]
pub enum HeartbeatMode {
    PeerAllowedToSend = 1,
    PeerNotAllowedToSend = 2,
}

#[derive(Debug, Clone)]
pub struct HeartbeatExt {
    mode: HeartbeatMode,
}

impl HeartbeatExt {
    pub fn new() -> Self {
        Self {
            mode: HeartbeatMode::PeerNotAllowedToSend,
        }
    }

    fn decode(bytes: &[u8]) -> TLSResult<(Extension, usize)> {
        let extension_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        assert_eq!(extension_len, 1);
        let mode = HeartbeatMode::try_from(bytes[4])?;
        Ok((Self { mode }.into(), 4 + extension_len))
    }
}

impl EncodeExtension for HeartbeatExt {
    fn encode(&self) -> Vec<u8> {
        vec![0x00, 0x0f, 0x00, 0x01, self.mode as u8]
    }
}

#[derive(Debug, Clone)]
pub struct ALPNExt {
    protocols: Vec<String>,
}

impl ALPNExt {
    pub fn new(protocols: Vec<String>) -> Self {
        Self { protocols }
    }

    fn decode(bytes: &[u8]) -> TLSResult<(Extension, usize)> {
        let extension_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        let mut idx = 6;
        let mut protocols = Vec::<String>::new();
        while idx < 4 + extension_len {
            let name_len = bytes[idx] as usize;
            protocols.push(String::from_utf8(
                bytes[idx + 1..idx + 1 + name_len].to_vec(),
            )?);
            idx += 1 + name_len;
        }

        Ok((Self { protocols }.into(), 4 + extension_len))
    }
}

impl EncodeExtension for ALPNExt {
    fn encode(&self) -> Vec<u8> {
        let mut protocols_bytes = Vec::<u8>::new();
        for protocol in &self.protocols {
            protocols_bytes.push(protocol.len() as u8);
            protocols_bytes.extend_from_slice(protocol.as_ref());
        }
        let mut bytes = Vec::<u8>::new();
        bytes.extend_from_slice(&[0x00, 0x10]);
        bytes.extend_from_slice(&((protocols_bytes.len() + 2) as u16).to_be_bytes());
        bytes.extend_from_slice(&(protocols_bytes.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&protocols_bytes);
        bytes
    }
}
