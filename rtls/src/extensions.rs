use std::fmt::Debug;

use enum_dispatch::enum_dispatch;
use num_enum::TryFromPrimitive;

use crate::TLSResult;

#[enum_dispatch]
#[derive(Debug)]
pub enum Extension {
    SecureRenegotiation(SecureRenegotationExt),
    SignatureAlgorithms(SignatureAlgorithmsExt),
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
        _ => return Err(format!("unimplemented extension type: {id:#x}").into()),
    };
    let mut extensions: Vec<Extension> = vec![ext];
    extensions.extend(decode_extensions(&bytes[pos..])?.into_iter());
    Ok(extensions)
}

#[derive(Debug)]
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
            }.into(),
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
        // println!("{:?} {}", &bytes, bytes.len());
        bytes
    }
}

#[derive(Debug, Copy, Clone, TryFromPrimitive)]
#[repr(u8)]
pub enum SigAlgo {
    Rsa = 1,
}

#[derive(Debug, Copy, Clone, TryFromPrimitive)]
#[repr(u8)]
pub enum HashAlgo {
    Sha = 2,
    Sha256 = 4,
}

#[derive(Debug)]
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
