use std::fmt::Debug;

use crate::{
    gcm::{decrypt_aes_cbc, decrypt_aes_gcm, encrypt_aes_cbc, encrypt_aes_gcm},
    prf::{HmacHashAlgo, hmac, prf_sha256, prf_sha384},
};
use aes::{Aes128, Aes256};
use enum_dispatch::enum_dispatch;
use sha2::{Digest, Sha256, Sha384};

#[derive(Debug, Copy, Clone)]
pub enum CompressionAlgorithm {
    Null,
}

#[derive(Debug, Copy, Clone)]
pub enum MacAlgorithm {
    None,
    HmacSha1,
    HmacSha256,
}

impl MacAlgorithm {
    pub fn mac_length(&self) -> usize {
        match self {
            Self::None => 0,
            Self::HmacSha1 => 20,
            Self::HmacSha256 => 32,
        }
    }

    pub fn key_length(&self) -> usize {
        self.mac_length()
    }

    pub fn mac(&self, key: &[u8], seed: &[u8]) -> Vec<u8> {
        match self {
            Self::HmacSha1 => hmac(key, seed, HmacHashAlgo::Sha1),
            Self::HmacSha256 => hmac(key, seed, HmacHashAlgo::Sha256),
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum PrfAlgorithm {
    Sha256,
    Sha384,
}

impl PrfAlgorithm {
    pub fn prf(&self, secret: &[u8], label: &[u8], seed: &[u8], len: usize) -> Vec<u8> {
        match self {
            Self::Sha256 => prf_sha256(secret, label, seed, len),
            Self::Sha384 => prf_sha384(secret, label, seed, len),
        }
    }

    pub fn hash(&self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(data).to_vec(),
            Self::Sha384 => Sha384::digest(data).to_vec(),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum CipherType {
    Stream,
    Block,
    Aead,
}

#[derive(Debug, Copy, Clone)]
pub enum EncAlgorithm {
    Aes128Cbc,
    Aes256Cbc,
    Aes128Gcm,
    Aes256Gcm,
}

impl EncAlgorithm {
    pub fn key_length(&self) -> usize {
        match self {
            Self::Aes128Cbc => 16,
            Self::Aes256Cbc => 32,
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm => 32,
        }
    }

    pub fn block_length(&self) -> usize {
        match self {
            Self::Aes128Cbc => 16,
            Self::Aes256Cbc => 16,
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm => 16,
        }
    }

    pub fn record_iv_length(&self) -> usize {
        match self {
            Self::Aes128Gcm => 8,
            Self::Aes256Gcm => 8,
            _ => self.block_length(),
        }
    }

    pub fn fixed_iv_length(&self) -> usize {
        match self {
            Self::Aes128Gcm => 4,
            Self::Aes256Gcm => 4,
            _ => 0,
        }
    }

    pub fn cipher_type(&self) -> CipherType {
        match self {
            Self::Aes128Cbc => CipherType::Block,
            Self::Aes256Cbc => CipherType::Block,
            Self::Aes128Gcm => CipherType::Aead,
            Self::Aes256Gcm => CipherType::Aead,
        }
    }

    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        key: &[u8],
        iv: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, String> {
        Ok(match self {
            Self::Aes128Cbc => decrypt_aes_cbc::<Aes128>(ciphertext, key, iv),
            Self::Aes256Cbc => decrypt_aes_cbc::<Aes256>(ciphertext, key, iv),
            Self::Aes128Gcm => decrypt_aes_gcm::<Aes128>(
                key,
                iv,
                ciphertext,
                aad.expect("GCM missing additional data"),
            )?,
            Self::Aes256Gcm => decrypt_aes_gcm::<Aes256>(
                key,
                iv,
                ciphertext,
                aad.expect("GCM missing additional data"),
            )?,
        })
    }

    pub fn encrypt(&self, plaintext: &[u8], key: &[u8], iv: &[u8], aad: Option<&[u8]>) -> Vec<u8> {
        match self {
            Self::Aes128Cbc => encrypt_aes_cbc::<Aes128>(plaintext, key, iv),
            Self::Aes256Cbc => encrypt_aes_cbc::<Aes256>(plaintext, key, iv),
            Self::Aes128Gcm => encrypt_aes_gcm::<Aes128>(
                key,
                iv,
                plaintext,
                aad.expect("GCM missing additional data"),
            ),
            Self::Aes256Gcm => encrypt_aes_gcm::<Aes256>(
                key,
                iv,
                plaintext,
                aad.expect("GCM missing additional data"),
            ),
        }
    }
}

#[derive(Debug, Clone)]
pub enum KeyExchangeAlgorithm {
    Rsa,
    DheRsa,
    DheDss,
    EcdheRsa,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct CipherSuiteParams {
    pub name: &'static str,
    pub mac_algorithm: MacAlgorithm,
    pub enc_algorithm: EncAlgorithm,
    pub key_exchange_algorithm: KeyExchangeAlgorithm,
    pub prf_algorithm: PrfAlgorithm,
}

tls_codable_enum! {
    #[repr(u16)]
    pub enum CipherSuiteId {
        RsaAes128CbcSha = 0x002f,
        RsaAes128CbcSha256 = 0x003c,
        RsaAes256CbcSha = 0x0035,
        RsaAes256CbcSha256 = 0x003d,
        DheRsaAes128CbcSha = 0x0033,
        DheRsaAes128CbcSha256 = 0x0067,
        DheDssAes128CbcSha = 0x0032,
        RsaAes128GcmSha256 = 0x009c,
        RsaAes256GcmSha384 = 0x009d,
        DheRsaAes128GcmSha256 = 0x009e,
        EcdheRsaAes128CbcSha = 0xc013
    }
}

#[enum_dispatch]
#[derive(Debug)]
pub enum CipherSuite {
    RsaAes128CbcSha,
    RsaAes128CbcSha256,
    RsaAes256CbcSha,
    RsaAes256CbcSha256,
    DheRsaAes128CbcSha,
    DheRsaAes128CbcSha256,
    DheDssAes128CbcSha,
    RsaAes128GcmSha256,
    RsaAes256GcmSha384,
    DheRsaAes128GcmSha256,
    EcdheRsaAes128CbcSha,
    Unknown,
}

impl From<CipherSuiteId> for CipherSuite {
    fn from(value: CipherSuiteId) -> CipherSuite {
        match value {
            CipherSuiteId::RsaAes128CbcSha => RsaAes128CbcSha.into(),
            CipherSuiteId::RsaAes128CbcSha256 => RsaAes128CbcSha256.into(),
            CipherSuiteId::RsaAes256CbcSha => RsaAes256CbcSha.into(),
            CipherSuiteId::RsaAes256CbcSha256 => RsaAes256CbcSha256.into(),
            CipherSuiteId::DheRsaAes128CbcSha => DheRsaAes128CbcSha.into(),
            CipherSuiteId::DheRsaAes128CbcSha256 => DheRsaAes128CbcSha256.into(),
            CipherSuiteId::DheDssAes128CbcSha => DheDssAes128CbcSha.into(),
            CipherSuiteId::RsaAes128GcmSha256 => RsaAes128GcmSha256.into(),
            CipherSuiteId::RsaAes256GcmSha384 => RsaAes256GcmSha384.into(),
            CipherSuiteId::DheRsaAes128GcmSha256 => DheRsaAes128GcmSha256.into(),
            CipherSuiteId::EcdheRsaAes128CbcSha => EcdheRsaAes128CbcSha.into(),
            _ => Unknown.into(),
        }
    }
}

#[derive(Debug)]
pub struct Unknown;

impl CipherSuiteMethods for Unknown {
    fn encode(&self) -> u16 {
        unimplemented!()
    }

    fn params(&self) -> CipherSuiteParams {
        CipherSuiteParams {
            name: "UNKNOWN",
            mac_algorithm: MacAlgorithm::HmacSha1,
            enc_algorithm: EncAlgorithm::Aes128Cbc,
            key_exchange_algorithm: KeyExchangeAlgorithm::Rsa,
            prf_algorithm: PrfAlgorithm::Sha256,
        }
    }
}

#[enum_dispatch(CipherSuite)]
pub trait CipherSuiteMethods: Debug {
    fn encode(&self) -> u16;
    fn params(&self) -> CipherSuiteParams;
}

#[derive(Debug)]
pub struct RsaAes128CbcSha;

impl CipherSuiteMethods for RsaAes128CbcSha {
    fn encode(&self) -> u16 {
        return CipherSuiteId::RsaAes128CbcSha.into();
    }

    fn params(&self) -> CipherSuiteParams {
        CipherSuiteParams {
            name: "TLS_RSA_WITH_AES_128_CBC_SHA",
            mac_algorithm: MacAlgorithm::HmacSha1,
            enc_algorithm: EncAlgorithm::Aes128Cbc,
            key_exchange_algorithm: KeyExchangeAlgorithm::Rsa,
            prf_algorithm: PrfAlgorithm::Sha256,
        }
    }
}

#[derive(Debug)]
pub struct RsaAes256CbcSha;

impl CipherSuiteMethods for RsaAes256CbcSha {
    fn encode(&self) -> u16 {
        return CipherSuiteId::RsaAes256CbcSha.into();
    }
    fn params(&self) -> CipherSuiteParams {
        CipherSuiteParams {
            name: "TLS_RSA_WITH_AES_256_CBC_SHA",
            mac_algorithm: MacAlgorithm::HmacSha1,
            enc_algorithm: EncAlgorithm::Aes256Cbc,
            key_exchange_algorithm: KeyExchangeAlgorithm::Rsa,
            prf_algorithm: PrfAlgorithm::Sha256,
        }
    }
}

#[derive(Debug)]
pub struct RsaAes128CbcSha256;

impl CipherSuiteMethods for RsaAes128CbcSha256 {
    fn encode(&self) -> u16 {
        return CipherSuiteId::RsaAes128CbcSha256.into();
    }
    fn params(&self) -> CipherSuiteParams {
        CipherSuiteParams {
            name: "TLS_RSA_WITH_AES_128_CBC_SHA256",
            mac_algorithm: MacAlgorithm::HmacSha256,
            enc_algorithm: EncAlgorithm::Aes128Cbc,
            key_exchange_algorithm: KeyExchangeAlgorithm::Rsa,
            prf_algorithm: PrfAlgorithm::Sha256,
        }
    }
}

#[derive(Debug)]
pub struct RsaAes256CbcSha256;

impl CipherSuiteMethods for RsaAes256CbcSha256 {
    fn encode(&self) -> u16 {
        return CipherSuiteId::RsaAes256CbcSha256.into();
    }
    fn params(&self) -> CipherSuiteParams {
        CipherSuiteParams {
            name: "TLS_RSA_WITH_AES_256_CBC_SHA256",
            mac_algorithm: MacAlgorithm::HmacSha256,
            enc_algorithm: EncAlgorithm::Aes256Cbc,
            key_exchange_algorithm: KeyExchangeAlgorithm::Rsa,
            prf_algorithm: PrfAlgorithm::Sha256,
        }
    }
}

#[derive(Debug)]
pub struct DheRsaAes128CbcSha;

impl CipherSuiteMethods for DheRsaAes128CbcSha {
    fn encode(&self) -> u16 {
        return CipherSuiteId::DheRsaAes128CbcSha.into();
    }

    fn params(&self) -> CipherSuiteParams {
        CipherSuiteParams {
            name: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
            mac_algorithm: MacAlgorithm::HmacSha1,
            enc_algorithm: EncAlgorithm::Aes128Cbc,
            key_exchange_algorithm: KeyExchangeAlgorithm::DheRsa,
            prf_algorithm: PrfAlgorithm::Sha256,
        }
    }
}

#[derive(Debug)]
pub struct DheRsaAes128CbcSha256;

impl CipherSuiteMethods for DheRsaAes128CbcSha256 {
    fn encode(&self) -> u16 {
        return CipherSuiteId::DheRsaAes128CbcSha256.into();
    }

    fn params(&self) -> CipherSuiteParams {
        CipherSuiteParams {
            name: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
            mac_algorithm: MacAlgorithm::HmacSha256,
            enc_algorithm: EncAlgorithm::Aes128Cbc,
            key_exchange_algorithm: KeyExchangeAlgorithm::DheRsa,
            prf_algorithm: PrfAlgorithm::Sha256,
        }
    }
}

#[derive(Debug)]
pub struct DheDssAes128CbcSha;

impl CipherSuiteMethods for DheDssAes128CbcSha {
    fn encode(&self) -> u16 {
        return CipherSuiteId::DheDssAes128CbcSha.into();
    }

    fn params(&self) -> CipherSuiteParams {
        CipherSuiteParams {
            name: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
            mac_algorithm: MacAlgorithm::HmacSha1,
            enc_algorithm: EncAlgorithm::Aes128Cbc,
            key_exchange_algorithm: KeyExchangeAlgorithm::DheDss,
            prf_algorithm: PrfAlgorithm::Sha256,
        }
    }
}

#[derive(Debug)]
pub struct RsaAes128GcmSha256;

impl CipherSuiteMethods for RsaAes128GcmSha256 {
    fn encode(&self) -> u16 {
        return CipherSuiteId::RsaAes128GcmSha256.into();
    }

    fn params(&self) -> CipherSuiteParams {
        CipherSuiteParams {
            name: "TLS_RSA_WITH_AES_128_GCM_SHA256",
            mac_algorithm: MacAlgorithm::None,
            enc_algorithm: EncAlgorithm::Aes128Gcm,
            key_exchange_algorithm: KeyExchangeAlgorithm::Rsa,
            prf_algorithm: PrfAlgorithm::Sha256,
        }
    }
}

#[derive(Debug)]
pub struct RsaAes256GcmSha384;

impl CipherSuiteMethods for RsaAes256GcmSha384 {
    fn encode(&self) -> u16 {
        return CipherSuiteId::RsaAes256GcmSha384.into();
    }

    fn params(&self) -> CipherSuiteParams {
        CipherSuiteParams {
            name: "TLS_RSA_WITH_AES_256_GCM_SHA384",
            mac_algorithm: MacAlgorithm::None,
            enc_algorithm: EncAlgorithm::Aes256Gcm,
            key_exchange_algorithm: KeyExchangeAlgorithm::Rsa,
            prf_algorithm: PrfAlgorithm::Sha384,
        }
    }
}

#[derive(Debug)]
pub struct DheRsaAes128GcmSha256;

impl CipherSuiteMethods for DheRsaAes128GcmSha256 {
    fn encode(&self) -> u16 {
        return CipherSuiteId::DheRsaAes128GcmSha256.into();
    }

    fn params(&self) -> CipherSuiteParams {
        CipherSuiteParams {
            name: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
            mac_algorithm: MacAlgorithm::None,
            enc_algorithm: EncAlgorithm::Aes128Gcm,
            key_exchange_algorithm: KeyExchangeAlgorithm::DheRsa,
            prf_algorithm: PrfAlgorithm::Sha256,
        }
    }
}

#[derive(Debug)]
pub struct EcdheRsaAes128CbcSha;

impl CipherSuiteMethods for EcdheRsaAes128CbcSha {
    fn encode(&self) -> u16 {
        return CipherSuiteId::EcdheRsaAes128CbcSha.into();
    }

    fn params(&self) -> CipherSuiteParams {
        CipherSuiteParams {
            name: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            mac_algorithm: MacAlgorithm::HmacSha1,
            enc_algorithm: EncAlgorithm::Aes128Cbc,
            key_exchange_algorithm: KeyExchangeAlgorithm::EcdheRsa,
            prf_algorithm: PrfAlgorithm::Sha256,
        }
    }
}
