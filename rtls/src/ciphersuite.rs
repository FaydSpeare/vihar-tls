use std::fmt::Debug;

use aes::{cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit}, Aes128, Aes256};
use enum_dispatch::enum_dispatch;
use num_enum::TryFromPrimitive;
use crate::{gcm::{decrypt_aes_128_gcm, encrypt_aes_128_gcm}, prf::hmac, TLSResult};

use crate::utils;

const AES128_BLOCKSIZE: usize = 16;
const AES256_BLOCKSIZE: usize = 16;

fn decrypt_aes_128_cbc(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut plaintext = Vec::<u8>::new();
    let mut state = iv;
    let cipher = Aes128::new(&GenericArray::from_slice(key));

    assert!(ciphertext.len() % AES128_BLOCKSIZE == 0);
    for ct_block in ciphertext.chunks_exact(AES128_BLOCKSIZE) {
        let mut block = GenericArray::clone_from_slice(ct_block);
        cipher.decrypt_block(&mut block);
        let pt_block = utils::xor_bytes(&block, state);
        plaintext.extend_from_slice(&pt_block);
        state = ct_block;
    }

    plaintext
}

pub fn encrypt_aes_128_cbc(plaintext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut ciphertext = Vec::<u8>::new();
    let mut state = iv.to_vec();
    let cipher = Aes128::new(&GenericArray::from_slice(key));

    assert!(plaintext.len() % AES128_BLOCKSIZE == 0);
    for pt_block in plaintext.chunks_exact(AES128_BLOCKSIZE) {
        let input_block = utils::xor_bytes(pt_block, &state);
        let mut block = GenericArray::clone_from_slice(&input_block);
        cipher.encrypt_block(&mut block);
        ciphertext.extend_from_slice(&block);
        state = block.to_vec();
    }
    ciphertext
}

pub fn encrypt_aes_256_cbc(plaintext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut ciphertext = Vec::<u8>::new();
    let mut state = iv.to_vec();
    let cipher = Aes256::new(&GenericArray::from_slice(key));

    assert!(plaintext.len() % AES256_BLOCKSIZE == 0);
    for pt_block in plaintext.chunks_exact(AES256_BLOCKSIZE) {
        let input_block = utils::xor_bytes(pt_block, &state);
        let mut block = GenericArray::clone_from_slice(&input_block);
        cipher.encrypt_block(&mut block);
        ciphertext.extend_from_slice(&block);
        state = block.to_vec();
    }
    ciphertext
}

fn decrypt_aes_256_cbc(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut plaintext = Vec::<u8>::new();
    let mut state = iv;
    let cipher = Aes256::new(&GenericArray::from_slice(key));

    assert!(ciphertext.len() % AES256_BLOCKSIZE == 0);
    for ct_block in ciphertext.chunks_exact(AES256_BLOCKSIZE) {
        let mut block = GenericArray::clone_from_slice(ct_block);
        cipher.decrypt_block(&mut block);
        let pt_block = utils::xor_bytes(&block, state);
        plaintext.extend_from_slice(&pt_block);
        state = ct_block;
    }

    plaintext
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
            Self::HmacSha1 => hmac(key, seed, true),
            Self::HmacSha256 => hmac(key, seed, false),
            _ => unreachable!()
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum EncAlgorithm {
    None,
    Aes128Cbc,
    Aes256Cbc,
    Aes128Gcm,
}

impl EncAlgorithm {
    pub fn key_length(&self) -> usize {
        match self {
            Self::None => 16,
            Self::Aes128Cbc => 16,
            Self::Aes256Cbc => 32,
            Self::Aes128Gcm => 16,
        }
    }

    pub fn block_length(&self) -> usize {
        match self {
            Self::None => 16,
            Self::Aes128Cbc => 16,
            Self::Aes256Cbc => 16,
            Self::Aes128Gcm => 16,
        }
    }

    pub fn record_iv_length(&self) -> usize {
        match self {
            Self::Aes128Gcm => 8,
            _ => self.block_length()
        }
        
    }

    pub fn fixed_iv_length(&self) -> usize {
        match self {
            Self::Aes128Gcm => 4,
            _ => 0
        }
    }

    pub fn decrypt(&self, ciphertext: &[u8], key: &[u8], iv: &[u8], aad: &[u8]) -> Vec<u8> {
        match self {
            Self::None => ciphertext.to_vec(),
            Self::Aes128Cbc => decrypt_aes_128_cbc(ciphertext, key, iv),
            Self::Aes256Cbc => decrypt_aes_256_cbc(ciphertext, key, iv),
            Self::Aes128Gcm => decrypt_aes_128_gcm(key, iv, ciphertext, aad),
        }
    }

    pub fn encrypt(&self, plaintext: &[u8], key: &[u8], iv: &[u8], aad: &[u8]) -> Vec<u8> {
        match self {
            Self::None => plaintext.to_vec(),
            Self::Aes128Cbc => encrypt_aes_128_cbc(plaintext, key, iv),
            Self::Aes256Cbc => encrypt_aes_256_cbc(plaintext, key, iv),
            Self::Aes128Gcm => encrypt_aes_128_gcm(key, iv, plaintext, aad),
        }
    }
}

#[derive(Debug, Clone)]
pub enum KeyExchangeAlgorithm {
    Rsa,
    DheRsa,
    DheDss,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct CipherSuiteParams {
    pub name: &'static str,
    pub mac_algorithm: MacAlgorithm,
    pub enc_algorithm: EncAlgorithm,
    pub key_exchange_algorithm: KeyExchangeAlgorithm,
}

#[derive(TryFromPrimitive)]
#[repr(u16)]
enum CipherSuiteId {
    RsaAes128CbcSha = 0x002f,
    RsaAes128CbcSha256 = 0x003c,
    RsaAes256CbcSha = 0x0035,
    RsaAes256CbcSha256 = 0x003d,
    DheRsaAes128CbcSha = 0x0033,
    DheRsaAes128CbcSha256 = 0x0067,
    DheDssAes128CbcSha = 0x0032,
    RsaAes128GcmSha256 = 0x009c,
    DheRsaAes128GcmSha256 = 0x009e,
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
    DheRsaAes128GcmSha256,
}

impl CipherSuite {
    pub fn from_u16(value: u16) -> TLSResult<CipherSuite> {
        Ok(match CipherSuiteId::try_from(value)? {
            CipherSuiteId::RsaAes128CbcSha => RsaAes128CbcSha.into(),
            CipherSuiteId::RsaAes128CbcSha256 => RsaAes128CbcSha256.into(),
            CipherSuiteId::RsaAes256CbcSha => RsaAes256CbcSha.into(),
            CipherSuiteId::RsaAes256CbcSha256 => RsaAes256CbcSha256.into(),
            CipherSuiteId::DheRsaAes128CbcSha => DheRsaAes128CbcSha.into(),
            CipherSuiteId::DheRsaAes128CbcSha256 => DheRsaAes128CbcSha256.into(),
            CipherSuiteId::DheDssAes128CbcSha => DheDssAes128CbcSha.into(),
            CipherSuiteId::RsaAes128GcmSha256 => RsaAes128GcmSha256.into(),
            CipherSuiteId::DheRsaAes128GcmSha256 => DheRsaAes128GcmSha256.into(),
        })
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
        return CipherSuiteId::RsaAes128CbcSha as u16;
    }

    fn params(&self) -> CipherSuiteParams {
        CipherSuiteParams {
            name: "TLS_RSA_WITH_AES_128_CBC_SHA",
            mac_algorithm: MacAlgorithm::HmacSha1,
            enc_algorithm: EncAlgorithm::Aes128Cbc,
            key_exchange_algorithm: KeyExchangeAlgorithm::Rsa,
        }
    }
}

#[derive(Debug)]
pub struct RsaAes256CbcSha;

impl CipherSuiteMethods for RsaAes256CbcSha {
    fn encode(&self) -> u16 {
        return CipherSuiteId::RsaAes256CbcSha as u16;
    }
    fn params(&self) -> CipherSuiteParams {
        CipherSuiteParams {
            name: "TLS_RSA_WITH_AES_256_CBC_SHA",
            mac_algorithm: MacAlgorithm::HmacSha1,
            enc_algorithm: EncAlgorithm::Aes256Cbc,
            key_exchange_algorithm: KeyExchangeAlgorithm::Rsa,
        }
    }
}

#[derive(Debug)]
pub struct RsaAes128CbcSha256;

impl CipherSuiteMethods for RsaAes128CbcSha256 {
    fn encode(&self) -> u16 {
        return CipherSuiteId::RsaAes128CbcSha256 as u16;
    }
    fn params(&self) -> CipherSuiteParams {
        CipherSuiteParams {
            name: "TLS_RSA_WITH_AES_128_CBC_SHA256",
            mac_algorithm: MacAlgorithm::HmacSha256,
            enc_algorithm: EncAlgorithm::Aes128Cbc,
            key_exchange_algorithm: KeyExchangeAlgorithm::Rsa,
        }
    }
}

#[derive(Debug)]
pub struct RsaAes256CbcSha256;

impl CipherSuiteMethods for RsaAes256CbcSha256 {
    fn encode(&self) -> u16 {
        return CipherSuiteId::RsaAes256CbcSha256 as u16;
    }
    fn params(&self) -> CipherSuiteParams {
        CipherSuiteParams {
            name: "TLS_RSA_WITH_AES_256_CBC_SHA256",
            mac_algorithm: MacAlgorithm::HmacSha256,
            enc_algorithm: EncAlgorithm::Aes256Cbc,
            key_exchange_algorithm: KeyExchangeAlgorithm::Rsa,
        }
    }
}

#[derive(Debug)]
pub struct DheRsaAes128CbcSha;

impl CipherSuiteMethods for DheRsaAes128CbcSha {
    fn encode(&self) -> u16 {
        return CipherSuiteId::DheRsaAes128CbcSha as u16;
    }

    fn params(&self) -> CipherSuiteParams {
        CipherSuiteParams {
            name: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
            mac_algorithm: MacAlgorithm::HmacSha1,
            enc_algorithm: EncAlgorithm::Aes128Cbc,
            key_exchange_algorithm: KeyExchangeAlgorithm::DheRsa,
        }
    }
}

#[derive(Debug)]
pub struct DheRsaAes128CbcSha256;

impl CipherSuiteMethods for DheRsaAes128CbcSha256 {
    fn encode(&self) -> u16 {
        return CipherSuiteId::DheRsaAes128CbcSha256 as u16;
    }

    fn params(&self) -> CipherSuiteParams {
        CipherSuiteParams {
            name: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
            mac_algorithm: MacAlgorithm::HmacSha256,
            enc_algorithm: EncAlgorithm::Aes128Cbc,
            key_exchange_algorithm: KeyExchangeAlgorithm::DheRsa,
        }
    }
}

#[derive(Debug)]
pub struct DheDssAes128CbcSha;

impl CipherSuiteMethods for DheDssAes128CbcSha {
    fn encode(&self) -> u16 {
        return CipherSuiteId::DheDssAes128CbcSha as u16;
    }

    fn params(&self) -> CipherSuiteParams {
        CipherSuiteParams {
            name: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
            mac_algorithm: MacAlgorithm::HmacSha1,
            enc_algorithm: EncAlgorithm::Aes128Cbc,
            key_exchange_algorithm: KeyExchangeAlgorithm::DheDss,
        }
    }
}

#[derive(Debug)]
pub struct RsaAes128GcmSha256;

impl CipherSuiteMethods for RsaAes128GcmSha256 {
    fn encode(&self) -> u16 {
        return CipherSuiteId::RsaAes128GcmSha256 as u16;
    }

    fn params(&self) -> CipherSuiteParams {
        CipherSuiteParams {
            name: "TLS_RSA_WITH_AES_128_GCM_SHA256",
            mac_algorithm: MacAlgorithm::None,
            enc_algorithm: EncAlgorithm::Aes128Gcm,
            key_exchange_algorithm: KeyExchangeAlgorithm::Rsa,
        }
    }
}


#[derive(Debug)]
pub struct DheRsaAes128GcmSha256;

impl CipherSuiteMethods for DheRsaAes128GcmSha256 {
    fn encode(&self) -> u16 {
        return CipherSuiteId::DheRsaAes128GcmSha256 as u16;
    }

    fn params(&self) -> CipherSuiteParams {
        CipherSuiteParams {
            name: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
            mac_algorithm: MacAlgorithm::None,
            enc_algorithm: EncAlgorithm::Aes128Gcm,
            key_exchange_algorithm: KeyExchangeAlgorithm::DheRsa,
        }
    }
}
