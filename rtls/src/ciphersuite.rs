use aes::{cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit}, Aes128, Aes256};
use num_enum::TryFromPrimitive;
use crate::prf::hmac;

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
}

impl EncAlgorithm {
    pub fn key_length(&self) -> usize {
        match self {
            Self::None => 16,
            Self::Aes128Cbc => 16,
            Self::Aes256Cbc => 32,
        }
    }

    pub fn block_length(&self) -> usize {
        match self {
            Self::None => 16,
            Self::Aes128Cbc => 16,
            Self::Aes256Cbc => 16,
        }
    }

    pub fn iv_length(&self) -> usize {
        self.block_length()
    }

    pub fn decrypt(&self, ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
        match self {
            Self::None => ciphertext.to_vec(),
            Self::Aes128Cbc => decrypt_aes_128_cbc(ciphertext, key, iv),
            Self::Aes256Cbc => decrypt_aes_256_cbc(ciphertext, key, iv),
        }
    }

    pub fn encrypt(&self, plaintext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
        match self {
            Self::None => plaintext.to_vec(),
            Self::Aes128Cbc => encrypt_aes_128_cbc(plaintext, key, iv),
            Self::Aes256Cbc => encrypt_aes_256_cbc(plaintext, key, iv),
        }
    }
}

#[derive(Debug, Clone)]
pub enum KeyExchangeAlgorithm {
    Rsa,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct CipherSuiteParams {
    pub name: &'static str,
    pub mac_algorithm: MacAlgorithm,
    pub enc_algorithm: EncAlgorithm,
    pub key_exchange_algorithm: KeyExchangeAlgorithm,
}

pub trait CipherSuite {
    fn params(&self) -> CipherSuiteParams;
}

pub struct RsaAes128CbcSha;

impl CipherSuite for RsaAes128CbcSha {
    fn params(&self) -> CipherSuiteParams {
        CipherSuiteParams {
            name: "TLS_RSA_WITH_AES_128_CBC_SHA",
            mac_algorithm: MacAlgorithm::HmacSha1,
            enc_algorithm: EncAlgorithm::Aes128Cbc,
            key_exchange_algorithm: KeyExchangeAlgorithm::Rsa,
        }
    }
}

pub struct RsaAes256CbcSha;

impl CipherSuite for RsaAes256CbcSha {
    fn params(&self) -> CipherSuiteParams {
        CipherSuiteParams {
            name: "TLS_RSA_WITH_AES_256_CBC_SHA",
            mac_algorithm: MacAlgorithm::HmacSha1,
            enc_algorithm: EncAlgorithm::Aes256Cbc,
            key_exchange_algorithm: KeyExchangeAlgorithm::Rsa,
        }
    }
}

pub struct RsaAes128CbcSha256;

impl CipherSuite for RsaAes128CbcSha256 {
    fn params(&self) -> CipherSuiteParams {
        CipherSuiteParams {
            name: "TLS_RSA_WITH_AES_128_CBC_SHA256",
            mac_algorithm: MacAlgorithm::HmacSha256,
            enc_algorithm: EncAlgorithm::Aes128Cbc,
            key_exchange_algorithm: KeyExchangeAlgorithm::Rsa,
        }
    }
}

pub struct RsaAes256CbcSha256;

impl CipherSuite for RsaAes256CbcSha256 {
    fn params(&self) -> CipherSuiteParams {
        CipherSuiteParams {
            name: "TLS_RSA_WITH_AES_256_CBC_SHA256",
            mac_algorithm: MacAlgorithm::HmacSha256,
            enc_algorithm: EncAlgorithm::Aes256Cbc,
            key_exchange_algorithm: KeyExchangeAlgorithm::Rsa,
        }
    }
}

pub struct RsaNullSha;

impl CipherSuite for RsaNullSha {
    fn params(&self) -> CipherSuiteParams {
        CipherSuiteParams {
            name: "TLS_RSA_WITH_NULL_SHA",
            mac_algorithm: MacAlgorithm::HmacSha1,
            enc_algorithm: EncAlgorithm::None,
            key_exchange_algorithm: KeyExchangeAlgorithm::Rsa,
        }
    }
}

#[derive(Debug, TryFromPrimitive)]
#[repr(u16)]
pub enum CipherSuiteEnum {
    RsaNullSha = 0x0002,
    RsaAes128CbcSha = 0x002f,
    RsaAes256CbcSha = 0x0035,
    RsaAes128CbcSha256 = 0x003c,
    RsaAes256CbcSha256 = 0x003d,
}

impl CipherSuiteEnum {
    pub fn suite(&self) -> Box<dyn CipherSuite> {
        match self {
            Self::RsaNullSha => Box::new(RsaNullSha),
            Self::RsaAes128CbcSha => Box::new(RsaAes128CbcSha),
            Self::RsaAes256CbcSha => Box::new(RsaAes256CbcSha),
            Self::RsaAes128CbcSha256 => Box::new(RsaAes128CbcSha256),
            Self::RsaAes256CbcSha256 => Box::new(RsaAes256CbcSha256),
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, TryFromPrimitive)]
#[repr(u16)]
pub enum CipherSuiteId {
    TLS_RSA_WITH_NULL_SHA = 0x0002,
    TLS_RSA_WITH_AES_128_CBC_SHA = 0x002f,
    TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035,
    TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x003c,
    TLS_RSA_WITH_AES_256_CBC_SHA256 = 0x003d,
}
