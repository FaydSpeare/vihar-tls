use std::fmt::Debug;

use aes::{cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit}, Aes128, Aes256};
use enum_dispatch::enum_dispatch;
use crate::{prf::hmac, TLSResult};

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
    DheRsa,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct CipherSuiteParams {
    pub name: &'static str,
    pub mac_algorithm: MacAlgorithm,
    pub enc_algorithm: EncAlgorithm,
    pub key_exchange_algorithm: KeyExchangeAlgorithm,
}

#[enum_dispatch]
#[derive(Debug)]
pub enum CipherSuite {
    RsaAes128CbcSha(RsaAes128CbcSha),
    RsaAes128CbcSha256(RsaAes128CbcSha256),
    RsaAes256CbcSha(RsaAes256CbcSha),
    RsaAes256CbcSha256(RsaAes256CbcSha256),
    DheRsaAes128CbcSha(DheRsaAes128CbcSha),
    DheRsaAes128CbcSha256(DheRsaAes128CbcSha256),
}

#[enum_dispatch(CipherSuite)]
pub trait CipherSuiteMethods: Debug {
    fn encode(&self) -> [u8; 2];
    fn params(&self) -> CipherSuiteParams;
}

#[derive(Debug)]
pub struct RsaAes128CbcSha;

impl CipherSuiteMethods for RsaAes128CbcSha {
    fn encode(&self) -> [u8; 2] {
        return [0x00, 0x2f];
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
    fn encode(&self) -> [u8; 2] {
        return [0x00, 0x35];
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
    fn encode(&self) -> [u8; 2] {
        return [0x00, 0x3c];
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
    fn encode(&self) -> [u8; 2] {
        return [0x00, 0x3d];
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
pub struct RsaNullSha;

impl CipherSuiteMethods for RsaNullSha {
    fn encode(&self) -> [u8; 2] {
        return [0x00, 0x02];
    }
    fn params(&self) -> CipherSuiteParams {
        CipherSuiteParams {
            name: "TLS_RSA_WITH_NULL_SHA",
            mac_algorithm: MacAlgorithm::HmacSha1,
            enc_algorithm: EncAlgorithm::None,
            key_exchange_algorithm: KeyExchangeAlgorithm::Rsa,
        }
    }
}

#[derive(Debug)]
pub struct DheRsaAes128CbcSha;

impl CipherSuiteMethods for DheRsaAes128CbcSha {
    fn encode(&self) -> [u8; 2] {
        return [0x00, 0x33];
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
    fn encode(&self) -> [u8; 2] {
        return [0x00, 0x67];
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


pub fn get_cipher_suite(value: u16) -> TLSResult<CipherSuite> {
    match value {
        0x002f => Ok(RsaAes128CbcSha.into()),
        0x0035 => Ok(RsaAes256CbcSha.into()),
        0x003c => Ok(RsaAes128CbcSha256.into()),
        0x003d => Ok(RsaAes256CbcSha256.into()),
        0x0033 => Ok(DheRsaAes128CbcSha.into()),
        0x0067 => Ok(DheRsaAes128CbcSha256.into()),
        _ => Err("unsupported cipher suite".into())
    }
}
