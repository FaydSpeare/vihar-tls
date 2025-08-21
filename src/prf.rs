use crate::utils;
use md5 as Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384};

fn sha256(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}

fn sha384(bytes: &[u8]) -> Vec<u8> {
    Sha384::digest(bytes).to_vec()
}

fn sha1(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Sha1::new();
    hasher.update(bytes);
    hasher.finalize().to_vec()
}

fn md5(bytes: &[u8]) -> Vec<u8> {
    Md5::compute(bytes).to_vec()
}

#[derive(Debug, Copy, Clone)]
pub enum HmacHashAlgo {
    Md5,
    Sha1,
    Sha256,
    Sha384,
}

impl HmacHashAlgo {
    fn hash_fn(&self) -> fn(&[u8]) -> Vec<u8> {
        match self {
            Self::Md5 => md5,
            Self::Sha1 => sha1,
            Self::Sha256 => sha256,
            Self::Sha384 => sha384,
        }
    }
    fn block_size(&self) -> usize {
        match self {
            Self::Md5 => 64,
            Self::Sha1 => 64,
            Self::Sha256 => 64,
            Self::Sha384 => 128,
        }
    }
}

pub fn hmac(key: &[u8], message: &[u8], hash_algo: HmacHashAlgo) -> Vec<u8> {
    let hash_fn = hash_algo.hash_fn();
    let hash_block_size = hash_algo.block_size();
    let mut k = if key.len() > hash_block_size {
        hash_fn(key)
    } else {
        key.to_vec()
    };

    // Pad key to BLOCK_SIZE_BYTES with zeros
    if k.len() < hash_block_size {
        k.resize(hash_block_size, 0);
    }

    let opad = vec![0x5c; hash_block_size];
    let ipad = vec![0x36; hash_block_size];

    let tmp = [&utils::xor_bytes(&ipad, &k), message].concat();
    let right: &[u8] = &hash_fn(&tmp);
    let left = &utils::xor_bytes(&opad, &k) as &[u8];
    hash_fn(&[left, right].concat()).to_vec()
}

fn p_hash(secret: &[u8], seed: &[u8], len: usize, hash_algo: HmacHashAlgo) -> Vec<u8> {
    let mut bytes: Vec<u8> = vec![];
    let mut a = hmac(secret, seed, hash_algo);
    while bytes.len() < len {
        let a_seed = [&a, seed].concat();
        let h = hmac(secret, &a_seed, hash_algo);
        bytes.extend_from_slice(&h);
        a = hmac(secret, &a, hash_algo);
    }
    bytes[..len].to_vec()
}

pub fn prf_sha256(secret: &[u8], label: &[u8], seed: &[u8], len: usize) -> Vec<u8> {
    let mut concatenated = Vec::with_capacity(label.len() + seed.len());
    concatenated.extend_from_slice(label);
    concatenated.extend_from_slice(seed);
    p_hash(secret, &concatenated, len, HmacHashAlgo::Sha256)
}

pub fn prf_sha384(secret: &[u8], label: &[u8], seed: &[u8], len: usize) -> Vec<u8> {
    let mut concatenated = Vec::with_capacity(label.len() + seed.len());
    concatenated.extend_from_slice(label);
    concatenated.extend_from_slice(seed);
    p_hash(secret, &concatenated, len, HmacHashAlgo::Sha384)
}
