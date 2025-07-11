use sha2::{Sha256, Digest};
use sha1::Sha1;
use crate::utils;

const BLOCK_SIZE_BYTES: usize = 64;


fn sha256(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}
 
fn sha1(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Sha1::new();
    hasher.update(bytes);
    hasher.finalize().to_vec()
}

pub fn hmac(key: &[u8], message: &[u8], use_sha1: bool) -> Vec<u8> {
    let hash_fn = if use_sha1 { sha1 } else { sha256 };
    let mut k = if key.len() > BLOCK_SIZE_BYTES {
        hash_fn(key).to_vec()
    } else {
        key.to_vec()
    };

    // Pad key to BLOCK_SIZE_BYTES with zeros
    if k.len() < BLOCK_SIZE_BYTES {
        k.resize(BLOCK_SIZE_BYTES, 0);
    }

    let opad = vec![0x5c; BLOCK_SIZE_BYTES];
    let ipad = vec![0x36; BLOCK_SIZE_BYTES];

    let tmp = [&utils::xor_bytes(&ipad, &k), message].concat();
    let right: &[u8] = &hash_fn(&tmp);
    let left = &utils::xor_bytes(&opad, &k) as &[u8];
    return hash_fn(&[left, right].concat()).to_vec();
}

fn p_hash(secret: &[u8], seed: &[u8], len: usize) -> Vec<u8> {
    let mut bytes: Vec<u8> = vec![];
    let mut a = hmac(secret, seed, false);
    while bytes.len() < len {
        let a_seed = [&a, seed].concat();
        let h = hmac(secret, &a_seed, false);
        bytes.extend_from_slice(&h);
        a = hmac(secret, &a, false);
    }
    bytes[..len].to_vec()
}

pub fn prf_sha256(secret: &[u8], label: &[u8], seed: &[u8], len: usize) -> Vec<u8> {
    let mut concatenated = Vec::with_capacity(label.len() + seed.len());
    concatenated.extend_from_slice(label);
    concatenated.extend_from_slice(seed);
    p_hash(secret, &concatenated, len)
}
