use sha2::{Sha256, Digest};

const BLOCK_SIZE_BYTES: usize = 64;

fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(a.len(), b.len(), "Slices must be the same length");
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

fn hmac(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut k = if key.len() > BLOCK_SIZE_BYTES {
        Sha256::digest(key).to_vec()
    } else {
        key.to_vec()
    };

    // Pad key to BLOCK_SIZE_BYTES with zeros
    if k.len() < BLOCK_SIZE_BYTES {
        k.resize(BLOCK_SIZE_BYTES, 0);
    }

    let opad = vec![0x5c; BLOCK_SIZE_BYTES];
    let ipad = vec![0x36; BLOCK_SIZE_BYTES];

    let tmp = [&xor_bytes(&ipad, &k), message].concat();
    let right = &Sha256::digest(tmp).to_vec() as &[u8]; 
    let left = &xor_bytes(&opad, &k) as &[u8];

    return Sha256::digest([left, right].concat()).to_vec();
}

fn p_hash(secret: &[u8], seed: &[u8], len: usize) -> Vec<u8> {
    let mut bytes: Vec<u8> = vec![];
    let mut a = hmac(secret, seed);
    while bytes.len() < len {
        let a_seed = [&a, seed].concat();
        let h = hmac(secret, &a_seed);
        bytes.extend_from_slice(&h);
        a = hmac(secret, &a);
    }
    bytes[..len].to_vec()
}

pub fn prf(secret: &[u8], label: &[u8], seed: &[u8], len: usize) -> Vec<u8> {
    let mut concatenated = Vec::with_capacity(label.len() + seed.len());
    concatenated.extend_from_slice(label);
    concatenated.extend_from_slice(seed);
    p_hash(secret, &concatenated, len)
}
