use crate::utils;
use aes::cipher::{
    BlockDecrypt, BlockEncrypt, BlockSizeUser, KeyInit, generic_array::GenericArray,
};

pub fn encrypt_aes_cbc<C: KeyInit + BlockEncrypt + BlockSizeUser>(
    plaintext: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Vec<u8> {
    let mut ciphertext = Vec::<u8>::new();
    let mut state = iv.to_vec();
    let cipher = C::new(GenericArray::from_slice(key));

    assert!(plaintext.len() % C::block_size() == 0);
    for pt_block in plaintext.chunks_exact(C::block_size()) {
        let input_block = utils::xor_bytes(pt_block, &state);
        let mut block = GenericArray::clone_from_slice(&input_block);
        cipher.encrypt_block(&mut block);
        ciphertext.extend_from_slice(&block);
        state = block.to_vec();
    }
    ciphertext
}

pub fn decrypt_aes_cbc<C: KeyInit + BlockDecrypt>(
    ciphertext: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Vec<u8> {
    let mut plaintext = Vec::<u8>::new();
    let mut state = iv;
    let cipher = C::new(GenericArray::from_slice(key));

    assert!(ciphertext.len() % C::block_size() == 0);
    for ct_block in ciphertext.chunks_exact(C::block_size()) {
        let mut block = GenericArray::clone_from_slice(ct_block);
        cipher.decrypt_block(&mut block);
        let pt_block = utils::xor_bytes(&block, state);
        plaintext.extend_from_slice(&pt_block);
        state = ct_block;
    }

    plaintext
}

fn encrypt_aes_block<C: BlockEncrypt + KeyInit>(key: &[u8], plaintext: &[u8]) -> [u8; 16] {
    let aes = C::new(GenericArray::from_slice(key));
    let mut block = GenericArray::clone_from_slice(plaintext);
    aes.encrypt_block(&mut block);
    block.to_vec().try_into().unwrap()
}

const GCM_POLY_REV: u128 = 0x87;
pub fn gf_mul(mut a: u128, mut b: u128) -> u128 {
    a = a.reverse_bits();
    b = b.reverse_bits();
    let mut c: u128 = 0;
    for i in 0..128 {
        if b & (1 << i) != 0 {
            c ^= a;
        }
        if a & (1 << 127) == 0 {
            a <<= 1;
        } else {
            a = (a << 1) ^ GCM_POLY_REV;
        }
    }
    c.reverse_bits()
}

/*
* Cleaner implementation but weird with bits reversed.
*
const GCM_POLY: u128 = 0xe100_0000_0000_0000_0000_0000_0000_0000;
pub fn gf_mul(mut a: u128, b: u128) -> u128 {
    let mut c: u128 = 0;
    for i in 0..128 {
        if b & (1 << (127 - i)) != 0 {
            c ^= a;
        }
        if a & 1 == 0 {
            a >>= 1;
        } else {
            a = (a >> 1) ^ GCM_POLY;
        }
    }
    c
}
*/

pub fn pad_to_multiple(data: &[u8], of: usize) -> Vec<u8> {
    [data, &vec![0u8; (of - (data.len() % of)) % of]].concat()
}

pub fn g_hash(h: u128, aad: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let data = [
        &pad_to_multiple(aad, 16),
        &pad_to_multiple(ciphertext, 16),
        &((aad.len() * 8) as u64).to_be_bytes()[..],
        &((ciphertext.len() * 8) as u64).to_be_bytes()[..],
    ]
    .concat();

    let mut result: u128 = 0;
    for chunk in data.chunks(16) {
        let tmp = result ^ u128::from_be_bytes(chunk.try_into().unwrap());
        result = gf_mul(h, tmp);
    }

    result.to_be_bytes().to_vec()
}

fn generate_keystream<C: BlockEncrypt + KeyInit>(
    key: &[u8],
    start_count: u128,
    len: usize,
) -> Vec<u8> {
    let mut keystream = Vec::<u8>::new();
    let mut count = start_count;
    while keystream.len() < len {
        let ptb = count.to_be_bytes();
        let ctb = encrypt_aes_block::<C>(key, &ptb);
        keystream.extend_from_slice(&ctb);
        count += 1;
    }
    keystream[..len].to_vec()
}

pub fn encrypt_aes_gcm<C: BlockEncrypt + KeyInit>(
    plaintext: &[u8],
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
) -> Vec<u8> {
    let h = u128::from_be_bytes(encrypt_aes_block::<C>(key, &0u128.to_be_bytes()));
    let counter_start = if iv.len() == 12 {
        u128::from_be_bytes([iv, &1u32.to_be_bytes()[..]].concat().try_into().unwrap())
    } else {
        u128::from_be_bytes(g_hash(h, b"", iv).try_into().unwrap())
    };
    let keystream = generate_keystream::<C>(key, counter_start + 1, plaintext.len());

    let ciphertext = utils::xor_bytes(plaintext, &keystream);
    let auth_tag = utils::xor_bytes(
        &encrypt_aes_block::<C>(key, &counter_start.to_be_bytes()),
        &g_hash(h, aad, &ciphertext),
    );
    assert_eq!(auth_tag.len(), 16);
    [ciphertext, auth_tag].concat()
}

pub fn decrypt_aes_gcm<C: BlockEncrypt + KeyInit>(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    let (ciphertext, tag) = ciphertext.split_at(ciphertext.len() - 16);
    let h = u128::from_be_bytes(encrypt_aes_block::<C>(key, &0u128.to_be_bytes()));
    let counter_start = if iv.len() == 12 {
        u128::from_be_bytes([iv, &1u32.to_be_bytes()[..]].concat().try_into().unwrap())
    } else {
        u128::from_be_bytes(g_hash(h, b"", iv).try_into().unwrap())
    };
    let keystream = generate_keystream::<C>(key, counter_start + 1, ciphertext.len());

    let plaintext = utils::xor_bytes(ciphertext, &keystream);
    let calculated_tag = utils::xor_bytes(
        &encrypt_aes_block::<C>(key, &counter_start.to_be_bytes()),
        &g_hash(h, aad, ciphertext),
    );

    if tag != calculated_tag {
        return Err("invalid tag".into());
    }
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use aes::Aes128;

    use super::*;

    #[test]
    fn test_gcm() {
        let key = utils::hex_to_bytes("feffe9928665731c6d6a8f9467308308");
        let iv = utils::hex_to_bytes("cafebabefacedbaddecaf888");
        let aad = utils::hex_to_bytes("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let plaintext = utils::hex_to_bytes(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        );
        let expected = utils::hex_to_bytes(
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e0915bc94fbc3221a5db94fae95ae7121a47",
        );
        let output = encrypt_aes_gcm::<Aes128>(&plaintext, &key, &iv, &aad);
        assert_eq!(output, expected);
    }
}
