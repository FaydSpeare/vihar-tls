use crate::{TLSResult, utils};
use aes::{
    Aes128,
    cipher::{BlockEncrypt, generic_array::GenericArray, KeyInit},
};

const AES128_BLOCKSIZE: usize = 16;

fn encrypt_aes_128_block(key: &[u8], plaintext: &[u8]) -> [u8; 16] {
    assert_eq!(key.len(), AES128_BLOCKSIZE);
    assert_eq!(plaintext.len(), AES128_BLOCKSIZE);

    let aes = Aes128::new(&GenericArray::from_slice(key));
    let mut block = GenericArray::clone_from_slice(plaintext);
    aes.encrypt_block(&mut block);
    block.try_into().unwrap()
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

fn g_hash_data(h: u128, data: &[u8]) -> Vec<u8> {
    let mut result: u128 = 0;
    for chunk in data.chunks(16) {
        let tmp = result ^ u128::from_be_bytes(chunk.try_into().unwrap());
        result = gf_mul(h, tmp);
    }
    result.to_be_bytes().to_vec()
}

fn generate_keystream(key: &[u8], start_count: u128, len: usize) -> Vec<u8> {
    let mut keystream = Vec::<u8>::new();
    let mut count = start_count;
    while keystream.len() < len {
        let ptb = count.to_be_bytes();
        let ctb = encrypt_aes_128_block(key, &ptb);
        keystream.extend_from_slice(&ctb);
        count += 1;
    }
    keystream[..len].to_vec()
}


pub fn encrypt_aes_128_gcm(
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Vec<u8> {
    let h = u128::from_be_bytes(encrypt_aes_128_block(key, &0u128.to_be_bytes()));
    let counter_start = if iv.len() == 12 {
        u128::from_be_bytes(
            [&iv[..], &1u32.to_be_bytes()[..]]
                .concat()
                .try_into()
                .unwrap()
        )
    } else {
        u128::from_be_bytes(g_hash(h, b"", iv).try_into().unwrap())
    };
    let keystream = generate_keystream(key, counter_start + 1, plaintext.len());

    let ciphertext = utils::xor_bytes(&plaintext, &keystream);
    let auth_tag = utils::xor_bytes(
        &encrypt_aes_128_block(key, &counter_start.to_be_bytes()),
        &g_hash(h, aad, &ciphertext),
    );
    assert_eq!(auth_tag.len(), 16);
    [ciphertext, auth_tag].concat()
}

pub fn decrypt_aes_128_gcm(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Vec<u8> {
    let (ciphertext, tag) = ciphertext.split_at(ciphertext.len() - 16);
    let h = u128::from_be_bytes(encrypt_aes_128_block(key, &0u128.to_be_bytes()));
    let counter_start = if iv.len() == 12 {
        u128::from_be_bytes(
            [&iv[..], &1u32.to_be_bytes()[..]]
                .concat()
                .try_into()
                .unwrap()
        )
    } else {
        u128::from_be_bytes(g_hash(h, b"", iv).try_into().unwrap())
    };
    let keystream = generate_keystream(key, counter_start + 1, ciphertext.len());

    let plaintext = utils::xor_bytes(&ciphertext, &keystream);
    let auth_tag = utils::xor_bytes(
        &encrypt_aes_128_block(key, &counter_start.to_be_bytes()),
        &g_hash(h, aad, &ciphertext),
    );

    assert_eq!(tag, auth_tag);
    plaintext
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    // Remove whitespace and newlines
    let clean_hex: String = hex.chars()
        .filter(|c| !c.is_whitespace())
        .collect();

    // Convert every 2 hex chars into a u8
    (0..clean_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean_hex[i..i+2], 16).expect("Invalid hex"))
        .collect()
}

pub fn main() -> TLSResult<()> {
    let key = hex_to_bytes("feffe9928665731c6d6a8f9467308308");
    //let iv: [u8; 12] = hex_to_bytes("cafebabefacedbaddecaf888").try_into().unwrap();
    let iv = hex_to_bytes("9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b");
    let plaintext = b"hello brother";
    let aad = hex_to_bytes("feedfacedeadbeeffeedfacedeadbeefabaddad2");

    let ciphertext = encrypt_aes_128_gcm(&key, &iv, plaintext, &aad);
    let plaintext = decrypt_aes_128_gcm(&key, &iv, &ciphertext, &aad);
    println!("{:?}", String::from_utf8(plaintext));

    Ok(())
}
