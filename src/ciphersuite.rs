use std::{cell::RefCell, fmt::Debug};

use crate::{
    extensions::SigAlgo,
    gcm::{decrypt_aes_cbc, decrypt_aes_gcm, encrypt_aes_cbc, encrypt_aes_gcm},
    prf::{HmacHashAlgo, hmac, prf_sha256, prf_sha384},
};
use aes::{Aes128, Aes256};
use paste::paste;
use rc4::{KeyInit, Rc4, StreamCipher as Rc4StreamCipher};
use sha2::{Digest, Sha256, Sha384};

tls_codable_enum! {
    #[repr(u8)]
    pub enum CompressionMethod {
        Null = 0
    }
}

#[derive(Debug, Clone)]
pub enum ConcreteMac {
    Null,
    HmacMd5 { key: Vec<u8>, length: usize },
    HmacSha1 { key: Vec<u8>, length: usize },
    HmacSha256 { key: Vec<u8>, length: usize },
}

impl ConcreteMac {
    pub fn compute(&self, seed: &[u8]) -> Vec<u8> {
        match self {
            Self::Null => vec![],
            Self::HmacSha1 { key, .. } => hmac(key, seed, HmacHashAlgo::Sha1),
            Self::HmacSha256 { key, .. } => hmac(key, seed, HmacHashAlgo::Sha256),
            _ => unimplemented!(),
        }
    }
    pub fn length(&self) -> usize {
        match self {
            Self::Null => 0,
            Self::HmacSha1 { .. } => 20,
            Self::HmacSha256 { .. } => 32,
            _ => unimplemented!(),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum MacType {
    Null,
    HmacMd5,
    HmacSha1,
    HmacSha256,
}

impl MacType {
    pub fn concrete(&self, key: Vec<u8>) -> ConcreteMac {
        let length = self.mac_length();
        match self {
            Self::Null => ConcreteMac::Null,
            Self::HmacSha1 => ConcreteMac::HmacSha1 { key, length },
            Self::HmacSha256 => ConcreteMac::HmacSha256 { key, length },
            _ => unimplemented!(),
        }
    }

    pub fn mac_length(&self) -> usize {
        match self {
            Self::Null => 0,
            Self::HmacSha1 => 20,
            Self::HmacSha256 => 32,
            _ => unimplemented!(),
        }
    }

    pub fn key_length(&self) -> usize {
        self.mac_length()
    }
}

#[derive(Debug, Copy, Clone)]
pub enum PrfAlgorithm {
    Null,
    Sha256,
    Sha384,
}

impl PrfAlgorithm {
    pub fn prf(&self, secret: &[u8], label: &[u8], seed: &[u8], len: usize) -> Vec<u8> {
        match self {
            Self::Sha256 => prf_sha256(secret, label, seed, len),
            Self::Sha384 => prf_sha384(secret, label, seed, len),
            _ => unimplemented!(),
        }
    }

    pub fn hash(&self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(data).to_vec(),
            Self::Sha384 => Sha384::digest(data).to_vec(),
            _ => unimplemented!(),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum CipherType {
    Stream,
    Block,
    Aead,
}

pub enum StreamCipher {
    Null,
    Rc4(RefCell<Rc4<rc4::consts::U16>>),
}

impl StreamCipher {
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        match self {
            Self::Null => plaintext.to_vec(),
            Self::Rc4(rc4) => {
                let mut buffer = plaintext.to_vec();
                rc4.borrow_mut().apply_keystream(&mut buffer);
                buffer
            }
        }
    }
    pub fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        self.encrypt(ciphertext)
    }
}

impl Clone for StreamCipher {
    fn clone(&self) -> Self {
        unimplemented!()
    }
}

impl std::fmt::Debug for StreamCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rc4State")
            .field("inner", &"<hidden>")
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct BlockCipher {
    enc_key: Vec<u8>,
    encrypt_fn: fn(&[u8], &[u8], &[u8]) -> Vec<u8>,
    decrypt_fn: fn(&[u8], &[u8], &[u8]) -> Vec<u8>,
    pub block_length: usize,
    pub record_iv_length: usize,
}

impl BlockCipher {
    pub fn encrypt(&self, plaintext: &[u8], iv: &[u8]) -> Vec<u8> {
        (self.encrypt_fn)(plaintext, &self.enc_key, iv)
    }
    pub fn decrypt(&self, ciphertext: &[u8], iv: &[u8]) -> Vec<u8> {
        (self.decrypt_fn)(ciphertext, &self.enc_key, iv)
    }
}

#[derive(Clone, Debug)]
pub struct AeadCipher {
    enc_key: Vec<u8>,
    encrypt_fn: fn(&[u8], &[u8], &[u8], &[u8]) -> Vec<u8>,
    decrypt_fn: fn(&[u8], &[u8], &[u8], &[u8]) -> Result<Vec<u8>, String>,
    pub write_iv: Vec<u8>,
    pub block_length: usize,
    pub record_iv_length: usize,
}

impl AeadCipher {
    pub fn encrypt(&self, plaintext: &[u8], iv: &[u8], aad: &[u8]) -> Vec<u8> {
        (self.encrypt_fn)(plaintext, &self.enc_key, iv, aad)
    }
    pub fn decrypt(&self, ciphertext: &[u8], iv: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
        (self.decrypt_fn)(ciphertext, &self.enc_key, iv, aad)
    }
}

#[derive(Clone, Debug)]
pub enum ConcreteEncryption {
    Block(BlockCipher),
    Aead(AeadCipher),
    Stream(StreamCipher),
}

#[derive(Debug, Copy, Clone)]
pub enum EncryptionType {
    Null,
    Aes128Cbc,
    Aes256Cbc,
    Aes128Gcm,
    Aes256Gcm,
    ThreeDesEdeCbc,
    Rc4128,
}

impl EncryptionType {
    pub fn concrete(&self, enc_key: Vec<u8>, write_iv: Vec<u8>) -> ConcreteEncryption {
        let record_iv_length = self.record_iv_length();
        match self {
            Self::Null => ConcreteEncryption::Stream(StreamCipher::Null),
            Self::Aes128Cbc => ConcreteEncryption::Block(BlockCipher {
                enc_key,
                encrypt_fn: encrypt_aes_cbc::<Aes128>,
                decrypt_fn: decrypt_aes_cbc::<Aes128>,
                block_length: self.block_length(),
                record_iv_length,
            }),
            Self::Aes256Cbc => ConcreteEncryption::Block(BlockCipher {
                enc_key,
                encrypt_fn: encrypt_aes_cbc::<Aes256>,
                decrypt_fn: decrypt_aes_cbc::<Aes256>,
                block_length: self.block_length(),
                record_iv_length,
            }),
            Self::Aes128Gcm => ConcreteEncryption::Aead(AeadCipher {
                enc_key,
                write_iv,
                encrypt_fn: encrypt_aes_gcm::<Aes128>,
                decrypt_fn: decrypt_aes_gcm::<Aes128>,
                block_length: self.block_length(),
                record_iv_length,
            }),
            Self::Aes256Gcm => ConcreteEncryption::Aead(AeadCipher {
                enc_key,
                write_iv,
                encrypt_fn: encrypt_aes_gcm::<Aes256>,
                decrypt_fn: decrypt_aes_gcm::<Aes256>,
                block_length: self.block_length(),
                record_iv_length,
            }),
            Self::Rc4128 => ConcreteEncryption::Stream(StreamCipher::Rc4(RefCell::new(
                Rc4::new_from_slice(&enc_key).unwrap(),
            ))),
            _ => unimplemented!(),
        }
    }
    pub fn key_length(&self) -> usize {
        match self {
            Self::Null => 0,
            Self::Aes128Cbc => 16,
            Self::Aes256Cbc => 32,
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm => 32,
            Self::Rc4128 => 16,
            _ => unimplemented!(),
        }
    }

    pub fn block_length(&self) -> usize {
        match self {
            Self::Aes128Cbc => 16,
            Self::Aes256Cbc => 16,
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm => 16,
            Self::Rc4128 => unreachable!(),
            _ => unimplemented!(),
        }
    }

    pub fn record_iv_length(&self) -> usize {
        match self {
            Self::Null => 0,
            Self::Aes128Gcm => 8,
            Self::Aes256Gcm => 8,
            Self::Aes128Cbc | Self::Aes256Cbc => self.block_length(),
            Self::Rc4128 => 0,
            _ => unimplemented!(),
        }
    }

    pub fn fixed_iv_length(&self) -> usize {
        match self {
            Self::Null => 0,
            Self::Aes128Gcm => 4,
            Self::Aes256Gcm => 4,
            Self::Aes128Cbc | Self::Aes256Cbc | Self::Rc4128 => 0,
            _ => unimplemented!(),
        }
    }

    pub fn cipher_type(&self) -> CipherType {
        match self {
            Self::Aes128Cbc => CipherType::Block,
            Self::Aes256Cbc => CipherType::Block,
            Self::Aes128Gcm => CipherType::Aead,
            Self::Aes256Gcm => CipherType::Aead,
            Self::Rc4128 => CipherType::Stream,
            _ => unimplemented!(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum KeyExchangeType {
    Rsa,
    Dhe,
    Ecdhe,
}

#[derive(Debug, Clone)]
pub enum KeyExchangeAlgorithm {
    Null,
    Rsa,
    DheRsa,
    DheDss,
    EcdheRsa,
    DhAnon,
    DhDss,
    DhRsa,
}

impl KeyExchangeAlgorithm {
    pub fn signature_type(&self) -> SigAlgo {
        match self {
            Self::Rsa | Self::DheRsa | Self::EcdheRsa => SigAlgo::Rsa,
            Self::DheDss => SigAlgo::Dsa,
            _ => unimplemented!(),
        }
    }
    pub fn kx_type(&self) -> KeyExchangeType {
        match self {
            Self::Rsa => KeyExchangeType::Rsa,
            Self::DheDss | Self::DheRsa => KeyExchangeType::Dhe,
            Self::EcdheRsa => KeyExchangeType::Ecdhe,
            _ => unimplemented!(),
        }
    }
}

macro_rules! define_cipher_suites {
    (
        $(
            $name:ident = $id:literal {
                mac = $mac:path,
                enc = $enc:path,
                kx  = $kx:path,
                prf = $prf:path,
            }
        ),* $(,)?
    ) => {
        paste! {

            tls_codable_enum! {
                #[repr(u16)]
                pub enum CipherSuiteId {
                    $(
                        [< $name:camel >] = $id,
                    )*
                }
            }

            pub enum CipherSuite {
                $(
                    [< $name:camel >],
                )*
            }

            impl CipherSuite {
                pub fn id(&self) -> CipherSuiteId {
                    match self {
                        $(
                            Self::[< $name:camel >] => CipherSuiteId::[< $name:camel >],
                        )*
                    }
                }

                pub fn name(&self) -> &'static str {
                    match self {
                        $(
                            Self::[< $name:camel >] => stringify!($name),
                        )*
                    }
                }

                pub fn enc_type(&self) -> EncryptionType {
                    match self {
                        $(
                            Self::[< $name:camel >] => $enc,
                        )*
                    }
                }

                pub fn mac_type(&self) -> MacType {
                    match self {
                        $(
                            Self::[< $name:camel >] => $mac,
                        )*
                    }
                }

                pub fn kx_algorithm(&self) -> KeyExchangeAlgorithm {
                    match self {
                        $(
                            Self::[< $name:camel >] => $kx,
                        )*
                    }
                }

                pub fn prf_algorithm(&self) -> PrfAlgorithm {
                    match self {
                        $(
                            Self::[< $name:camel >] => $prf,
                        )*
                    }
                }

            }

            impl From<CipherSuiteId> for CipherSuite {
                fn from(value: CipherSuiteId) -> CipherSuite {
                    match value {
                        $(
                            CipherSuiteId::[< $name:camel >] => CipherSuite::[< $name:camel >],
                        )*
                        CipherSuiteId::Unknown(_) => panic!()
                    }
                }
            }
        }
    }
}

define_cipher_suites! {

    // RFC5246 Group 1
    NULL_WITH_NULL_NULL = 0x0000 {
        mac = MacType::Null,
        enc = EncryptionType::Null,
        kx  = KeyExchangeAlgorithm::Null,
        prf = PrfAlgorithm::Sha256,
    },
    RSA_WITH_NULL_MD5 = 0x0001 {
        mac = MacType::HmacMd5,
        enc = EncryptionType::Null,
        kx  = KeyExchangeAlgorithm::Rsa,
        prf = PrfAlgorithm::Sha256,
    },
    RSA_WITH_NULL_SHA = 0x0002 {
        mac = MacType::HmacSha1,
        enc = EncryptionType::Null,
        kx  = KeyExchangeAlgorithm::Rsa,
        prf = PrfAlgorithm::Sha256,
    },
    RSA_WITH_NULL_SHA256 = 0x003b {
        mac = MacType::HmacSha256,
        enc = EncryptionType::Null,
        kx  = KeyExchangeAlgorithm::Rsa,
        prf = PrfAlgorithm::Sha256,
    },
    RSA_WITH_RC4_128_MD5 = 0x0004 {
        mac = MacType::HmacMd5,
        enc = EncryptionType::Rc4128,
        kx  = KeyExchangeAlgorithm::Rsa,
        prf = PrfAlgorithm::Sha256,
    },
    RSA_WITH_RC4_128_SHA = 0x0005 {
        mac = MacType::HmacSha1,
        enc = EncryptionType::Rc4128,
        kx  = KeyExchangeAlgorithm::Rsa,
        prf = PrfAlgorithm::Sha256,
    },
    RSA_WITH_3DES_EDE_CBC_SHA = 0x000a {
        mac = MacType::HmacSha1,
        enc = EncryptionType::ThreeDesEdeCbc,
        kx  = KeyExchangeAlgorithm::Rsa,
        prf = PrfAlgorithm::Sha256,
    },
    RSA_WITH_AES_128_CBC_SHA = 0x002f {
        mac = MacType::HmacSha1,
        enc = EncryptionType::Aes128Cbc,
        kx  = KeyExchangeAlgorithm::Rsa,
        prf = PrfAlgorithm::Sha256,
    },
    RSA_WITH_AES_256_CBC_SHA = 0x0035 {
        mac = MacType::HmacSha1,
        enc = EncryptionType::Aes256Cbc,
        kx  = KeyExchangeAlgorithm::Rsa,
        prf = PrfAlgorithm::Sha256,
    },
    RSA_WITH_AES_128_CBC_SHA256 = 0x003c {
        mac = MacType::HmacSha256,
        enc = EncryptionType::Aes128Cbc,
        kx  = KeyExchangeAlgorithm::Rsa,
        prf = PrfAlgorithm::Sha256,
    },
    RSA_WITH_AES_256_CBC_SHA256 = 0x003d {
        mac = MacType::HmacSha256,
        enc = EncryptionType::Aes256Cbc,
        kx  = KeyExchangeAlgorithm::Rsa,
        prf = PrfAlgorithm::Sha256,
    },

    // RFC5246 Group 2
    DH_DSS_WITH_3DES_EDE_CBC_SHA = 0x000d {
        mac = MacType::HmacSha1,
        enc = EncryptionType::ThreeDesEdeCbc,
        kx  = KeyExchangeAlgorithm::DhDss,
        prf = PrfAlgorithm::Sha256,
    },
    DH_RSA_WITH_3DES_EDE_CBC_SHA = 0x0010 {
        mac = MacType::HmacSha1,
        enc = EncryptionType::ThreeDesEdeCbc,
        kx  = KeyExchangeAlgorithm::DhRsa,
        prf = PrfAlgorithm::Sha256,
    },
    DHE_DSS_WITH_3DES_EDE_CBC_SHA = 0x0013 {
        mac = MacType::HmacSha1,
        enc = EncryptionType::ThreeDesEdeCbc,
        kx  = KeyExchangeAlgorithm::DheDss,
        prf = PrfAlgorithm::Sha256,
    },
    DHE_RSA_WITH_3DES_EDE_CBC_SHA = 0x0016 {
        mac = MacType::HmacSha1,
        enc = EncryptionType::ThreeDesEdeCbc,
        kx  = KeyExchangeAlgorithm::DheRsa,
        prf = PrfAlgorithm::Sha256,
    },
    DH_DSS_WITH_AES_128_CBC_SHA = 0x0030 {
        mac = MacType::HmacSha1,
        enc = EncryptionType::Aes128Cbc,
        kx  = KeyExchangeAlgorithm::DhDss,
        prf = PrfAlgorithm::Sha256,
    },
    DH_RSA_WITH_AES_128_CBC_SHA = 0x0031 {
        mac = MacType::HmacSha1,
        enc = EncryptionType::Aes128Cbc,
        kx  = KeyExchangeAlgorithm::DhRsa,
        prf = PrfAlgorithm::Sha256,
    },
    DHE_DSS_WITH_AES_128_CBC_SHA = 0x0032 {
        mac = MacType::HmacSha1,
        enc = EncryptionType::Aes128Cbc,
        kx  = KeyExchangeAlgorithm::DheDss,
        prf = PrfAlgorithm::Sha256,
    },
    DHE_RSA_WITH_AES_128_CBC_SHA = 0x0033 {
        mac = MacType::HmacSha1,
        enc = EncryptionType::Aes128Cbc,
        kx  = KeyExchangeAlgorithm::DheRsa,
        prf = PrfAlgorithm::Sha256,
    },
    DH_DSS_WITH_AES_256_CBC_SHA = 0x0036 {
        mac = MacType::HmacSha1,
        enc = EncryptionType::Aes256Cbc,
        kx  = KeyExchangeAlgorithm::DhDss,
        prf = PrfAlgorithm::Sha256,
    },
    DH_RSA_WITH_AES_256_CBC_SHA = 0x0037 {
        mac = MacType::HmacSha1,
        enc = EncryptionType::Aes256Cbc,
        kx  = KeyExchangeAlgorithm::DhRsa,
        prf = PrfAlgorithm::Sha256,
    },
    DHE_DSS_WITH_AES_256_CBC_SHA = 0x0038 {
        mac = MacType::HmacSha1,
        enc = EncryptionType::Aes256Cbc,
        kx  = KeyExchangeAlgorithm::DheDss,
        prf = PrfAlgorithm::Sha256,
    },
    DHE_RSA_WITH_AES_256_CBC_SHA = 0x0039 {
        mac = MacType::HmacSha1,
        enc = EncryptionType::Aes256Cbc,
        kx  = KeyExchangeAlgorithm::DheRsa,
        prf = PrfAlgorithm::Sha256,
    },
    DH_DSS_WITH_AES_128_CBC_SHA256 = 0x003e {
        mac = MacType::HmacSha256,
        enc = EncryptionType::Aes128Cbc,
        kx  = KeyExchangeAlgorithm::DhDss,
        prf = PrfAlgorithm::Sha256,
    },
    DH_RSA_WITH_AES_128_CBC_SHA256 = 0x003f {
        mac = MacType::HmacSha256,
        enc = EncryptionType::Aes128Cbc,
        kx  = KeyExchangeAlgorithm::DhRsa,
        prf = PrfAlgorithm::Sha256,
    },
    DHE_DSS_WITH_AES_128_CBC_SHA256 = 0x0040 {
        mac = MacType::HmacSha256,
        enc = EncryptionType::Aes128Cbc,
        kx  = KeyExchangeAlgorithm::DheDss,
        prf = PrfAlgorithm::Sha256,
    },
    DHE_RSA_WITH_AES_128_CBC_SHA256 = 0x0067 {
        mac = MacType::HmacSha256,
        enc = EncryptionType::Aes128Cbc,
        kx  = KeyExchangeAlgorithm::DheRsa,
        prf = PrfAlgorithm::Sha256,
    },
    DH_DSS_WITH_AES_256_CBC_SHA256 = 0x0068 {
        mac = MacType::HmacSha256,
        enc = EncryptionType::Aes256Cbc,
        kx  = KeyExchangeAlgorithm::DhDss,
        prf = PrfAlgorithm::Sha256,
    },
    DH_RSA_WITH_AES_256_CBC_SHA256 = 0x0069 {
        mac = MacType::HmacSha256,
        enc = EncryptionType::Aes256Cbc,
        kx  = KeyExchangeAlgorithm::DhRsa,
        prf = PrfAlgorithm::Sha256,
    },
    DHE_DSS_WITH_AES_256_CBC_SHA256 = 0x006a {
        mac = MacType::HmacSha256,
        enc = EncryptionType::Aes256Cbc,
        kx  = KeyExchangeAlgorithm::DheDss,
        prf = PrfAlgorithm::Sha256,
    },
    DHE_RSA_WITH_AES_256_CBC_SHA256 = 0x006b {
        mac = MacType::HmacSha256,
        enc = EncryptionType::Aes256Cbc,
        kx  = KeyExchangeAlgorithm::DheRsa,
        prf = PrfAlgorithm::Sha256,
    },

    // RFC5246 Group 3
    DH_anon_WITH_RC4_128_MD5 = 0x0018 {
        mac = MacType::HmacMd5,
        enc = EncryptionType::Rc4128,
        kx  = KeyExchangeAlgorithm::DhAnon,
        prf = PrfAlgorithm::Sha256,
    },
    DH_anon_WITH_3DES_EDE_CBC_SHA = 0x001b {
        mac = MacType::HmacSha1,
        enc = EncryptionType::ThreeDesEdeCbc,
        kx  = KeyExchangeAlgorithm::DhAnon,
        prf = PrfAlgorithm::Sha256,
    },
    DH_anon_WITH_AES_128_CBC_SHA = 0x0034 {
        mac = MacType::HmacSha1,
        enc = EncryptionType::Aes128Cbc,
        kx  = KeyExchangeAlgorithm::DhAnon,
        prf = PrfAlgorithm::Sha256,
    },
    DH_anon_WITH_AES_256_CBC_SHA = 0x003a {
        mac = MacType::HmacSha1,
        enc = EncryptionType::Aes256Cbc,
        kx  = KeyExchangeAlgorithm::DhAnon,
        prf = PrfAlgorithm::Sha256,
    },
    DH_anon_WITH_AES_128_CBC_SHA256 = 0x006c {
        mac = MacType::HmacSha256,
        enc = EncryptionType::Aes128Cbc,
        kx  = KeyExchangeAlgorithm::DhAnon,
        prf = PrfAlgorithm::Sha256,
    },
    DH_anon_WITH_AES_256_CBC_SHA256 = 0x006d {
        mac = MacType::HmacSha256,
        enc = EncryptionType::Aes256Cbc,
        kx  = KeyExchangeAlgorithm::DhAnon,
        prf = PrfAlgorithm::Sha256,
    },

    // RFC5288 Galois Counter Mode
    RSA_WITH_AES_128_GCM_SHA256 = 0x009c {
        mac = MacType::Null,
        enc = EncryptionType::Aes128Gcm,
        kx  = KeyExchangeAlgorithm::Rsa,
        prf = PrfAlgorithm::Sha256,
    },
    RSA_WITH_AES_256_GCM_SHA384 = 0x009d {
        mac = MacType::Null,
        enc = EncryptionType::Aes256Gcm,
        kx  = KeyExchangeAlgorithm::Rsa,
        prf = PrfAlgorithm::Sha384,
    },
    DHE_RSA_WITH_AES_128_GCM_SHA256 = 0x009e {
        mac = MacType::Null,
        enc = EncryptionType::Aes128Gcm,
        kx  = KeyExchangeAlgorithm::DheRsa,
        prf = PrfAlgorithm::Sha256,
    },
    DHE_RSA_WITH_AES_256_GCM_SHA384 = 0x009f {
        mac = MacType::Null,
        enc = EncryptionType::Aes256Gcm,
        kx  = KeyExchangeAlgorithm::DheRsa,
        prf = PrfAlgorithm::Sha384,
    },
    DH_RSA_WITH_AES_128_GCM_SHA256 = 0x00a0 {
        mac = MacType::Null,
        enc = EncryptionType::Aes128Gcm,
        kx  = KeyExchangeAlgorithm::DhRsa,
        prf = PrfAlgorithm::Sha256,
    },
    DH_RSA_WITH_AES_256_GCM_SHA384 = 0x00a1 {
        mac = MacType::Null,
        enc = EncryptionType::Aes256Gcm,
        kx  = KeyExchangeAlgorithm::DhRsa,
        prf = PrfAlgorithm::Sha384,
    },
    DHE_DSS_WITH_AES_128_GCM_SHA256 = 0x00a2 {
        mac = MacType::Null,
        enc = EncryptionType::Aes128Gcm,
        kx  = KeyExchangeAlgorithm::DheDss,
        prf = PrfAlgorithm::Sha256,
    },
    DHE_DSS_WITH_AES_256_GCM_SHA384 = 0x00a3 {
        mac = MacType::Null,
        enc = EncryptionType::Aes256Gcm,
        kx  = KeyExchangeAlgorithm::DheDss,
        prf = PrfAlgorithm::Sha384,
    },
    DH_DSS_WITH_AES_128_GCM_SHA256 = 0x00a5 {
        mac = MacType::Null,
        enc = EncryptionType::Aes128Gcm,
        kx  = KeyExchangeAlgorithm::DhDss,
        prf = PrfAlgorithm::Sha256,
    },
    DH_DSS_WITH_AES_256_GCM_SHA384 = 0x00a4 {
        mac = MacType::Null,
        enc = EncryptionType::Aes256Gcm,
        kx  = KeyExchangeAlgorithm::DhDss,
        prf = PrfAlgorithm::Sha384,
    },
    DH_anon_WITH_AES_128_GCM_SHA256 = 0x00a6 {
        mac = MacType::Null,
        enc = EncryptionType::Aes128Gcm,
        kx  = KeyExchangeAlgorithm::DhAnon,
        prf = PrfAlgorithm::Sha256,
    },
    DH_anon_WITH_AES_256_GCM_SHA384 = 0x00a7 {
        mac = MacType::Null,
        enc = EncryptionType::Aes256Gcm,
        kx  = KeyExchangeAlgorithm::DhAnon,
        prf = PrfAlgorithm::Sha384,
    },
}
