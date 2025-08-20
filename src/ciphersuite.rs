use std::fmt::Debug;

use crate::{
    extensions::SigAlgo,
    gcm::{decrypt_aes_cbc, decrypt_aes_gcm, encrypt_aes_cbc, encrypt_aes_gcm},
    prf::{HmacHashAlgo, hmac, prf_sha256, prf_sha384},
};
use aes::{Aes128, Aes256};
use paste::paste;
use sha2::{Digest, Sha256, Sha384};

tls_codable_enum! {
    #[repr(u8)]
    pub enum CompressionMethod {
        Null = 0
    }
}

#[derive(Debug, Copy, Clone)]
pub enum MacAlgorithm {
    Null,
    HmacMd5,
    HmacSha1,
    HmacSha256,
}

impl MacAlgorithm {
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

    pub fn mac(&self, key: &[u8], seed: &[u8]) -> Vec<u8> {
        match self {
            Self::HmacSha1 => hmac(key, seed, HmacHashAlgo::Sha1),
            Self::HmacSha256 => hmac(key, seed, HmacHashAlgo::Sha256),
            _ => unimplemented!(),
        }
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

#[derive(Debug, Copy, Clone)]
pub enum EncAlgorithm {
    Null,
    Aes128Cbc,
    Aes256Cbc,
    Aes128Gcm,
    Aes256Gcm,
    ThreeDesEdeCbc,
    Rc4128,
}

impl EncAlgorithm {
    pub fn key_length(&self) -> usize {
        match self {
            Self::Aes128Cbc => 16,
            Self::Aes256Cbc => 32,
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm => 32,
            _ => unimplemented!(),
        }
    }

    pub fn block_length(&self) -> usize {
        match self {
            Self::Aes128Cbc => 16,
            Self::Aes256Cbc => 16,
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm => 16,
            _ => unimplemented!(),
        }
    }

    pub fn record_iv_length(&self) -> usize {
        match self {
            Self::Aes128Gcm => 8,
            Self::Aes256Gcm => 8,
            Self::Aes128Cbc | Self::Aes256Cbc => self.block_length(),
            _ => unimplemented!(),
        }
    }

    pub fn fixed_iv_length(&self) -> usize {
        match self {
            Self::Aes128Gcm => 4,
            Self::Aes256Gcm => 4,
            Self::Aes128Cbc | Self::Aes256Cbc => 0,
            _ => unimplemented!(),
        }
    }

    pub fn cipher_type(&self) -> CipherType {
        match self {
            Self::Aes128Cbc => CipherType::Block,
            Self::Aes256Cbc => CipherType::Block,
            Self::Aes128Gcm => CipherType::Aead,
            Self::Aes256Gcm => CipherType::Aead,
            _ => unimplemented!(),
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
            _ => unimplemented!(),
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

                pub fn enc_algorithm(&self) -> EncAlgorithm {
                    match self {
                        $(
                            Self::[< $name:camel >] => $enc,
                        )*
                    }
                }

                pub fn mac_algorithm(&self) -> MacAlgorithm {
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
        mac = MacAlgorithm::Null,
        enc = EncAlgorithm::Null,
        kx  = KeyExchangeAlgorithm::Null,
        prf = PrfAlgorithm::Sha256,
    },
    RSA_WITH_NULL_MD5 = 0x0001 {
        mac = MacAlgorithm::HmacMd5,
        enc = EncAlgorithm::Null,
        kx  = KeyExchangeAlgorithm::Rsa,
        prf = PrfAlgorithm::Sha256,
    },
    RSA_WITH_NULL_SHA = 0x0002 {
        mac = MacAlgorithm::HmacSha1,
        enc = EncAlgorithm::Null,
        kx  = KeyExchangeAlgorithm::Rsa,
        prf = PrfAlgorithm::Sha256,
    },
    RSA_WITH_NULL_SHA256 = 0x003b {
        mac = MacAlgorithm::HmacSha256,
        enc = EncAlgorithm::Null,
        kx  = KeyExchangeAlgorithm::Rsa,
        prf = PrfAlgorithm::Sha256,
    },
    RSA_WITH_RC4_128_MD5 = 0x0004 {
        mac = MacAlgorithm::HmacMd5,
        enc = EncAlgorithm::Rc4128,
        kx  = KeyExchangeAlgorithm::Rsa,
        prf = PrfAlgorithm::Sha256,
    },
    RSA_WITH_RC4_128_SHA = 0x0005 {
        mac = MacAlgorithm::HmacSha1,
        enc = EncAlgorithm::Rc4128,
        kx  = KeyExchangeAlgorithm::Rsa,
        prf = PrfAlgorithm::Sha256,
    },
    RSA_WITH_3DES_EDE_CBC_SHA = 0x000a {
        mac = MacAlgorithm::HmacSha1,
        enc = EncAlgorithm::ThreeDesEdeCbc,
        kx  = KeyExchangeAlgorithm::Rsa,
        prf = PrfAlgorithm::Sha256,
    },
    RSA_WITH_AES_128_CBC_SHA = 0x002f {
        mac = MacAlgorithm::HmacSha1,
        enc = EncAlgorithm::Aes128Cbc,
        kx  = KeyExchangeAlgorithm::Rsa,
        prf = PrfAlgorithm::Sha256,
    },
    RSA_WITH_AES_256_CBC_SHA = 0x0035 {
        mac = MacAlgorithm::HmacSha1,
        enc = EncAlgorithm::Aes256Cbc,
        kx  = KeyExchangeAlgorithm::Rsa,
        prf = PrfAlgorithm::Sha256,
    },
    RSA_WITH_AES_128_CBC_SHA256 = 0x003c {
        mac = MacAlgorithm::HmacSha256,
        enc = EncAlgorithm::Aes128Cbc,
        kx  = KeyExchangeAlgorithm::Rsa,
        prf = PrfAlgorithm::Sha256,
    },
    RSA_WITH_AES_256_CBC_SHA256 = 0x003d {
        mac = MacAlgorithm::HmacSha256,
        enc = EncAlgorithm::Aes256Cbc,
        kx  = KeyExchangeAlgorithm::Rsa,
        prf = PrfAlgorithm::Sha256,
    },

    // RFC5246 Group 2
    DH_DSS_WITH_3DES_EDE_CBC_SHA = 0x000d {
        mac = MacAlgorithm::HmacSha1,
        enc = EncAlgorithm::ThreeDesEdeCbc,
        kx  = KeyExchangeAlgorithm::DhDss,
        prf = PrfAlgorithm::Sha256,
    },
    DH_RSA_WITH_3DES_EDE_CBC_SHA = 0x0010 {
        mac = MacAlgorithm::HmacSha1,
        enc = EncAlgorithm::ThreeDesEdeCbc,
        kx  = KeyExchangeAlgorithm::DhRsa,
        prf = PrfAlgorithm::Sha256,
    },
    DHE_DSS_WITH_3DES_EDE_CBC_SHA = 0x0013 {
        mac = MacAlgorithm::HmacSha1,
        enc = EncAlgorithm::ThreeDesEdeCbc,
        kx  = KeyExchangeAlgorithm::DheDss,
        prf = PrfAlgorithm::Sha256,
    },
    DHE_RSA_WITH_3DES_EDE_CBC_SHA = 0x0016 {
        mac = MacAlgorithm::HmacSha1,
        enc = EncAlgorithm::ThreeDesEdeCbc,
        kx  = KeyExchangeAlgorithm::DheRsa,
        prf = PrfAlgorithm::Sha256,
    },
    DH_DSS_WITH_AES_128_CBC_SHA = 0x0030 {
        mac = MacAlgorithm::HmacSha1,
        enc = EncAlgorithm::Aes128Cbc,
        kx  = KeyExchangeAlgorithm::DhDss,
        prf = PrfAlgorithm::Sha256,
    },
    DH_RSA_WITH_AES_128_CBC_SHA = 0x0031 {
        mac = MacAlgorithm::HmacSha1,
        enc = EncAlgorithm::Aes128Cbc,
        kx  = KeyExchangeAlgorithm::DhRsa,
        prf = PrfAlgorithm::Sha256,
    },
    DHE_DSS_WITH_AES_128_CBC_SHA = 0x0032 {
        mac = MacAlgorithm::HmacSha1,
        enc = EncAlgorithm::Aes128Cbc,
        kx  = KeyExchangeAlgorithm::DheDss,
        prf = PrfAlgorithm::Sha256,
    },
    DHE_RSA_WITH_AES_128_CBC_SHA = 0x0033 {
        mac = MacAlgorithm::HmacSha1,
        enc = EncAlgorithm::Aes128Cbc,
        kx  = KeyExchangeAlgorithm::DheRsa,
        prf = PrfAlgorithm::Sha256,
    },
    DH_DSS_WITH_AES_256_CBC_SHA = 0x0036 {
        mac = MacAlgorithm::HmacSha1,
        enc = EncAlgorithm::Aes256Cbc,
        kx  = KeyExchangeAlgorithm::DhDss,
        prf = PrfAlgorithm::Sha256,
    },
    DH_RSA_WITH_AES_256_CBC_SHA = 0x0037 {
        mac = MacAlgorithm::HmacSha1,
        enc = EncAlgorithm::Aes256Cbc,
        kx  = KeyExchangeAlgorithm::DhRsa,
        prf = PrfAlgorithm::Sha256,
    },
    DHE_DSS_WITH_AES_256_CBC_SHA = 0x0038 {
        mac = MacAlgorithm::HmacSha1,
        enc = EncAlgorithm::Aes256Cbc,
        kx  = KeyExchangeAlgorithm::DheDss,
        prf = PrfAlgorithm::Sha256,
    },
    DHE_RSA_WITH_AES_256_CBC_SHA = 0x0039 {
        mac = MacAlgorithm::HmacSha1,
        enc = EncAlgorithm::Aes256Cbc,
        kx  = KeyExchangeAlgorithm::DheRsa,
        prf = PrfAlgorithm::Sha256,
    },
    DH_DSS_WITH_AES_128_CBC_SHA256 = 0x003e {
        mac = MacAlgorithm::HmacSha256,
        enc = EncAlgorithm::Aes128Cbc,
        kx  = KeyExchangeAlgorithm::DhDss,
        prf = PrfAlgorithm::Sha256,
    },
    DH_RSA_WITH_AES_128_CBC_SHA256 = 0x003f {
        mac = MacAlgorithm::HmacSha256,
        enc = EncAlgorithm::Aes128Cbc,
        kx  = KeyExchangeAlgorithm::DhRsa,
        prf = PrfAlgorithm::Sha256,
    },
    DHE_DSS_WITH_AES_128_CBC_SHA256 = 0x0040 {
        mac = MacAlgorithm::HmacSha256,
        enc = EncAlgorithm::Aes128Cbc,
        kx  = KeyExchangeAlgorithm::DheDss,
        prf = PrfAlgorithm::Sha256,
    },
    DHE_RSA_WITH_AES_128_CBC_SHA256 = 0x0067 {
        mac = MacAlgorithm::HmacSha256,
        enc = EncAlgorithm::Aes128Cbc,
        kx  = KeyExchangeAlgorithm::DheRsa,
        prf = PrfAlgorithm::Sha256,
    },
    DH_DSS_WITH_AES_256_CBC_SHA256 = 0x0068 {
        mac = MacAlgorithm::HmacSha256,
        enc = EncAlgorithm::Aes256Cbc,
        kx  = KeyExchangeAlgorithm::DhDss,
        prf = PrfAlgorithm::Sha256,
    },
    DH_RSA_WITH_AES_256_CBC_SHA256 = 0x0069 {
        mac = MacAlgorithm::HmacSha256,
        enc = EncAlgorithm::Aes256Cbc,
        kx  = KeyExchangeAlgorithm::DhRsa,
        prf = PrfAlgorithm::Sha256,
    },
    DHE_DSS_WITH_AES_256_CBC_SHA256 = 0x006a {
        mac = MacAlgorithm::HmacSha256,
        enc = EncAlgorithm::Aes256Cbc,
        kx  = KeyExchangeAlgorithm::DheDss,
        prf = PrfAlgorithm::Sha256,
    },
    DHE_RSA_WITH_AES_256_CBC_SHA256 = 0x006b {
        mac = MacAlgorithm::HmacSha256,
        enc = EncAlgorithm::Aes256Cbc,
        kx  = KeyExchangeAlgorithm::DheRsa,
        prf = PrfAlgorithm::Sha256,
    },

    // RFC5246 Group 3
    DH_anon_WITH_RC4_128_MD5 = 0x0018 {
        mac = MacAlgorithm::HmacMd5,
        enc = EncAlgorithm::Rc4128,
        kx  = KeyExchangeAlgorithm::DhAnon,
        prf = PrfAlgorithm::Sha256,
    },
    DH_anon_WITH_3DES_EDE_CBC_SHA = 0x001b {
        mac = MacAlgorithm::HmacSha1,
        enc = EncAlgorithm::ThreeDesEdeCbc,
        kx  = KeyExchangeAlgorithm::DhAnon,
        prf = PrfAlgorithm::Sha256,
    },
    DH_anon_WITH_AES_128_CBC_SHA = 0x0034 {
        mac = MacAlgorithm::HmacSha1,
        enc = EncAlgorithm::Aes128Cbc,
        kx  = KeyExchangeAlgorithm::DhAnon,
        prf = PrfAlgorithm::Sha256,
    },
    DH_anon_WITH_AES_256_CBC_SHA = 0x003a {
        mac = MacAlgorithm::HmacSha1,
        enc = EncAlgorithm::Aes256Cbc,
        kx  = KeyExchangeAlgorithm::DhAnon,
        prf = PrfAlgorithm::Sha256,
    },
    DH_anon_WITH_AES_128_CBC_SHA256 = 0x006c {
        mac = MacAlgorithm::HmacSha256,
        enc = EncAlgorithm::Aes128Cbc,
        kx  = KeyExchangeAlgorithm::DhAnon,
        prf = PrfAlgorithm::Sha256,
    },
    DH_anon_WITH_AES_256_CBC_SHA256 = 0x006d {
        mac = MacAlgorithm::HmacSha256,
        enc = EncAlgorithm::Aes256Cbc,
        kx  = KeyExchangeAlgorithm::DhAnon,
        prf = PrfAlgorithm::Sha256,
    },

    // RFC5288 Galois Counter Mode
    RSA_WITH_AES_128_GCM_SHA256 = 0x009c {
        mac = MacAlgorithm::HmacSha256,
        enc = EncAlgorithm::Aes128Gcm,
        kx  = KeyExchangeAlgorithm::Rsa,
        prf = PrfAlgorithm::Sha256,
    },
    RSA_WITH_AES_256_GCM_SHA384 = 0x009d {
        mac = MacAlgorithm::HmacSha256,
        enc = EncAlgorithm::Aes256Gcm,
        kx  = KeyExchangeAlgorithm::Rsa,
        prf = PrfAlgorithm::Sha384,
    },
    DHE_RSA_WITH_AES_128_GCM_SHA256 = 0x009e {
        mac = MacAlgorithm::HmacSha256,
        enc = EncAlgorithm::Aes128Gcm,
        kx  = KeyExchangeAlgorithm::DheRsa,
        prf = PrfAlgorithm::Sha256,
    },
    DHE_RSA_WITH_AES_256_GCM_SHA384 = 0x009f {
        mac = MacAlgorithm::HmacSha256,
        enc = EncAlgorithm::Aes256Gcm,
        kx  = KeyExchangeAlgorithm::DheRsa,
        prf = PrfAlgorithm::Sha384,
    },
    DH_RSA_WITH_AES_128_GCM_SHA256 = 0x00a0 {
        mac = MacAlgorithm::HmacSha256,
        enc = EncAlgorithm::Aes128Gcm,
        kx  = KeyExchangeAlgorithm::DhRsa,
        prf = PrfAlgorithm::Sha256,
    },
    DH_RSA_WITH_AES_256_GCM_SHA384 = 0x00a1 {
        mac = MacAlgorithm::HmacSha256,
        enc = EncAlgorithm::Aes256Gcm,
        kx  = KeyExchangeAlgorithm::DhRsa,
        prf = PrfAlgorithm::Sha384,
    },
    DHE_DSS_WITH_AES_128_GCM_SHA256 = 0x00a2 {
        mac = MacAlgorithm::HmacSha256,
        enc = EncAlgorithm::Aes128Gcm,
        kx  = KeyExchangeAlgorithm::DheDss,
        prf = PrfAlgorithm::Sha256,
    },
    DHE_DSS_WITH_AES_256_GCM_SHA384 = 0x00a3 {
        mac = MacAlgorithm::HmacSha256,
        enc = EncAlgorithm::Aes256Gcm,
        kx  = KeyExchangeAlgorithm::DheDss,
        prf = PrfAlgorithm::Sha384,
    },
    DH_DSS_WITH_AES_128_GCM_SHA256 = 0x00a5 {
        mac = MacAlgorithm::HmacSha256,
        enc = EncAlgorithm::Aes128Gcm,
        kx  = KeyExchangeAlgorithm::DhDss,
        prf = PrfAlgorithm::Sha256,
    },
    DH_DSS_WITH_AES_256_GCM_SHA384 = 0x00a4 {
        mac = MacAlgorithm::HmacSha256,
        enc = EncAlgorithm::Aes256Gcm,
        kx  = KeyExchangeAlgorithm::DhDss,
        prf = PrfAlgorithm::Sha384,
    },
    DH_anon_WITH_AES_128_GCM_SHA256 = 0x00a6 {
        mac = MacAlgorithm::HmacSha256,
        enc = EncAlgorithm::Aes128Gcm,
        kx  = KeyExchangeAlgorithm::DhAnon,
        prf = PrfAlgorithm::Sha256,
    },
    DH_anon_WITH_AES_256_GCM_SHA384 = 0x00a7 {
        mac = MacAlgorithm::HmacSha256,
        enc = EncAlgorithm::Aes256Gcm,
        kx  = KeyExchangeAlgorithm::DhAnon,
        prf = PrfAlgorithm::Sha384,
    },
}
