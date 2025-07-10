use num_enum::TryFromPrimitive;

#[allow(dead_code)]
#[derive(Debug)]
pub struct CipherSuiteParams {
    pub name: &'static str,
    pub enc_key_length: usize,
    pub block_length: usize,
    pub iv_length: usize,
    pub mac_length: usize,
    pub mac_key_length: usize,
}

pub trait CipherSuite {
    fn params(&self) -> CipherSuiteParams;
    // fn encrypt_fragment(&self, key: &[u8], plaintext: &[u8]) -> Vec<u8>;
    // fn decrypt_fragment(&self, key: &[u8], ciphertext: &[u8]) -> Vec<u8>;
}

pub struct RsaAes128CbcSha;

impl CipherSuite for RsaAes128CbcSha {
    fn params(&self) -> CipherSuiteParams {
        CipherSuiteParams {
            name: "TLS_RSA_WITH_AES_128_CBC_SHA",
            enc_key_length: 16,
            block_length: 16,
            iv_length: 16,
            mac_length: 20,
            mac_key_length: 20,
        }
    }
}

pub struct RsaAes128CbcSha256;

impl CipherSuite for RsaAes128CbcSha256 {
    fn params(&self) -> CipherSuiteParams {
        CipherSuiteParams {
            name: "TLS_RSA_WITH_AES_128_CBC_SHA256",
            enc_key_length: 16,
            block_length: 16,
            iv_length: 16,
            mac_length: 32,
            mac_key_length: 32,
        }
    }
}

#[derive(Debug, TryFromPrimitive)]
#[repr(u16)]
pub enum CipherSuiteEnum {
    RsaAes128CbcSha = 0x002f,
    RsaAes128CbcSha256 = 0x003c,
}

impl CipherSuiteEnum {
    pub fn suite(&self) -> Box<dyn CipherSuite> {
        match self {
            Self::RsaAes128CbcSha => Box::new(RsaAes128CbcSha),
            Self::RsaAes128CbcSha256 => Box::new(RsaAes128CbcSha256),
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, TryFromPrimitive)]
#[repr(u16)]
enum CipherSuiteId {
    TLS_RSA_WITH_AES_128_CBC_SHA = 0x002f,
    TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x003c,
    TLS_RSA_WITH_AES_256_CBC_SHA256 = 0x003d,
}
