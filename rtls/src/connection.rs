use crate::ciphersuite::{EncAlgorithm, MacAlgorithm};
use crate::prf::prf_sha256;
use crate::record::{TLSCiphertext, TLSContentType, TLSPlaintext};
use crate::{utils, TLSResult};

#[derive(Debug, Clone)]
pub struct DerivedKeys {
    pub client_mac_key: Vec<u8>,
    pub server_mac_key: Vec<u8>,
    pub client_enc_key: Vec<u8>,
    pub server_enc_key: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SecurityParams {
    pub cipher_suite_id: u16,
    pub enc_algorithm: EncAlgorithm,
    pub mac_algorithm: MacAlgorithm,
    pub client_random: [u8; 32],
    pub server_random: [u8; 32],
    pub master_secret: [u8; 48],
}

impl SecurityParams {
    pub fn derive_keys(&self) -> DerivedKeys {
        let mac_key_len = self.mac_algorithm.key_length();
        let enc_key_len = self.enc_algorithm.key_length();

        let key_block = prf_sha256(
            &self.master_secret,
            b"key expansion",
            &[self.server_random.as_slice(), self.client_random.as_slice()].concat(),
            2 * mac_key_len + 2 * enc_key_len,
        );

        let mut offset = 0;
        let client_mac_key = key_block[offset..offset + mac_key_len].to_vec();
        offset += mac_key_len;
        let server_mac_key = key_block[offset..offset + mac_key_len].to_vec();
        offset += mac_key_len;
        let client_enc_key = key_block[offset..offset + enc_key_len].to_vec();
        offset += enc_key_len;
        let server_enc_key = key_block[offset..offset + enc_key_len].to_vec();

        DerivedKeys {
            client_mac_key,
            server_mac_key,
            client_enc_key,
            server_enc_key,
        }
    }
}

#[derive(Default, Debug, Clone)]
pub struct InitialConnState {
    pub seq_num: u64,
}

impl InitialConnState {
    pub fn encrypt(&self, plaintext: TLSPlaintext) -> TLSCiphertext {
        TLSCiphertext::new(plaintext.content_type, plaintext.fragment)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        ciphertext.to_vec()
    }
}

#[derive(Clone, Debug)]
pub struct SecureConnState {
    pub params: SecurityParams,
    pub mac_key: Vec<u8>,
    pub enc_key: Vec<u8>,
    pub seq_num: u64,
    pub verify_data: Option<Vec<u8>>,
}

impl SecureConnState {
    pub fn new(params: SecurityParams, enc_key: Vec<u8>, mac_key: Vec<u8>) -> Self {
        Self {
            params,
            enc_key,
            mac_key,
            seq_num: 0,
            verify_data: None,
        }
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        let (iv, ciphertext) = ciphertext.split_at(self.params.enc_algorithm.iv_length());
        self.params
            .enc_algorithm
            .decrypt(ciphertext, &self.enc_key, iv)
    }

    pub fn encrypt(&mut self, plaintext: TLSPlaintext) -> TLSCiphertext {
        let ciphertext = self.encrypt_fragment(plaintext.content_type, &plaintext.fragment);
        self.seq_num += 1;
        TLSCiphertext::new(plaintext.content_type, ciphertext)
    }

    pub fn encrypt_fragment(&self, content_type: TLSContentType, fragment: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::<u8>::new();
        bytes.extend_from_slice(&self.seq_num.to_be_bytes());
        bytes.push(content_type as u8);
        bytes.extend([3, 3]);
        bytes.extend((fragment.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&fragment);

        let mac = self.params.mac_algorithm.mac(&self.mac_key, &bytes);
        let block_len = self.params.enc_algorithm.block_length();
        let padding_len = block_len - ((fragment.len() + mac.len() + 1) % block_len);
        let mut padding = Vec::<u8>::new();
        for _ in 0..padding_len {
            padding.push(padding_len as u8);
        }

        let mut plaintext = Vec::<u8>::new();
        plaintext.extend_from_slice(&fragment);
        plaintext.extend_from_slice(&mac);
        plaintext.extend_from_slice(&padding);
        plaintext.push(padding_len as u8);

        // Encrypt
        let iv = utils::get_random_bytes(self.params.enc_algorithm.iv_length());
        let ciphertext = self
            .params
            .enc_algorithm
            .encrypt(&plaintext, &self.enc_key, &iv);

        let mut encrypted = Vec::<u8>::new();
        encrypted.extend_from_slice(&iv);
        encrypted.extend_from_slice(&ciphertext);
        encrypted
    }
}

pub enum ConnStateRef<'a> {
    Initial(&'a InitialConnState),
    Secure(&'a SecureConnState),
}

impl ConnStateRef<'_> {
    pub fn params(&self) -> Option<&SecurityParams> {
        match self {
            Self::Initial(_) => None,
            Self::Secure(state) => Some(&state.params),
        }
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        match self {
            Self::Initial(state) => state.decrypt(ciphertext),
            Self::Secure(state) => state.decrypt(ciphertext),
        }
    }
}

pub enum ConnStateRefMut<'a> {
    Initial(&'a mut InitialConnState),
    Secure(&'a mut SecureConnState),
}

impl ConnStateRefMut<'_> {
    pub fn encrypt<T: Into<TLSPlaintext>>(&mut self, plaintext: T) -> TLSCiphertext {
        match self {
            Self::Initial(state) => state.encrypt(plaintext.into()),
            Self::Secure(state) => state.encrypt(plaintext.into()),
        }
    }
}

#[derive(Debug, Clone)]
pub enum ConnState {
    Initial(InitialConnState),
    Secure(SecureConnState),
}

impl ConnState {

    pub fn into_secure(self) -> TLSResult<SecureConnState> {
        if let ConnState::Secure(state) = self {
            return Ok(state);
        }
        Err("Connection state is not secure".into())
    }

    pub fn as_ref(&self) -> ConnStateRef<'_> {
        match self {
            Self::Initial(state) => ConnStateRef::Initial(state),
            Self::Secure(state) => ConnStateRef::Secure(state),
        }
    }

    pub fn as_mut(&mut self) -> ConnStateRefMut<'_> {
        match self {
            Self::Initial(state) => ConnStateRefMut::Initial(state),
            Self::Secure(state) => ConnStateRefMut::Secure(state),
        }
    }

    pub fn encrypt<T: Into<TLSPlaintext>>(&mut self, plaintext: T) -> TLSCiphertext {
        match self {
            Self::Initial(state) => state.encrypt(plaintext.into()),
            Self::Secure(state) => state.encrypt(plaintext.into()),
        }
    }
}
