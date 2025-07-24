use sha2::{Sha256, Digest};

use crate::ciphersuite::{CipherType, EncAlgorithm, MacAlgorithm, PrfAlgorithm};
use crate::messages::{TLSCiphertext, TLSPlaintext};
use crate::prf::prf_sha256;
use crate::utils;

#[derive(Debug, Clone)]
pub struct DerivedKeys {
    pub client_mac_key: Vec<u8>,
    pub server_mac_key: Vec<u8>,
    pub client_enc_key: Vec<u8>,
    pub server_enc_key: Vec<u8>,
    pub client_write_iv: Vec<u8>,
    pub server_write_iv: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SecurityParams {
    pub cipher_suite_id: u16,
    pub enc_algorithm: EncAlgorithm,
    pub mac_algorithm: MacAlgorithm,
    pub prf_algorithm: PrfAlgorithm,
    pub client_random: [u8; 32],
    pub server_random: [u8; 32],
    pub master_secret: [u8; 48],
}

impl SecurityParams {
    
    pub fn client_verify_data(&self, handshakes: &[u8]) -> Vec<u8> {
        let seed = self.prf_algorithm.hash(handshakes);
        self.prf_algorithm.prf(&self.master_secret, b"client finished", &seed, 12)
    }

    pub fn server_verify_data(&self, handshakes: &[u8]) -> Vec<u8> {
        let seed = self.prf_algorithm.hash(handshakes);
        self.prf_algorithm.prf(&self.master_secret, b"server finished", &seed, 12)
    }

    pub fn derive_keys(&self) -> DerivedKeys {
        let mac_key_len = self.mac_algorithm.key_length();
        let enc_key_len = self.enc_algorithm.key_length();
        let fixed_iv_len = self.enc_algorithm.fixed_iv_length();

        let key_block = self.prf_algorithm.prf(
            &self.master_secret,
            b"key expansion",
            &[self.server_random.as_slice(), self.client_random.as_slice()].concat(),
            2 * mac_key_len + 2 * enc_key_len + 2 * fixed_iv_len,
        );

        let mut offset = 0;
        let client_mac_key = key_block[offset..offset + mac_key_len].to_vec();
        offset += mac_key_len;
        let server_mac_key = key_block[offset..offset + mac_key_len].to_vec();
        offset += mac_key_len;
        let client_enc_key = key_block[offset..offset + enc_key_len].to_vec();
        offset += enc_key_len;
        let server_enc_key = key_block[offset..offset + enc_key_len].to_vec();
        offset += enc_key_len;
        let client_write_iv = key_block[offset..offset + fixed_iv_len].to_vec();
        offset += fixed_iv_len;
        let server_write_iv = key_block[offset..offset + fixed_iv_len].to_vec();

        DerivedKeys {
            client_mac_key,
            server_mac_key,
            client_enc_key,
            server_enc_key,
            client_write_iv,
            server_write_iv,
        }
    }
}

#[derive(Default, Debug, Clone)]
pub struct InitialConnState {
    pub seq_num: u64,
}

impl InitialConnState {
    pub fn encrypt(&mut self, plaintext: TLSPlaintext) -> TLSCiphertext {
        self.seq_num += 1;
        TLSCiphertext::new(plaintext.content_type, plaintext.fragment)
    }

    pub fn decrypt(&mut self, ciphertext: &TLSCiphertext) -> TLSPlaintext {
        self.seq_num += 1;
        TLSPlaintext::new(ciphertext.content_type, ciphertext.fragment.to_vec())
    }
}

#[derive(Clone, Debug)]
pub struct SecureConnState {
    pub params: SecurityParams,
    pub mac_key: Vec<u8>,
    pub enc_key: Vec<u8>,
    pub write_iv: Vec<u8>,
    pub seq_num: u64,
}

impl SecureConnState {
    pub fn new(
        params: SecurityParams,
        enc_key: Vec<u8>,
        mac_key: Vec<u8>,
        write_iv: Vec<u8>,
    ) -> Self {
        Self {
            params,
            enc_key,
            mac_key,
            write_iv,
            seq_num: 0,
        }
    }

    fn decrypt_block_cipher(&self, ciphertext: &TLSCiphertext) -> Vec<u8> {
        let content_type = ciphertext.content_type;
        let (iv, ciphertext) = ciphertext
            .fragment
            .split_at(self.params.enc_algorithm.record_iv_length());
        let decrypted = self
            .params
            .enc_algorithm
            .decrypt(ciphertext, &self.enc_key, iv, None);

        let len = decrypted.len();
        let padding = decrypted[len - 1] as usize;
        let mac_len = self.params.mac_algorithm.mac_length();
        let fragment = decrypted[..len - padding - 1 - mac_len].to_vec();
        let actual_mac = decrypted[len - padding - 1 - mac_len..len - padding - 1].to_vec();

        let mut bytes = Vec::<u8>::new();
        bytes.extend_from_slice(&self.seq_num.to_be_bytes());
        bytes.push(content_type as u8);
        bytes.extend([3, 3]);
        bytes.extend((fragment.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&fragment);

        let expected_mac = self.params.mac_algorithm.mac(&self.mac_key, &bytes);
        assert_eq!(expected_mac, actual_mac, "bad_record_mac");
        fragment
    }

    fn decrypt_aead_cipher(&self, ciphertext: &TLSCiphertext) -> Vec<u8> {
        let content_type = ciphertext.content_type;
        let (explicit, ciphertext) = ciphertext
            .fragment
            .split_at(self.params.enc_algorithm.record_iv_length());
        let iv = [&self.write_iv, explicit].concat();
        let mut aad = Vec::<u8>::new();
        aad.extend_from_slice(&self.seq_num.to_be_bytes());
        aad.push(content_type as u8);
        aad.extend([3, 3]);
        // Remeber the -16 to remove the tag length
        aad.extend(((ciphertext.len() - 16) as u16).to_be_bytes());
        self.params
            .enc_algorithm
            .decrypt(ciphertext, &self.enc_key, &iv, Some(&aad))
    }


    fn encrypt_block_cipher(&self, plaintext: &TLSPlaintext) -> Vec<u8> {
        let mut bytes = Vec::<u8>::new();
        bytes.extend_from_slice(&self.seq_num.to_be_bytes());
        bytes.push(plaintext.content_type as u8);
        bytes.extend([plaintext.version.major, plaintext.version.minor]);
        bytes.extend((plaintext.fragment.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&plaintext.fragment);

        let mac = self.params.mac_algorithm.mac(&self.mac_key, &bytes);
        let block_len = self.params.enc_algorithm.block_length();
        let padding_len = block_len - ((plaintext.fragment.len() + mac.len() + 1) % block_len);
        let mut padding = Vec::<u8>::new();
        for _ in 0..padding_len {
            padding.push(padding_len as u8);
        }

        let mut to_encrypt = Vec::<u8>::new();
        to_encrypt.extend_from_slice(&plaintext.fragment);
        to_encrypt.extend_from_slice(&mac);
        to_encrypt.extend_from_slice(&padding);
        to_encrypt.push(padding_len as u8);

        let iv = utils::get_random_bytes(self.params.enc_algorithm.record_iv_length());
        let ciphertext = self
            .params
            .enc_algorithm
            .encrypt(&to_encrypt, &self.enc_key, &iv, None);

        let mut fragment = Vec::<u8>::new();
        fragment.extend_from_slice(&iv);
        fragment.extend_from_slice(&ciphertext);
        fragment
    }

    fn encrypt_aead_cipher(&self, plaintext: &TLSPlaintext) -> Vec<u8> {
        let implicit: [u8; 4] = self.write_iv.clone().try_into().unwrap();
        let explicit = utils::get_random_bytes(self.params.enc_algorithm.record_iv_length());
        let nonce = [&implicit[..], &explicit[..]].concat();
        assert_eq!(nonce.len(), 12);

        let mut aad = Vec::<u8>::new();
        aad.extend_from_slice(&self.seq_num.to_be_bytes());
        aad.push(plaintext.content_type as u8);
        aad.extend([plaintext.version.major, plaintext.version.minor]);
        aad.extend((plaintext.fragment.len() as u16).to_be_bytes());
        let aead_ciphertext = self.params.enc_algorithm.encrypt(
            &plaintext.fragment,
            &self.enc_key,
            &nonce,
            Some(&aad),
        );
        [&explicit, &aead_ciphertext[..]].concat()
    }

    pub fn encrypt(&mut self, plaintext: &TLSPlaintext) -> TLSCiphertext {
        let ciphertext = match self.params.enc_algorithm.cipher_type() {
            CipherType::Block => self.encrypt_block_cipher(plaintext),
            CipherType::Aead => self.encrypt_aead_cipher(plaintext),
            CipherType::Stream => unimplemented!(),
        };
        self.seq_num += 1;
        TLSCiphertext::new(plaintext.content_type, ciphertext)
    }

    pub fn decrypt(&mut self, ciphertext: &TLSCiphertext) -> TLSPlaintext {
        let fragment = match self.params.enc_algorithm.cipher_type() {
            CipherType::Block => self.decrypt_block_cipher(ciphertext),
            CipherType::Aead => self.decrypt_aead_cipher(ciphertext),
            CipherType::Stream => unimplemented!(),
        };
        self.seq_num += 1;
        TLSPlaintext::new(ciphertext.content_type, fragment)
    }

}

#[derive(Debug, Clone)]
pub enum ConnState {
    Initial(InitialConnState),
    Secure(SecureConnState),
}

impl ConnState {
    pub fn encrypt<T: Into<TLSPlaintext>>(&mut self, plaintext: T) -> TLSCiphertext {
        match self {
            Self::Initial(state) => state.encrypt(plaintext.into()),
            Self::Secure(state) => state.encrypt(&plaintext.into()),
        }
    }

    pub fn decrypt(&mut self, ciphertext: &TLSCiphertext) -> TLSPlaintext {
        match self {
            Self::Initial(state) => state.decrypt(ciphertext),
            Self::Secure(state) => state.decrypt(ciphertext),
        }
    }
}
