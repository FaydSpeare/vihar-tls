use log::debug;

use crate::ciphersuite;
use crate::ciphersuite::{EncAlgorithm, MacAlgorithm};
use crate::prf::prf_sha256;
use crate::record::{TLSCiphertext, TLSContentType, TLSPlaintext};
use crate::utils;
use crate::{TLSResult, ciphersuite::CipherSuiteParams};

const MASTER_SECRET_LEN: usize = 48;

#[derive(Debug, Clone)]
struct DerivedKeys {
    client_mac_key: Vec<u8>,
    server_mac_key: Vec<u8>,
    client_enc_key: Vec<u8>,
    server_enc_key: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SecurityParams {
    pub enc_algorithm: EncAlgorithm,
    pub mac_algorithm: MacAlgorithm,
    pub client_random: [u8; 32],
    pub server_random: [u8; 32],
    pub master_secret: [u8; 48],
}

impl SecurityParams {
    fn from_partial(params: &PartialSecurityParams) -> TLSResult<Self> {
        let client_random = params.client_random.ok_or("Unset param")?;
        let server_random = params.server_random.ok_or("Unset param")?;

        let master_secret: [u8; MASTER_SECRET_LEN] = prf_sha256(
            &params.pre_master_secret.clone().ok_or("Unset param")?,
            b"master secret",
            &[client_random.as_slice(), server_random.as_slice()].concat(),
            MASTER_SECRET_LEN,
        )
        .try_into()
        .unwrap();

        Ok(Self {
            enc_algorithm: params.enc_algorithm.ok_or("Encryption algorithm not set")?,
            mac_algorithm: params.mac_algorithm.ok_or("Mac algorithm not set")?,
            master_secret,
            client_random,
            server_random,
        })
    }

    fn derive_keys(&self) -> DerivedKeys {
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

#[derive(Default, Clone)]
pub struct PartialSecurityParams {
    pub enc_algorithm: Option<EncAlgorithm>,
    pub mac_algorithm: Option<MacAlgorithm>,
    pub client_random: Option<[u8; 32]>,
    pub server_random: Option<[u8; 32]>,
    pub master_secret: Option<[u8; 48]>,
    pub pre_master_secret: Option<Vec<u8>>,
    pub enc_pre_master_secret: Option<Vec<u8>>,
}

#[derive(Default, Clone)]
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

#[derive(Clone)]
pub struct SecureConnState {
    pub params: SecurityParams,
    pub mac_key: Vec<u8>,
    pub enc_key: Vec<u8>,
    pub seq_num: u64,
    pub verify_data: Option<Vec<u8>>,
}

impl SecureConnState {
    fn new(params: SecurityParams, enc_key: Vec<u8>, mac_key: Vec<u8>) -> Self {
        Self {
            params,
            enc_key,
            mac_key,
            seq_num: 0,
            verify_data: None
        }
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        let (iv, ciphertext) = ciphertext.split_at(self.params.enc_algorithm.iv_length());
        self.params
            .enc_algorithm
            .decrypt(ciphertext, &self.enc_key, iv)
    }

    pub fn encrypt(&self, plaintext: TLSPlaintext) -> TLSCiphertext {
        let ciphertext = self.encrypt_fragment(plaintext.content_type, &plaintext.fragment);
        TLSCiphertext::new(plaintext.content_type, ciphertext)
    }

    pub fn encrypt_fragment(&self, content_type: TLSContentType, fragment: &[u8]) -> Vec<u8> {
        // debug!("seq_num {}", self.seq_num);
        let mut bytes = Vec::<u8>::new();
        bytes.extend_from_slice(&self.seq_num.to_be_bytes());
        bytes.push(content_type as u8);
        bytes.extend([3, 3]);
        bytes.extend((fragment.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&fragment);

        // let mac = prf::hmac(&state.enc_key, &bytes, USE_SHA1);
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
        let ciphertext = self.params.enc_algorithm.encrypt(&plaintext, &self.enc_key, &iv);

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
            Self::Initial(state) => {
                debug!("...");
                state.decrypt(ciphertext)
            }
            Self::Secure(state) => {
                debug!("Dencrypted");
                state.decrypt(ciphertext)
            }
        }
    }

    pub fn encrypt<T: Into<TLSPlaintext>>(&self, plaintext: T) -> TLSCiphertext {
        match self {
            Self::Initial(state) => {
                debug!("Unencrypted");
                state.encrypt(plaintext.into())
            }
            Self::Secure(state) => {
                debug!("Encrypted");
                state.encrypt(plaintext.into())
            }
        }
    }

}

pub enum ConnStateRefMut<'a> {
    Initial(&'a mut InitialConnState),
    Secure(&'a mut SecureConnState),
}

impl ConnStateRefMut<'_> {

    pub fn inc_seq_num(&mut self) {
        match self {
            Self::Initial(state) => state.seq_num += 1,
            Self::Secure(state) => state.seq_num += 1,
        }
    }
}

#[derive(Clone)]
pub enum ConnState {
    Initial(InitialConnState),
    Secure(SecureConnState),
}

impl ConnState {

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
}


#[derive(Clone)]
pub struct Negotiating {
    pub pending: PartialSecurityParams,
    pub read: ConnState,
    pub write: ConnState,
}

impl Negotiating {
    pub fn negotiated_params(&self) -> &PartialSecurityParams {
        &self.pending
    }
}

pub struct Transitioning {
    pub read: ConnState,
    pub write: SecureConnState,
}

impl Transitioning {
    pub fn write_params(&self) -> &SecurityParams {
        &self.write.params
    }
}

pub struct Synchronised {
    pub write: SecureConnState,
    pub read: SecureConnState,
}

impl Synchronised {
    pub fn read_params(&self) -> &SecurityParams {
        &self.read.params
    }

    pub fn write_params(&self) -> &SecurityParams {
        &self.write.params
    }
}

pub enum ConnStates {
    Negotating(Negotiating),
    Transitioning(Transitioning),
    Synchronised(Synchronised),
}

impl Default for ConnStates {
    fn default() -> Self {
        Self::Negotating(Negotiating {
            pending: PartialSecurityParams::default(),
            read: ConnState::Initial(InitialConnState::default()),
            write: ConnState::Initial(InitialConnState::default()),
        })
    }
}

impl ConnStates {
    pub fn read_params(&self) -> Option<&SecurityParams> {
        match self {
            Self::Synchronised(x) => Some(x.read_params()),
            _ => None,
        }
    }

    pub fn write_params(&self) -> TLSResult<&SecurityParams> {
        let params = match self {
            Self::Negotating(_) => None,
            Self::Transitioning(x) => Some(x.write_params()),
            Self::Synchronised(x) => Some(x.write_params()),
        };
        params.ok_or("There are no write params in this state".into())
    }

    pub fn read_state(&self) -> ConnStateRef<'_> {
        match self {
            Self::Negotating(x) => x.read.as_ref(),
            Self::Transitioning(x) => x.read.as_ref(),
            Self::Synchronised(x) => ConnStateRef::Secure(&x.read),
        }
    }

    pub fn write_state(&self) -> ConnStateRef<'_> {
        match self {
            Self::Negotating(x) => x.write.as_ref(),
            Self::Transitioning(x) => ConnStateRef::Secure(&x.write),
            Self::Synchronised(x) => ConnStateRef::Secure(&x.write),
        }
    }

    pub fn write_state_mut(&mut self) -> ConnStateRefMut<'_> {
        match self {
            Self::Negotating(x) => x.write.as_mut(),
            Self::Transitioning(x) => ConnStateRefMut::Secure(&mut x.write),
            Self::Synchronised(x) => ConnStateRefMut::Secure(&mut x.write),
        }
    }

    pub fn as_negotating(&self) -> TLSResult<&Negotiating> {
        match self {
            Self::Negotating(x) => Ok(&x),
            _ => Err("Connection not in negotating state".into()),
        }
    }

    pub fn as_transitioning(&self) -> TLSResult<&Transitioning> {
        match self {
            Self::Transitioning(x) => Ok(x),
            _ => Err("Connection not in negotating state".into()),
        }
    }

    pub fn as_transitioning_mut(&mut self) -> TLSResult<&mut Transitioning> {
        match self {
            Self::Transitioning(x) => Ok(x),
            _ => Err("Connection not in negotating state".into()),
        }
    }

    pub fn as_synchronised(&self) -> TLSResult<&Synchronised> {
        match self {
            Self::Synchronised(state) => Ok(state),
            _ => Err("Connection not in synchronised state".into()),
        }
    }

    pub fn as_synchronised_mut(&mut self) -> TLSResult<&mut Synchronised> {
        match self {
            Self::Synchronised(state) => Ok(state),
            _ => Err("Connection not in synchronised state".into()),
        }
    }


    pub fn transition_write_state(&self) -> TLSResult<Self> {
        match self {
            Self::Negotating(state) => {
                let params = SecurityParams::from_partial(&state.pending)?;
                let keys = params.derive_keys();

                Ok(Self::Transitioning(Transitioning {
                    read: state.read.clone(),
                    write: SecureConnState::new(params, keys.client_enc_key, keys.client_mac_key),
                }))
            }
            _ => Err("Cannot change pending params in this state".into()),
        }
    }

    pub fn transition_read_state(&self) -> TLSResult<Self> {
        match self {
            Self::Transitioning(state) => {
                let params = state.write.params.clone();
                let keys = params.derive_keys();

                Ok(Self::Synchronised(Synchronised {
                    write: state.write.clone(),
                    read: SecureConnState::new(params, keys.server_enc_key, keys.server_mac_key),
                }))
            }
            _ => Err("Cannot change pending params in this state".into()),
        }
    }

    pub fn start_handshake(&self) -> TLSResult<Self> {
        match self {
            Self::Synchronised(state) => {
                Ok(Self::Negotating(Negotiating {
                    pending: PartialSecurityParams::default(),
                    write: ConnState::Secure(state.write.clone()),
                    read: ConnState::Secure(state.read.clone())
                }))
            }
            Self::Negotating(state) => {
                Ok(Self::Negotating(state.clone()))
            }
            _ => Err("Cannot start a handshake in this state".into()),
        }
    }

    pub fn set_server_random(&mut self, value: [u8; 32]) -> TLSResult<()> {
        match self {
            Self::Negotating(state) => {
                state.pending.server_random = Some(value);
                Ok(())
            }
            _ => Err("Cannot change pending params in this state".into()),
        }
    }

    pub fn set_client_random(&mut self, value: [u8; 32]) -> TLSResult<()> {
        match self {
            Self::Negotating(state) => {
                state.pending.client_random = Some(value);
                Ok(())
            }
            _ => Err("Cannot change pending params in this state".into()),
        }
    }

    pub fn set_pre_master_secret(&mut self, value: Vec<u8>) -> TLSResult<()> {
        match self {
            Self::Negotating(state) => {
                state.pending.pre_master_secret = Some(value);
                Ok(())
            }
            _ => Err("Cannot change pending params in this state".into()),
        }
    }

    pub fn set_enc_pre_master_secret(&mut self, value: Vec<u8>) -> TLSResult<()> {
        match self {
            Self::Negotating(state) => {
                state.pending.enc_pre_master_secret = Some(value);
                Ok(())
            }
            _ => Err("Cannot change pending params in this state".into()),
        }
    }

    pub fn set_cipher_params(&mut self, cipher_params: &CipherSuiteParams) -> TLSResult<()> {
        match self {
            Self::Negotating(state) => {
                state.pending.mac_algorithm = Some(cipher_params.mac_algorithm);
                state.pending.enc_algorithm = Some(cipher_params.enc_algorithm);
                Ok(())
            }
            _ => Err("Cannot change pending params in this state".into()),
        }
    }
}
