#![allow(dead_code)]

use crate::prf::prf;
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
    pub enc_key_length: usize,
    pub block_length: usize,
    pub iv_length: usize,
    pub mac_length: usize,
    pub mac_key_length: usize,
    pub client_random: [u8; 32],
    pub server_random: [u8; 32],
    pub master_secret: [u8; 48],
}

impl SecurityParams {
    fn from_partial(params: &PartialSecurityParams) -> TLSResult<Self> {

        let client_random = params.client_random.ok_or("Unset param")?;
        let server_random = params.server_random.ok_or("Unset param")?;

        let master_secret: [u8; MASTER_SECRET_LEN] = prf(
            &params.pre_master_secret.clone().ok_or("Unset param")?,
            b"master secret",
            &[client_random.as_slice(), server_random.as_slice()].concat(),
            MASTER_SECRET_LEN,
        ).try_into().unwrap();

        Ok(Self {
            enc_key_length: params.enc_key_length.ok_or("Unset param")?,
            block_length: params.block_length.ok_or("Unset param")?,
            iv_length: params.iv_length.ok_or("Unset param")?,
            mac_length: params.mac_length.ok_or("Unset param")?,
            mac_key_length: params.mac_key_length.ok_or("Unset param")?,
            master_secret,
            client_random,
            server_random
        })
    }

    fn derive_keys(&self) -> DerivedKeys {
        let key_block = prf(
            &self.master_secret,
            b"key expansion",
            &[self.server_random.as_slice(), self.client_random.as_slice()].concat(),
            2 * self.mac_key_length + 2 * self.enc_key_length,
        );

        let mut offset = 0;
        let client_mac_key = key_block[offset..offset + self.mac_key_length].to_vec();
        offset += self.mac_key_length;
        let server_mac_key = key_block[offset..offset + self.mac_key_length].to_vec();
        offset += self.mac_key_length;
        let client_enc_key = key_block[offset..offset + self.enc_key_length].to_vec();
        offset += self.enc_key_length;
        let server_enc_key = key_block[offset..offset + self.enc_key_length].to_vec();

        DerivedKeys {
            client_mac_key,
            server_mac_key,
            client_enc_key,
            server_enc_key
        }
    }
}

#[derive(Default)]
pub struct PartialSecurityParams {
    pub enc_key_length: Option<usize>,
    pub block_length: Option<usize>,
    pub iv_length: Option<usize>,
    pub mac_length: Option<usize>,
    pub mac_key_length: Option<usize>,
    pub client_random: Option<[u8; 32]>,
    pub server_random: Option<[u8; 32]>,
    pub master_secret: Option<[u8; 48]>,
    pub pre_master_secret: Option<Vec<u8>>,
    pub enc_pre_master_secret: Option<Vec<u8>>,
}

#[derive(Default, Clone)]
pub struct ConnState {
    pub mac_key: Vec<u8>,
    pub enc_key: Vec<u8>,
    pub seq_num: u64,
}

impl ConnState {
    fn new(enc_key: Vec<u8>, mac_key: Vec<u8>) -> Self {
        Self {
            enc_key,
            mac_key,
            seq_num: 0,
        }
    }
}

pub struct Negotiating {
    pub pending: PartialSecurityParams,
}

pub struct Transitioning {
    pending: SecurityParams,
    pub write: ConnState,
}

impl Transitioning {
    pub fn write_params(&self) -> &SecurityParams {
        &self.pending
    }
}

pub struct Synchronised {
    params: SecurityParams,
    pub write: ConnState,
    pub read: ConnState,
}

impl Synchronised {
    pub fn read_params(&self) -> &SecurityParams {
        &self.params
    }

    pub fn write_params(&self) -> &SecurityParams {
        &self.params
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
        })
    }
}

pub enum SecParamsRef<'a> {
    None,
    Partial(&'a PartialSecurityParams),
    Complete(&'a SecurityParams),
}

impl ConnStates {

    pub fn read_params(&self) -> TLSResult<&SecurityParams> {
        let params = match self {
            Self::Synchronised(x) => Some(x.read_params()),
            _ => None,
        };
        params.ok_or("There are no read params in this state".into())
    }

    pub fn write_params(&self) -> TLSResult<&SecurityParams> {
        let params = match self {
            Self::Negotating(_) => None,
            Self::Transitioning(x) => Some(x.write_params()),
            Self::Synchronised(x) => Some(x.write_params()),
        };
        params.ok_or("There are no write params in this state".into())
    }

    pub fn as_negotating(&self) -> TLSResult<&Negotiating> {
        match self {
            Self::Negotating(x) => Ok(&x),
            _ => Err("Connection not in negotating state".into()),
        }
    }

    pub fn as_transitioning(&self) -> TLSResult<&Transitioning> {
        match self {
            Self::Transitioning(x) => Ok(&x),
            _ => Err("Connection not in negotating state".into()),
        }
    }

    pub fn as_synchronised(&self) -> TLSResult<&Synchronised> {
        match self {
            Self::Synchronised(x) => Ok(&x),
            _ => Err("Connection not in synchronised state".into()),
        }
    }

    pub fn transition_write_state(&self) -> TLSResult<Self> {
        match self {
            Self::Negotating(x) => {
                let params = SecurityParams::from_partial(&x.pending)?;
                let keys = params.derive_keys();

                Ok(Self::Transitioning(Transitioning {
                    pending: params,
                    write: ConnState::new(keys.client_enc_key, keys.client_mac_key),
                }))
            }
            _ => Err("Cannot change pending params in this state".into()),
        }
    }

    pub fn transition_read_state(&self) -> TLSResult<Self> {
        match self {
            Self::Transitioning(x) => {
                let keys = x.pending.derive_keys();

                Ok(Self::Synchronised(Synchronised {
                    params: x.pending.clone(),
                    write: x.write.clone(),
                    read: ConnState::new(keys.server_enc_key, keys.server_mac_key),
                }))
            }
            _ => Err("Cannot change pending params in this state".into()),
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
                state.pending.block_length = Some(cipher_params.block_length);
                state.pending.enc_key_length = Some(cipher_params.enc_key_length);
                state.pending.iv_length = Some(cipher_params.iv_length);
                state.pending.mac_length = Some(cipher_params.mac_length);
                state.pending.mac_key_length = Some(cipher_params.mac_key_length);
                Ok(())
            }
            _ => Err("Cannot change pending params in this state".into()),
        }
    }
}
