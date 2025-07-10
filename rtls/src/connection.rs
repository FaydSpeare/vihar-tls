#![allow(dead_code)]

use crate::{ciphersuite::CipherSuiteParams, TLSResult};

struct SecurityParams {
    enc_key_length: u8,
    block_length: u8,
    iv_length: u8,
    mac_length: u8,
    mac_key_length: u8,
    client_random: [u8; 32],
    server_random: [u8; 32],
    master_secret: [u8; 48],
}

impl SecurityParams {
    fn from_partial(params: &PartialSecurityParams) -> TLSResult<Self> {
        Ok(Self {
            enc_key_length: params.enc_key_length.ok_or("Unset param")?,
            block_length: params.block_length.ok_or("Unset param")?,
            iv_length: params.iv_length.ok_or("Unset param")?,
            mac_length: params.mac_length.ok_or("Unset param")?,
            mac_key_length: params.mac_key_length.ok_or("Unset param")?,
            master_secret: params.master_secret.ok_or("Unset param")?,
            client_random: params.client_random.ok_or("Unset param")?,
            server_random: params.server_random.ok_or("Unset param")?,
        })
    }
}

#[derive(Default)]
struct PartialSecurityParams {
    enc_key_length: Option<u8>,
    block_length: Option<u8>,
    iv_length: Option<u8>,
    mac_length: Option<u8>,
    mac_key_length: Option<u8>,
    client_random: Option<[u8; 32]>,
    server_random: Option<[u8; 32]>,
    master_secret: Option<[u8; 48]>,
    enc_pre_master_secret: Option<Vec<u8>>,
}

#[derive(Default)]
struct ConnState {
    mac_key: Vec<u8>,
    enc_key: Vec<u8>,
    seq_num: u64,
}

enum ConnStates {
    InitialPending {
        pending: PartialSecurityParams,
    },
    ReadPending {
        current: SecurityParams,
        pending: SecurityParams,
        read: Option<ConnState>,
        write: ConnState,
    },
    Synchronized {
        params: SecurityParams,
        read: ConnState,
        write: ConnState,
    },
    // For Renegotation
    ReadWritePending {
        current: SecurityParams,
        pending: PartialSecurityParams,
        read: ConnState,
        write: ConnState,
    },
}

impl Default for ConnStates {
    fn default() -> Self {
        Self::InitialPending {
            pending: PartialSecurityParams::default(),
        }
    }
}

enum SecParamsRef<'a> {
    None,
    Partial(&'a PartialSecurityParams),
    Complete(&'a SecurityParams),
}

impl ConnStates {

    // fn transition_write_state(&mut self) -> TLSResult<Self> {
    //     match self {
    //         Self::InitialPending { pending } | Self::ReadWritePending { pending, .. } => {
    //             pending.server_random = Some(value);
    //             Ok(())
    //         },
    //         _ => Err("Cannot change pending params in this state".into())
    //     }
    // }

    pub fn read_state(&self) -> Option<&ConnState> {
        match self {
            Self::InitialPending { .. } => None,
            Self::ReadPending { read, .. } => read.as_ref(),
            Self::ReadWritePending { read, .. } | Self::Synchronized { read, .. } => Some(read),
        }
    }

    pub fn write_state(&self) -> Option<&ConnState> {
        match self {
            Self::InitialPending { .. } => None,
            Self::ReadWritePending { write, .. }
            | Self::Synchronized { write, .. }
            | Self::ReadPending { write, .. } => Some(write),
        }
    }

    pub fn read_params(&self) -> SecParamsRef<'_> {
        match self {
            Self::InitialPending { .. } => SecParamsRef::None,
            Self::ReadWritePending { current, .. } | Self::ReadPending { current, .. } => {
                SecParamsRef::Complete(current)
            }
            Self::Synchronized { params, .. } => SecParamsRef::Complete(params),
        }
    }

    pub fn write_params(&self) -> SecParamsRef<'_> {
        match self {
            Self::InitialPending { .. } => SecParamsRef::None,
            Self::ReadWritePending { current, .. } => SecParamsRef::Complete(current),
            Self::ReadPending { pending, .. } => SecParamsRef::Complete(pending),
            Self::Synchronized { params, .. } => SecParamsRef::Complete(params),
        }
    }

    pub fn set_server_random(&mut self, value: [u8; 32]) -> TLSResult<()> {
        match self {
            Self::InitialPending { pending } | Self::ReadWritePending { pending, .. } => {
                pending.server_random = Some(value);
                Ok(())
            },
            _ => Err("Cannot change pending params in this state".into())
        }
    }

    pub fn set_client_random(&mut self, value: [u8; 32]) -> TLSResult<()> {
        match self {
            Self::InitialPending { pending } | Self::ReadWritePending { pending, .. } => {
                pending.client_random = Some(value);
                Ok(())
            },
            _ => Err("Cannot change pending params in this state".into())
        }
    }

    pub fn set_master_secret(&mut self, value: [u8; 48]) -> TLSResult<()> {
        match self {
            Self::InitialPending { pending } | Self::ReadWritePending { pending, .. } => {
                pending.master_secret = Some(value);
                Ok(())
            },
            _ => Err("Cannot change pending params in this state".into())
        }
    }

    pub fn set_enc_pre_master_secret(&mut self, value: Vec<u8>) -> TLSResult<()> {
        match self {
            Self::InitialPending { pending } | Self::ReadWritePending { pending, .. } => {
                pending.enc_pre_master_secret = Some(value);
                Ok(())
            },
            _ => Err("Cannot change pending params in this state".into())
        }
    }

    pub fn set_cipher_params(&mut self, cipher_params: &CipherSuiteParams) -> TLSResult<()> {
        match self {
            Self::InitialPending { pending } | Self::ReadWritePending { pending, .. } => {
                pending.block_length = Some(cipher_params.block_length);
                pending.enc_key_length = Some(cipher_params.enc_key_length);
                pending.iv_length = Some(cipher_params.iv_length);
                pending.mac_length = Some(cipher_params.mac_length);
                pending.mac_key_length = Some(cipher_params.mac_key_length);
                Ok(())
            },
            _ => Err("Cannot change pending params in this state".into())
        }
    }
}
