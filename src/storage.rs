use std::fmt::Debug;

use crate::{TlsResult, ciphersuite::CipherSuiteId};

type SessionTicket = Vec<u8>;

#[derive(Debug, Clone)]
pub struct SessionTicketInfo {
    pub master_secret: [u8; 48],
    pub cipher_suite: CipherSuiteId,
}

impl SessionTicketInfo {
    pub fn new(master_secret: [u8; 48], cipher_suite: CipherSuiteId) -> Self {
        Self {
            master_secret,
            cipher_suite,
        }
    }
}

impl SessionTicketInfo {
    fn encode(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.extend_from_slice(&self.master_secret);
        bytes.extend_from_slice(&u16::from(self.cipher_suite).to_be_bytes());
        bytes
    }
    fn decode(bytes: Vec<u8>) -> Self {
        let master_secret: [u8; 48] = bytes[..48].try_into().unwrap();
        let cipher_suite = CipherSuiteId::from(u16::from_be_bytes(bytes[48..].try_into().unwrap()));
        Self {
            master_secret,
            cipher_suite,
        }
    }
}

pub trait SessionTicketStorage: Debug {
    fn get_one(&self) -> TlsResult<Option<SessionTicket>>;
    fn get(&self, ticket: &SessionTicket) -> TlsResult<Option<SessionTicketInfo>>;
    fn put(&self, ticket: SessionTicket, info: SessionTicketInfo) -> TlsResult<()>;
}

#[derive(Debug, Clone)]
pub struct SledSessionTicketStore {
    db: sled::Db,
}

impl SledSessionTicketStore {
    pub fn open(path: &str) -> TlsResult<Self> {
        Ok(Self {
            db: sled::open(path)?,
        })
    }
}

impl SessionTicketStorage for SledSessionTicketStore {
    fn get_one(&self) -> TlsResult<Option<SessionTicket>> {
        Ok(self.db.last()?.map(|(k, _)| k.to_vec()))
    }

    fn get(&self, ticket: &SessionTicket) -> TlsResult<Option<SessionTicketInfo>> {
        let value = self.db.get(ticket)?;
        Ok(value.map(|x| SessionTicketInfo::decode(x.to_vec())))
    }
    fn put(&self, ticket: SessionTicket, info: SessionTicketInfo) -> TlsResult<()> {
        self.db.insert(ticket, info.encode())?;
        Ok(())
    }
}
