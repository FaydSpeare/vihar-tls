use std::fmt::Debug;

use sled::Tree;

use crate::{TlsResult, ciphersuite::CipherSuiteId};

type SessionTicket = Vec<u8>;
type SessionId = Vec<u8>;

#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub master_secret: [u8; 48],
    pub cipher_suite: CipherSuiteId,
}

impl SessionInfo {
    pub fn new(master_secret: [u8; 48], cipher_suite: CipherSuiteId) -> Self {
        Self {
            master_secret,
            cipher_suite,
        }
    }
}

impl SessionInfo {
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

pub trait SessionStorage: Debug {
    fn get_any_session_ticket(&self) -> TlsResult<Option<(SessionTicket, SessionInfo)>>;

    fn get_session_ticket(&self, ticket: &SessionTicket) -> TlsResult<Option<SessionInfo>>;

    fn insert_session_ticket(&self, ticket: &SessionTicket, info: SessionInfo) -> TlsResult<()>;

    fn get_any_session_id(&self) -> TlsResult<Option<(SessionId, SessionInfo)>>;

    fn get_session_id(&self, id: &SessionId) -> TlsResult<Option<SessionInfo>>;

    fn insert_session_id(&self, id: &SessionId, info: SessionInfo) -> TlsResult<()>;
}

#[derive(Debug, Clone)]
pub struct SledSessionStore {
    db: sled::Db,
}

impl SledSessionStore {
    pub fn open(path: &str) -> TlsResult<Self> {
        Ok(Self {
            db: sled::open(path)?,
        })
    }

    fn session_ticket_db(&self) -> TlsResult<Tree> {
        Ok(self.db.open_tree("session_tickets")?)
    }

    fn session_id_db(&self) -> TlsResult<Tree> {
        Ok(self.db.open_tree("session_ids")?)
    }

    fn find_any(db: Tree) -> TlsResult<Option<(Vec<u8>, SessionInfo)>> {
        Ok(db
            .last()?
            .map(|(k, v)| (k.to_vec(), SessionInfo::decode(v.to_vec()))))
    }

    fn find_one(db: Tree, key: &[u8]) -> TlsResult<Option<SessionInfo>> {
        let value = db.get(key)?;
        Ok(value.map(|x| SessionInfo::decode(x.to_vec())))
    }

    fn insert_one(db: Tree, key: &[u8], info: SessionInfo) -> TlsResult<()> {
        db.insert(key, info.encode())?;
        Ok(())
    }
}

impl SessionStorage for SledSessionStore {
    fn get_any_session_ticket(&self) -> TlsResult<Option<(SessionTicket, SessionInfo)>> {
        SledSessionStore::find_any(self.session_ticket_db()?)
    }

    fn get_session_ticket(&self, ticket: &SessionTicket) -> TlsResult<Option<SessionInfo>> {
        SledSessionStore::find_one(self.session_ticket_db()?, ticket)
    }

    fn insert_session_ticket(&self, ticket: &SessionTicket, info: SessionInfo) -> TlsResult<()> {
        SledSessionStore::insert_one(self.session_ticket_db()?, ticket, info)
    }

    fn get_any_session_id(&self) -> TlsResult<Option<(SessionId, SessionInfo)>> {
        SledSessionStore::find_any(self.session_id_db()?)
    }

    fn get_session_id(&self, id: &SessionId) -> TlsResult<Option<SessionInfo>> {
        SledSessionStore::find_one(self.session_id_db()?, id)
    }

    fn insert_session_id(&self, id: &SessionId, info: SessionInfo) -> TlsResult<()> {
        SledSessionStore::insert_one(self.session_id_db()?, id, info)
    }
}
