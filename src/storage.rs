use std::fmt::Debug;

use sled::Tree;

use crate::{
    MaxFragmentLength, TlsResult,
    ciphersuite::CipherSuiteId,
    encoding::{Reader, TlsCodable},
    utils,
};

type SessionTicket = Vec<u8>;
type SessionId = Vec<u8>;
type StekName = Vec<u8>;

#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub master_secret: [u8; 48],
    pub cipher_suite: CipherSuiteId,
    pub max_fragment_len: Option<MaxFragmentLength>,
    pub extended_master_secret: bool,
}

impl SessionInfo {
    pub fn new(
        master_secret: [u8; 48],
        cipher_suite: CipherSuiteId,
        max_fragment_len: Option<MaxFragmentLength>,
        extended_master_secret: bool,
    ) -> Self {
        Self {
            master_secret,
            cipher_suite,
            max_fragment_len,
            extended_master_secret,
        }
    }
}

impl SessionInfo {
    fn encode(&self) -> Vec<u8> {
        let mut bytes = vec![];
        self.master_secret.write_to(&mut bytes);
        self.cipher_suite.write_to(&mut bytes);
        self.max_fragment_len.write_to(&mut bytes);
        self.extended_master_secret.write_to(&mut bytes);
        bytes
    }
    fn decode(mut bytes: Vec<u8>) -> TlsResult<Self> {
        let mut reader = Reader::new(bytes.as_mut());
        let master_secret: [u8; 48] = reader.consume(48)?.try_into().unwrap();
        let cipher_suite = CipherSuiteId::read_from(&mut reader)?;
        let max_fragment_len = Option::<MaxFragmentLength>::read_from(&mut reader)?;
        Ok(Self {
            master_secret,
            cipher_suite,
            max_fragment_len,
            extended_master_secret: bool::read_from(&mut reader)?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct StekInfo {
    pub key_name: [u8; 16],
    pub enc_key: [u8; 16],
    pub mac_key: [u8; 32],
}

impl Default for StekInfo {
    fn default() -> Self {
        Self::new()
    }
}

impl StekInfo {
    pub fn new() -> Self {
        Self {
            key_name: utils::get_random_bytes(16).try_into().unwrap(),
            enc_key: utils::get_random_bytes(16).try_into().unwrap(),
            mac_key: utils::get_random_bytes(32).try_into().unwrap(),
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut bytes = vec![];
        self.key_name.write_to(&mut bytes);
        self.enc_key.write_to(&mut bytes);
        self.mac_key.write_to(&mut bytes);
        bytes
    }
    fn decode(mut bytes: Vec<u8>) -> TlsResult<Self> {
        let mut reader = Reader::new(bytes.as_mut());
        Ok(Self {
            key_name: <[u8; 16]>::read_from(&mut reader)?,
            enc_key: <[u8; 16]>::read_from(&mut reader)?,
            mac_key: <[u8; 32]>::read_from(&mut reader)?,
        })
    }
}

pub trait SessionStorage: Debug {
    fn get_any_session_ticket(&self) -> TlsResult<Option<(SessionTicket, SessionInfo)>>;

    fn get_session_ticket(&self, ticket: &SessionTicket) -> TlsResult<Option<SessionInfo>>;

    fn insert_session_ticket(&self, ticket: &SessionTicket, info: SessionInfo) -> TlsResult<()>;

    fn delete_session_ticket(&self, ticket: &SessionTicket) -> TlsResult<()>;

    fn get_any_session_id(&self) -> TlsResult<Option<(SessionId, SessionInfo)>>;

    fn get_session_id(&self, id: &SessionId) -> TlsResult<Option<SessionInfo>>;

    fn insert_session_id(&self, id: &SessionId, info: SessionInfo) -> TlsResult<()>;

    fn delete_session_id(&self, id: &SessionId) -> TlsResult<()>;

    fn get_stek(&self, name: &StekName) -> TlsResult<Option<StekInfo>>;

    fn insert_stek(&self, name: &StekName, info: StekInfo) -> TlsResult<()>;

    fn delete_stek(&self, name: &StekName) -> TlsResult<()>;
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

    fn stek_db(&self) -> TlsResult<Tree> {
        Ok(self.db.open_tree("steks")?)
    }

    fn find_any(db: Tree) -> TlsResult<Option<(Vec<u8>, SessionInfo)>> {
        if let Some((k, v)) = db.last()? {
            let session_info = SessionInfo::decode(v.to_vec())?;
            return Ok(Some((k.to_vec(), session_info)));
        }
        Ok(None)
    }

    fn find_one(db: Tree, key: &[u8]) -> TlsResult<Option<SessionInfo>> {
        if let Some(x) = db.get(key)? {
            return Ok(Some(SessionInfo::decode(x.to_vec())?));
        }
        Ok(None)
    }

    fn insert_one(db: Tree, key: &[u8], info: SessionInfo) -> TlsResult<()> {
        db.insert(key, info.encode())?;
        Ok(())
    }

    fn delete_one(db: Tree, key: &[u8]) -> TlsResult<()> {
        db.remove(key)?;
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

    fn delete_session_ticket(&self, ticket: &SessionTicket) -> TlsResult<()> {
        SledSessionStore::delete_one(self.session_ticket_db()?, ticket)
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

    fn delete_session_id(&self, id: &SessionId) -> TlsResult<()> {
        SledSessionStore::delete_one(self.session_id_db()?, id)
    }

    fn get_stek(&self, name: &StekName) -> TlsResult<Option<StekInfo>> {
        if let Some(x) = self.stek_db()?.get(name)? {
            return Ok(Some(StekInfo::decode(x.to_vec())?));
        }
        Ok(None)
    }

    fn insert_stek(&self, name: &StekName, info: StekInfo) -> TlsResult<()> {
        self.stek_db()?.insert(name, info.encode())?;
        Ok(())
    }

    fn delete_stek(&self, name: &StekName) -> TlsResult<()> {
        self.stek_db()?.remove(name)?;
        Ok(())
    }
}
