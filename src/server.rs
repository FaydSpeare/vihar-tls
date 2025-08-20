use std::{
    io::{Read, Write},
    rc::Rc,
};

use crate::{TlsResult, client::TlsConfig, connection::TlsConnection, state_machine::TlsEntity};

pub struct TlsServer<T: Read + Write> {
    config: Rc<TlsConfig>,
    connection: TlsConnection<T>,
}

impl<T: Read + Write> TlsServer<T> {
    pub fn new(config: TlsConfig, stream: T) -> Self {
        let config = Rc::new(config);
        Self {
            connection: TlsConnection::new(TlsEntity::Server, stream, config.clone()),
            config,
        }
    }

    pub fn write(&mut self, buf: &[u8]) -> TlsResult<usize> {
        if !self.connection.is_established() {
            self.connection
                .complete_handshake(TlsEntity::Server, &self.config)?;
        }
        self.connection.write(buf)?;
        Ok(buf.len())
    }

    pub fn serve(&mut self) -> TlsResult<()> {
        loop {
            self.connection.next_message()?;
        }
    }
}
