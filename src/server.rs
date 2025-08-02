use std::io::{Read, Write};

use crate::{TlsResult, client::TlsConfig, connection::TlsConnection, state_machine::TlsEntity};

pub struct TlsServer<T: Read + Write> {
    config: TlsConfig,
    connection: TlsConnection<T>,
}

impl<T: Read + Write> TlsServer<T> {
    pub fn new(config: TlsConfig, stream: T) -> Self {
        Self {
            connection: TlsConnection::new(TlsEntity::Server, stream, &config),
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
}
