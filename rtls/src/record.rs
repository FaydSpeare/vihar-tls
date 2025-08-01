use log::trace;

use crate::{
    TLSError, TLSResult,
    alert::TLSAlert,
    connection::ConnState,
    encoding::{Reader, TlsCodable},
    messages::{ProtocolVersion, TLSCiphertext, TLSContentType, TlsHandshake, TlsMessage},
};

pub struct RecordLayer {
    buffer: Vec<u8>,
    alert_buffer: Vec<u8>,
    handshake_buffer: Vec<u8>,
}

impl RecordLayer {
    pub fn new() -> Self {
        Self {
            buffer: vec![],
            alert_buffer: vec![],
            handshake_buffer: vec![],
        }
    }

    pub fn feed(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    pub fn try_parse_message(&mut self, conn_state: &mut ConnState) -> TLSResult<TlsMessage> {
        loop {
            let mut reader = Reader::new(&self.buffer);
            let plaintext = TLSCiphertext::read_from(&mut reader)
                .map(|ciphertext| conn_state.decrypt(&ciphertext))?;
            self.buffer.drain(..reader.bytes_consumed());

            match plaintext.content_type {
                TLSContentType::ChangeCipherSpec => {
                    assert_eq!(plaintext.fragment, &[1]);
                    return Ok(TlsMessage::ChangeCipherSpec);
                }
                TLSContentType::ApplicationData => {
                    return Ok(TlsMessage::ApplicationData(plaintext.fragment));
                }
                TLSContentType::Alert => {
                    self.alert_buffer.extend(plaintext.fragment);
                    let mut reader = Reader::new(&self.alert_buffer);
                    match TLSAlert::read_from(&mut reader) {
                        Ok(alert) => {
                            self.alert_buffer.drain(..reader.bytes_consumed());
                            return Ok(TlsMessage::Alert(alert));
                        }
                        Err(e) => trace!("Alert parsing failed: {e}"),
                    }
                }
                TLSContentType::Handshake => {
                    self.handshake_buffer.extend(plaintext.fragment);
                    let mut reader = Reader::new(&self.handshake_buffer);
                    match TlsHandshake::read_from(&mut reader) {
                        Ok(handshake) => {
                            self.handshake_buffer.drain(..reader.bytes_consumed());
                            return Ok(TlsMessage::Handshake(handshake));
                        }
                        Err(e) => trace!("Handshake parsing failed: {e}"),
                    }
                }
            }
        }
    }
}
