use log::trace;

use crate::{
    TLSError, TLSResult,
    alert::try_parse_alert,
    connection::ConnState,
    encoding::{Reader, TlsCodable},
    messages::{
        ProtocolVersion, TLSCiphertext, TLSContentType, TlsHandshake, TlsMessage,
        try_parse_handshake,
    },
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

    fn try_parse_ciphertext(&mut self) -> TLSResult<TLSCiphertext> {
        if self.buffer.len() < 5 {
            return Err(TLSError::NeedData.into());
        }

        let content_type = TLSContentType::try_from(self.buffer[0])?;

        let version = ProtocolVersion {
            major: self.buffer[1],
            minor: self.buffer[2],
        };

        if !(version.major == 3 && version.minor == 3) {
            return Err(TLSError::InvalidProtocolVersion(version.major, version.minor).into());
        }

        let fragment_len = u16::from_be_bytes([self.buffer[3], self.buffer[4]]) as usize;

        if self.buffer.len() < 5 + fragment_len {
            return Err(TLSError::NeedData.into());
        }

        self.buffer.drain(..5);
        let fragment = self.buffer.drain(..fragment_len).collect();

        Ok(TLSCiphertext {
            content_type,
            version,
            fragment,
        })
    }

    pub fn feed(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    pub fn try_parse_message(&mut self, conn_state: &mut ConnState) -> TLSResult<TlsMessage> {
        loop {
            let plaintext = self
                .try_parse_ciphertext()
                .map(|ciphertext| conn_state.decrypt(&ciphertext))?;

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
                    println!("extended alert buffer");
                    if let Ok(alert) = try_parse_alert(&self.alert_buffer) {
                        self.alert_buffer.drain(..2);
                        return Ok(TlsMessage::Alert(alert));
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
