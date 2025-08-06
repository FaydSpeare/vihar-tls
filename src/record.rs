use crate::{
    TlsPolicy, TlsValidateable,
    alert::{TlsAlert, TlsAlertDesc},
    connection::ConnState,
    encoding::{Reader, TlsCodable},
    errors::TlsError,
    messages::{TlsCiphertext, TlsContentType, TlsHandshake, TlsMessage},
};
use log::trace;

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

    pub fn try_parse_message(
        &mut self,
        conn_state: &mut ConnState,
        policy: &TlsPolicy,
        max_fragmentation_len: usize,
    ) -> Result<TlsMessage, TlsError> {
        loop {
            let mut reader = Reader::new(&self.buffer);

            let ciphertext = TlsCiphertext::read_from(&mut reader)?;
            //println!("ciphertext len {}", ciphertext.fragment.len());
            if ciphertext.fragment.len() > max_fragmentation_len + 2048 {
                return Err(TlsError::Alert(TlsAlert::fatal(
                    TlsAlertDesc::RecordOverflow,
                )));
            }

            let plaintext = conn_state.decrypt(ciphertext)?;
            //println!("plaintext len {}", plaintext.fragment.len());
            if plaintext.fragment.len() > max_fragmentation_len {
                return Err(TlsError::Alert(TlsAlert::fatal(
                    TlsAlertDesc::RecordOverflow,
                )));
            }

            plaintext.validate(policy)?;

            self.buffer.drain(..reader.bytes_consumed());
            match plaintext.content_type {
                TlsContentType::ChangeCipherSpec => {
                    return Ok(TlsMessage::ChangeCipherSpec);
                }
                TlsContentType::ApplicationData => {
                    return Ok(TlsMessage::ApplicationData(plaintext.fragment));
                }
                TlsContentType::Alert => {
                    self.alert_buffer.extend(plaintext.fragment);
                    let mut reader = Reader::new(&self.alert_buffer);
                    match TlsAlert::read_from(&mut reader) {
                        Ok(alert) => {
                            self.alert_buffer.drain(..reader.bytes_consumed());
                            return Ok(TlsMessage::Alert(alert));
                        }
                        Err(e) => trace!("Alert parsing failed: {e}"),
                    }
                }
                TlsContentType::Handshake => {
                    self.handshake_buffer.extend(plaintext.fragment);
                    let mut reader = Reader::new(&self.handshake_buffer);
                    match TlsHandshake::read_from(&mut reader) {
                        Ok(handshake) => {
                            // Validation of handshake, which may return errors
                            handshake.validate(&policy)?;

                            self.handshake_buffer.drain(..reader.bytes_consumed());
                            return Ok(TlsMessage::Handshake(handshake));
                        }
                        Err(e) => trace!("Handshake parsing failed: {e}"),
                    }
                }
                TlsContentType::Unknown(x) => unimplemented!("Unknown content type: {x}"),
            }
        }
    }
}
