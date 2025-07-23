use crate::{
    alert::try_parse_alert, ciphersuite::EncAlgorithm, connection::ConnState, messages::{
        try_parse_handshake, ProtocolVersion, TLSCiphertext, TLSContentType, TLSPlaintext, TlsMessage
    }, TLSError, TLSResult
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

    fn decrypt_ciphertext(
        conn_state: &mut ConnState,
        ciphertext: TLSCiphertext,
    ) -> TLSResult<TLSPlaintext> {
        let decrypted = conn_state.decrypt(&ciphertext);
        match conn_state {
            ConnState::Initial(_) => Ok(TLSPlaintext::new(ciphertext.content_type, decrypted)),
            ConnState::Secure(secure_state) => {
                match secure_state.params.enc_algorithm {
                    EncAlgorithm::Aes128Gcm => {
                        Ok(TLSPlaintext::new(ciphertext.content_type, decrypted))
                    },
                    _ => {
                        let len = decrypted.len();
                        let padding = decrypted[len - 1] as usize;
                        let mac_len = secure_state.params.mac_algorithm.mac_length();
                        let fragment = decrypted[..len - padding - 1 - mac_len].to_vec();
                        let mac = decrypted[len - padding - 1 - mac_len..len - padding - 1].to_vec();

                        let mut bytes = Vec::<u8>::new();
                        bytes.extend_from_slice(&(secure_state.seq_num - 1).to_be_bytes());
                        bytes.push(ciphertext.content_type as u8);
                        bytes.extend([3, 3]);
                        bytes.extend((fragment.len() as u16).to_be_bytes());
                        bytes.extend_from_slice(&fragment);

                        assert_eq!(
                            secure_state
                                .params
                                .mac_algorithm
                                .mac(&secure_state.mac_key, &bytes),
                            mac,
                            "bad_record_mac"
                        );
                        Ok(TLSPlaintext::new(ciphertext.content_type, fragment))
                    }
                }
            }
        }
    }

    pub fn feed(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    pub fn try_parse_message(&mut self, conn_state: &mut ConnState) -> TLSResult<TlsMessage> {
        loop {
            let plaintext = self
                .try_parse_ciphertext()
                .and_then(|ciphertext| RecordLayer::decrypt_ciphertext(conn_state, ciphertext))?;

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
                    if let Ok((handshake, len)) = try_parse_handshake(&self.handshake_buffer) {
                        self.handshake_buffer.drain(..len);
                        return Ok(TlsMessage::Handshake(handshake));
                    }
                }
            }
        }
    }
}
