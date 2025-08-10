use crate::alert::{TlsAlert, TlsAlertDesc};
use crate::ciphersuite::{
    CipherSuite, CipherSuiteId, CipherSuiteMethods, CipherType, CompressionAlgorithm, EncAlgorithm,
    MacAlgorithm, PrfAlgorithm,
};
use crate::client::TlsConfig;
use crate::encoding::TlsCodable;
use crate::errors::{DecodingError, TlsError};
use crate::messages::{TlsCiphertext, TlsCompressed, TlsContentType, TlsMessage, TlsPlaintext};
use crate::record::RecordLayer;
use crate::state_machine::{
    SessionIdResumption, SessionResumption, SessionTicketResumption, SessionValidation, SessionValidationRequest, TlsAction, TlsEntity, TlsEvent, TlsStateMachine
};
use crate::{TlsResult, utils};
use log::{debug, info, trace};
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct DerivedKeys {
    pub client_mac_key: Vec<u8>,
    pub server_mac_key: Vec<u8>,
    pub client_enc_key: Vec<u8>,
    pub server_enc_key: Vec<u8>,
    pub client_write_iv: Vec<u8>,
    pub server_write_iv: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SecurityParams {
    pub cipher_suite_id: CipherSuiteId,
    pub enc_algorithm: EncAlgorithm,
    pub mac_algorithm: MacAlgorithm,
    pub prf_algorithm: PrfAlgorithm,
    pub compression_algorithm: CompressionAlgorithm,
    pub client_random: [u8; 32],
    pub server_random: [u8; 32],
    pub master_secret: [u8; 48],
}

impl SecurityParams {
    pub fn new(
        client_random: [u8; 32],
        server_random: [u8; 32],
        master_secret: [u8; 48],
        cipher_suite_id: CipherSuiteId,
    ) -> Self {
        let ciphersuite = CipherSuite::from(cipher_suite_id);
        Self {
            cipher_suite_id,
            client_random,
            server_random,
            master_secret,
            enc_algorithm: ciphersuite.params().enc_algorithm,
            mac_algorithm: ciphersuite.params().mac_algorithm,
            prf_algorithm: ciphersuite.params().prf_algorithm,
            compression_algorithm: CompressionAlgorithm::Null,
        }
    }
    pub fn client_verify_data(&self, handshakes: &[u8]) -> Vec<u8> {
        let seed = self.prf_algorithm.hash(handshakes);
        self.prf_algorithm
            .prf(&self.master_secret, b"client finished", &seed, 12)
    }

    pub fn server_verify_data(&self, handshakes: &[u8]) -> Vec<u8> {
        let seed = self.prf_algorithm.hash(handshakes);
        self.prf_algorithm
            .prf(&self.master_secret, b"server finished", &seed, 12)
    }

    pub fn derive_keys(&self) -> DerivedKeys {
        let mac_key_len = self.mac_algorithm.key_length();
        let enc_key_len = self.enc_algorithm.key_length();
        let fixed_iv_len = self.enc_algorithm.fixed_iv_length();

        let key_block = self.prf_algorithm.prf(
            &self.master_secret,
            b"key expansion",
            &[self.server_random.as_slice(), self.client_random.as_slice()].concat(),
            2 * mac_key_len + 2 * enc_key_len + 2 * fixed_iv_len,
        );

        let mut offset = 0;
        let client_mac_key = key_block[offset..offset + mac_key_len].to_vec();
        offset += mac_key_len;
        let server_mac_key = key_block[offset..offset + mac_key_len].to_vec();
        offset += mac_key_len;
        let client_enc_key = key_block[offset..offset + enc_key_len].to_vec();
        offset += enc_key_len;
        let server_enc_key = key_block[offset..offset + enc_key_len].to_vec();
        offset += enc_key_len;
        let client_write_iv = key_block[offset..offset + fixed_iv_len].to_vec();
        offset += fixed_iv_len;
        let server_write_iv = key_block[offset..offset + fixed_iv_len].to_vec();

        DerivedKeys {
            client_mac_key,
            server_mac_key,
            client_enc_key,
            server_enc_key,
            client_write_iv,
            server_write_iv,
        }
    }
}

#[derive(Default, Debug, Clone)]
pub struct InitialConnState {
    pub seq_num: u64,
}

impl InitialConnState {
    pub fn encrypt(&mut self, plaintext: TlsPlaintext) -> TlsCiphertext {
        self.seq_num += 1;
        TlsCiphertext {
            content_type: plaintext.content_type,
            version: plaintext.version,
            fragment: plaintext.fragment,
        }
    }

    pub fn decrypt(&mut self, ciphertext: TlsCiphertext) -> Result<TlsPlaintext, TlsError> {
        self.seq_num += 1;
        Ok(TlsPlaintext {
            content_type: ciphertext.content_type,
            version: ciphertext.version,
            fragment: ciphertext.fragment,
        })
    }
}

#[derive(Clone, Debug)]
pub struct SecureConnState {
    pub params: SecurityParams,
    pub mac_key: Vec<u8>,
    pub enc_key: Vec<u8>,
    pub write_iv: Vec<u8>,
    pub seq_num: u64,
}

impl SecureConnState {
    pub fn new(
        params: SecurityParams,
        enc_key: Vec<u8>,
        mac_key: Vec<u8>,
        write_iv: Vec<u8>,
    ) -> Self {
        Self {
            params,
            enc_key,
            mac_key,
            write_iv,
            seq_num: 0,
        }
    }

    fn decrypt_block_cipher(&self, ciphertext: TlsCiphertext) -> Result<TlsCompressed, TlsError> {
        let content_type = ciphertext.content_type;
        let version = ciphertext.version;
        let (iv, ciphertext) = ciphertext
            .fragment
            .split_at(self.params.enc_algorithm.record_iv_length());
        let decrypted = self
            .params
            .enc_algorithm
            .decrypt(ciphertext, &self.enc_key, iv, None)
            .unwrap();

        let len = decrypted.len();
        let padding_len = decrypted[len - 1];
        let mac_len = self.params.mac_algorithm.mac_length();
        let fragment_len = len - (padding_len as usize) - 1 - mac_len;
        let (fragment, mac_and_padding) = decrypted.split_at(fragment_len);
        let (actual_mac, padding_bytes) = mac_and_padding.split_at(mac_len);

        if padding_bytes.iter().any(|b| *b != padding_len) {
            debug!("invalid padding bytes: {:?}", padding_bytes);
            return Err(TlsAlert::fatal(TlsAlertDesc::BadRecordMac).into());
        }

        let mut bytes = Vec::<u8>::new();
        bytes.extend_from_slice(&self.seq_num.to_be_bytes());
        bytes.push(u8::from(content_type));
        bytes.extend([3, 3]);
        bytes.extend((fragment.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&fragment);

        let expected_mac = self.params.mac_algorithm.mac(&self.mac_key, &bytes);
        if actual_mac != expected_mac {
            debug!("mac verification failed");
            return Err(TlsAlert::fatal(TlsAlertDesc::BadRecordMac).into());
        }

        Ok(TlsCompressed {
            content_type,
            version,
            fragment: fragment.to_vec().try_into().unwrap(),
        })
    }

    fn decrypt_aead_cipher(&self, ciphertext: TlsCiphertext) -> Result<TlsCompressed, TlsError> {
        let content_type = ciphertext.content_type;
        let version = ciphertext.version;
        let (explicit, ciphertext) = ciphertext
            .fragment
            .split_at(self.params.enc_algorithm.record_iv_length());
        let iv = [&self.write_iv, explicit].concat();
        let mut aad = Vec::<u8>::new();
        aad.extend_from_slice(&self.seq_num.to_be_bytes());
        aad.push(u8::from(content_type));
        aad.extend([3, 3]);

        // Remeber the -16 to remove the tag length
        aad.extend(((ciphertext.len() - 16) as u16).to_be_bytes());
        let fragment =
            match self
                .params
                .enc_algorithm
                .decrypt(ciphertext, &self.enc_key, &iv, Some(&aad))
            {
                Ok(fragment) => fragment,
                Err(_) => return Err(TlsAlert::fatal(TlsAlertDesc::BadRecordMac).into()),
            };

        Ok(TlsCompressed {
            content_type,
            version,
            fragment: fragment.try_into().unwrap(),
        })
    }

    fn encrypt_block_cipher(
        &self,
        compressed: TlsCompressed,
    ) -> Result<TlsCiphertext, DecodingError> {
        let mut bytes = Vec::<u8>::new();
        bytes.extend_from_slice(&self.seq_num.to_be_bytes());
        bytes.push(u8::from(compressed.content_type));
        bytes.extend([compressed.version.major, compressed.version.minor]);
        bytes.extend((compressed.fragment.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&compressed.fragment);

        let mac = self.params.mac_algorithm.mac(&self.mac_key, &bytes);
        let block_len = self.params.enc_algorithm.block_length();
        let padding_len = block_len - ((compressed.fragment.len() + mac.len() + 1) % block_len);
        let mut padding = Vec::<u8>::new();
        for _ in 0..padding_len {
            padding.push(padding_len as u8);
        }

        let mut to_encrypt = Vec::<u8>::new();
        to_encrypt.extend_from_slice(&compressed.fragment);
        to_encrypt.extend_from_slice(&mac);
        to_encrypt.extend_from_slice(&padding);
        to_encrypt.push(padding_len as u8);

        let iv = utils::get_random_bytes(self.params.enc_algorithm.record_iv_length());
        let ciphertext = self
            .params
            .enc_algorithm
            .encrypt(&to_encrypt, &self.enc_key, &iv, None);

        let mut fragment = Vec::<u8>::new();
        fragment.extend_from_slice(&iv);
        fragment.extend_from_slice(&ciphertext);
        Ok(TlsCiphertext {
            content_type: compressed.content_type,
            version: compressed.version,
            fragment,
        })
    }

    fn encrypt_aead_cipher(
        &self,
        compressed: TlsCompressed,
    ) -> Result<TlsCiphertext, DecodingError> {
        let implicit: [u8; 4] = self.write_iv.clone().try_into().unwrap();
        let explicit = utils::get_random_bytes(self.params.enc_algorithm.record_iv_length());
        let nonce = [&implicit[..], &explicit[..]].concat();
        assert_eq!(nonce.len(), 12);

        let mut aad = Vec::<u8>::new();
        aad.extend_from_slice(&self.seq_num.to_be_bytes());
        aad.push(u8::from(compressed.content_type));
        aad.extend([compressed.version.major, compressed.version.minor]);
        aad.extend((compressed.fragment.len() as u16).to_be_bytes());
        let aead_ciphertext = self.params.enc_algorithm.encrypt(
            &compressed.fragment,
            &self.enc_key,
            &nonce,
            Some(&aad),
        );
        let fragment = [&explicit, &aead_ciphertext[..]].concat();
        Ok(TlsCiphertext {
            content_type: compressed.content_type,
            version: compressed.version,
            fragment,
        })
    }

    pub fn compress(&mut self, plaintext: TlsPlaintext) -> TlsCompressed {
        match self.params.compression_algorithm {
            CompressionAlgorithm::Null => TlsCompressed {
                content_type: plaintext.content_type,
                version: plaintext.version,
                fragment: plaintext.fragment,
            },
        }
    }

    pub fn decompress(&mut self, compressed: TlsCompressed) -> Result<TlsPlaintext, TlsError> {
        match self.params.compression_algorithm {
            CompressionAlgorithm::Null => Ok(TlsPlaintext {
                content_type: compressed.content_type,
                version: compressed.version,
                fragment: compressed.fragment,
            }),
        }
    }

    pub fn encrypt(&mut self, plaintext: TlsPlaintext) -> Result<TlsCiphertext, DecodingError> {
        let compressed = self.compress(plaintext);
        let ciphertext = match self.params.enc_algorithm.cipher_type() {
            CipherType::Block => self.encrypt_block_cipher(compressed),
            CipherType::Aead => self.encrypt_aead_cipher(compressed),
            CipherType::Stream => unimplemented!(),
        };
        self.seq_num += 1;
        ciphertext
    }

    pub fn decrypt(&mut self, ciphertext: TlsCiphertext) -> Result<TlsPlaintext, TlsError> {
        let compressed = match self.params.enc_algorithm.cipher_type() {
            CipherType::Block => self.decrypt_block_cipher(ciphertext)?,
            CipherType::Aead => self.decrypt_aead_cipher(ciphertext)?,
            CipherType::Stream => unimplemented!(),
        };
        self.seq_num += 1;
        self.decompress(compressed)
    }
}

#[derive(Debug, Clone)]
pub enum ConnState {
    Initial(InitialConnState),
    Secure(SecureConnState),
}

impl ConnState {
    pub fn encrypt(&mut self, plaintext: TlsPlaintext) -> Result<TlsCiphertext, DecodingError> {
        match self {
            Self::Initial(state) => Ok(state.encrypt(plaintext)),
            Self::Secure(state) => state.encrypt(plaintext),
        }
    }

    pub fn decrypt(&mut self, ciphertext: TlsCiphertext) -> Result<TlsPlaintext, TlsError> {
        match self {
            Self::Initial(state) => state.decrypt(ciphertext),
            Self::Secure(state) => state.decrypt(ciphertext),
        }
    }
}

pub struct ConnStates {
    pub read: ConnState,
    pub write: ConnState,
}

impl ConnStates {
    pub fn new() -> Self {
        Self {
            read: ConnState::Initial(InitialConnState::default()),
            write: ConnState::Initial(InitialConnState::default()),
        }
    }
}

pub struct TlsConnection<T: Read + Write> {
    stream: T,
    pub handshake_state_machine: TlsStateMachine,
    conn_states: ConnStates,
    record_layer: RecordLayer,
    config: Arc<TlsConfig>,
    side: TlsEntity,
    is_closed: bool,
    max_fragment_len: usize,
}

impl<T: Read + Write> TlsConnection<T> {
    pub fn is_established(&self) -> bool {
        self.handshake_state_machine.is_established()
    }

    pub fn new(side: TlsEntity, stream: T, config: Arc<TlsConfig>) -> Self {
        Self {
            side,
            stream,
            handshake_state_machine: TlsStateMachine::new(side, config.clone()),
            config,
            conn_states: ConnStates::new(),
            record_layer: RecordLayer::new(),
            is_closed: false,
            max_fragment_len: 16_384,
        }
    }

    fn process_message(&mut self, event: TlsEvent) -> TlsResult<()> {
        match self.handshake_state_machine.handle(event) {
            Ok(actions) => {
                for action in actions {
                    match action {
                        TlsAction::ChangeCipherSpec(side, spec) => {
                            if side == self.side {
                                self.send_msg(TlsMessage::ChangeCipherSpec)?;
                                self.conn_states.write = spec;
                            } else {
                                self.conn_states.read = spec;
                            }
                        }
                        TlsAction::SendHandshakeMsg(handshake) => {
                            self.send_msg(handshake)?;
                        }
                        TlsAction::SendAlert(alert) => {
                            self.send_alert(alert)?;
                        }
                        TlsAction::CloseConnection(alert) => {
                            self.is_closed = true;
                            return Err(format!("Connection closed due to: {:?}", alert).into());
                        }
                        TlsAction::ValidateSession(request) => {
                            trace!("Validating session...");
                            let Some(store) = &self.config.session_store else {
                                trace!("No session store configured -> invalid session");
                                self.process_message(TlsEvent::SessionValidation(SessionValidation::Invalid))?;
                                continue;
                            };
                            
                            let validation = match request {
                                SessionValidationRequest::SessionId(id) => {
                                    match store.get_session_id(&id)? {
                                        None => SessionValidation::Invalid,
                                        Some(session_info) => SessionValidation::Valid(session_info),
                                    }
                                },
                                SessionValidationRequest::SessionTicket(ticket) => {
                                    match store.get_session_ticket(&ticket)? {
                                        None => SessionValidation::Invalid,
                                        Some(session_info) => SessionValidation::Valid(session_info),
                                    }
                                }
                            };

                            if let SessionValidation::Valid(_) = validation {
                                trace!("Session is valid");
                            } else {
                                trace!("Session is invalid");
                            }
                            
                            self.process_message(TlsEvent::SessionValidation(validation))?;

                        },
                        TlsAction::StoreSessionTicketInfo(ticket, info) => {
                            trace!("Storing session ticket");
                            if let Some(store) = &self.config.session_store {
                                store.insert_session_ticket(&ticket, info)?
                            }
                        }
                        TlsAction::StoreSessionIdInfo(id, info) => {
                            trace!("Storing session id");
                            if let Some(store) = &self.config.session_store {
                                store.insert_session_id(&id, info)?
                            }
                        }
                        TlsAction::UpdateMaxFragmentLen(max_fragment_len) => {
                            trace!(
                                "Updating max_fragment_length to {}",
                                max_fragment_len.length()
                            );
                            self.max_fragment_len = max_fragment_len.length();
                        }
                    }
                }
            }
            Err(_) => unreachable!(),
        }
        Ok(())
    }

    pub fn next_message(&mut self) -> TlsResult<TlsMessage> {
        loop {
            match self.record_layer.try_parse_message(
                &mut self.conn_states.read,
                &self.config.policy,
                self.max_fragment_len,
            ) {
                Ok(msg) => {
                    self.process_message(TlsEvent::IncomingMessage(&msg))?;
                    return Ok(msg);
                }
                Err(e) => match e {
                    TlsError::Alert(alert) => self.send_alert(alert)?,
                    TlsError::Decoding(e @ DecodingError::RanOutOfData) => {
                        trace!("Record parsing failed: {e}");
                    }
                    TlsError::Decoding(DecodingError::InvalidEncoding(e)) => {
                        trace!("Record parsing failed: {e}");
                        self.send_alert(TlsAlert::fatal(TlsAlertDesc::DecodeError))?;
                    }
                    _ => {}
                },
            };

            let mut buf = [0u8; 8096];
            let mut n = self.stream.read(&mut buf)?;
            while n == 0 {
                n = self.stream.read(&mut buf)?;
            }

            trace!("Received {} bytes", n);
            self.record_layer.feed(&buf[..n]);
        }
    }

    fn send_bytes(&mut self, bytes: &[u8]) -> TlsResult<()> {
        self.stream.write_all(bytes)?;
        Ok(())
    }

    fn send_msg<M: Into<TlsMessage>>(&mut self, msg: M) -> TlsResult<()> {
        self.check_connection_not_closed()?;

        let msg: TlsMessage = msg.into();
        let content_type = msg.content_type();
        for bytes in Fragmenter::new(msg.encode(), self.max_fragment_len).into_iter() {
            let plaintext = TlsPlaintext::new(content_type, bytes.to_vec())?;
            let ciphertext = self.conn_states.write.encrypt(plaintext)?;
            self.send_bytes(&ciphertext.get_encoding())?;
        }

        Ok(())
    }

    fn send_alert(&mut self, alert: TlsAlert) -> TlsResult<()> {
        info!("Sent alert: {:?}", alert);
        self.send_msg(TlsMessage::Alert(alert))?;
        Ok(())
    }

    fn check_connection_not_closed(&self) -> Result<(), TlsError> {
        (!self.is_closed)
            .then_some(())
            .ok_or(TlsError::ConnectionClosed)
    }

    pub fn complete_handshake(&mut self, side: TlsEntity, config: &TlsConfig) -> TlsResult<()> {
        self.check_connection_not_closed()?;

        let start_time = Instant::now();
        if side == TlsEntity::Client {
            let session_resumption = match &config.session_store {
                None => SessionResumption::None,
                Some(store) => match store.get_any_session_ticket()? {
                    Some((session_ticket, info)) => {
                        debug!(
                            "Using session ticket: {}",
                            utils::bytes_to_hex(&session_ticket)
                        );

                        SessionResumption::SessionTicket(SessionTicketResumption {
                            session_ticket,
                            master_secret: info.master_secret,
                            cipher_suite: info.cipher_suite,
                            max_fragment_len: info.max_fragment_len,
                        })
                    }
                    None => match store.get_any_session_id()? {
                        Some((session_id, info)) => {
                            debug!("Using session id: {}", utils::bytes_to_hex(&session_id));

                            SessionResumption::SessionId(SessionIdResumption {
                                session_id,
                                master_secret: info.master_secret,
                                cipher_suite: info.cipher_suite,
                                max_fragment_len: info.max_fragment_len,
                            })
                        }
                        None => {
                            debug!("No sessions to resume");
                            SessionResumption::None
                        }
                    },
                },
            };

            let initiate = TlsEvent::ClientInitiate {
                cipher_suites: config.cipher_suites.iter().map(|x| x.id).collect(),
                session_resumption,
                server_name: config.server_name.clone(),
                support_session_ticket: true,
                support_extended_master_secret: true,
                support_secure_renegotiation: true,
                max_fragment_len: self.config.max_fragment_length,
            };
            self.process_message(initiate)?;
        }

        while !self.handshake_state_machine.is_established() {
            self.next_message()?;
        }

        let elapsed = Instant::now() - start_time;
        println!("elapsed: {} seconds", elapsed.as_secs_f64());
        Ok(())
    }

    pub fn write(&mut self, bytes: &[u8]) -> TlsResult<()> {
        self.check_connection_not_closed()?;

        let msg = TlsMessage::new_appdata(bytes.to_vec());
        let plaintext = TlsPlaintext::new(TlsContentType::ApplicationData, msg.encode())?;
        let ciphertext = self.conn_states.write.encrypt(plaintext)?;
        self.send_bytes(&ciphertext.get_encoding())?;
        println!("Sent AppData: {:?}", String::from_utf8_lossy(bytes));
        Ok(())
    }

    pub fn read(&mut self) -> TlsResult<Vec<u8>> {
        self.check_connection_not_closed()?;

        loop {
            let msg = self.next_message()?;
            match msg {
                TlsMessage::ApplicationData(bytes) => {
                    return Ok(bytes);
                }
                _ => {
                    println!("{:?}", msg);
                    return Err("Received unexpected message".into());
                }
            }
        }
    }
}

pub struct Fragmenter {
    bytes: Vec<u8>,
    max_fragment_size: usize,
}

impl Fragmenter {
    pub fn new(bytes: Vec<u8>, max_fragment_size: usize) -> Self {
        Self {
            bytes,
            max_fragment_size,
        }
    }
}

impl Iterator for Fragmenter {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.bytes.is_empty() {
            return None;
        }

        let take = self.max_fragment_size.min(self.bytes.len());
        let chunk: Vec<u8> = self.bytes.drain(..take).collect();
        Some(chunk)
    }
}
