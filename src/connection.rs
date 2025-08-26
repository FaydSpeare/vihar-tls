use crate::alert::{Alert, AlertDesc};
use crate::ciphersuite::{
    AeadCipher, BlockCipher, CipherSuite, CipherSuiteId, CompressionMethod, ConcreteEncryption,
    ConcreteMac, EncryptionType, MacType, PrfAlgorithm, StreamCipher,
};
use crate::client::TlsConfig;
use crate::encoding::TlsCodable;
use crate::errors::{DecodingError, TlsError};
use crate::messages::{TlsCiphertext, TlsCompressed, TlsContentType, TlsMessage, TlsPlaintext};
use crate::record::RecordLayer;
use crate::state_machine::{
    SessionIdResumption, SessionResumption, SessionTicketResumption, SessionValidation, TlsAction,
    TlsEntity, TlsEvent, TlsStateMachine,
};
use crate::{TlsResult, utils};
use log::{debug, info, trace};
use std::io::{Read, Write};
use std::rc::Rc;
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
    pub enc_type: EncryptionType,
    pub mac_type: MacType,
    pub prf_algorithm: PrfAlgorithm,
    pub compression_algorithm: CompressionMethod,
    pub client_random: [u8; 32],
    pub server_random: [u8; 32],
    pub master_secret: [u8; 48],
}

impl SecurityParams {
    pub fn new(
        client_random: [u8; 32],
        server_random: [u8; 32],
        master_secret: [u8; 48],
        cipher_suite: &CipherSuite,
    ) -> Self {
        Self {
            cipher_suite_id: cipher_suite.id(),
            client_random,
            server_random,
            master_secret,
            enc_type: cipher_suite.enc_type(),
            mac_type: cipher_suite.mac_type(),
            prf_algorithm: cipher_suite.prf_algorithm(),
            compression_algorithm: CompressionMethod::Null,
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
        let mac_key_len = self.mac_type.key_length();
        let enc_key_len = self.enc_type.key_length();
        let fixed_iv_len = self.enc_type.fixed_iv_length();

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

#[derive(Debug)]
pub struct ConnState {
    compression: CompressionMethod,
    encryption: ConcreteEncryption,
    mac: ConcreteMac,
    seq_num: u64,
}

impl Default for ConnState {
    fn default() -> Self {
        Self {
            compression: CompressionMethod::Null,
            encryption: ConcreteEncryption::Stream(StreamCipher::Null),
            mac: ConcreteMac::Null,
            seq_num: 0,
        }
    }
}

impl ConnState {
    pub fn new(params: SecurityParams, entity: TlsEntity) -> Self {
        let keys = params.derive_keys();
        let (enc_key, mac_key, write_iv) = match entity {
            TlsEntity::Client => (
                keys.client_enc_key,
                keys.client_mac_key,
                keys.client_write_iv,
            ),
            TlsEntity::Server => (
                keys.server_enc_key,
                keys.server_mac_key,
                keys.server_write_iv,
            ),
        };
        Self {
            compression: params.compression_algorithm,
            encryption: params.enc_type.concrete(enc_key, write_iv),
            mac: params.mac_type.concrete(mac_key),
            seq_num: 0,
        }
    }

    fn decrypt_stream_cipher(
        ciphertext: TlsCiphertext,
        cipher: &StreamCipher,
        mac: &ConcreteMac,
        seq_num: u64,
    ) -> Result<TlsCompressed, TlsError> {
        let content_type = ciphertext.content_type;
        let version = ciphertext.version;
        let decrypted = cipher.decrypt(&ciphertext.fragment);

        let (fragment, mac_bytes) = decrypted.split_at(decrypted.len() - mac.length());

        let mut bytes = Vec::<u8>::new();
        bytes.extend_from_slice(&seq_num.to_be_bytes());
        bytes.push(u8::from(content_type));
        bytes.extend([3, 3]);
        bytes.extend((fragment.len() as u16).to_be_bytes());
        bytes.extend_from_slice(fragment);

        if mac_bytes != mac.compute(&bytes) {
            debug!("mac verification failed");
            return Err(Alert::fatal(AlertDesc::BadRecordMac).into());
        }

        Ok(TlsCompressed {
            content_type,
            version,
            fragment: fragment.to_vec(),
        })
    }

    fn decrypt_block_cipher(
        ciphertext: TlsCiphertext,
        cipher: &BlockCipher,
        mac: &ConcreteMac,
        seq_num: u64,
    ) -> Result<TlsCompressed, TlsError> {
        let content_type = ciphertext.content_type;
        let version = ciphertext.version;
        let (iv, ciphertext) = ciphertext.fragment.split_at(cipher.record_iv_length);
        let decrypted = cipher.decrypt(ciphertext, iv);

        let len = decrypted.len();
        let padding_len = decrypted[len - 1];
        let mac_len = mac.length();
        let fragment_len = len - (padding_len as usize) - 1 - mac_len;
        let (fragment, mac_and_padding) = decrypted.split_at(fragment_len);
        let (actual_mac, padding_bytes) = mac_and_padding.split_at(mac_len);

        if padding_bytes.iter().any(|b| *b != padding_len) {
            debug!("invalid padding bytes: {:?}", padding_bytes);
            return Err(Alert::fatal(AlertDesc::BadRecordMac).into());
        }

        let mut bytes = Vec::<u8>::new();
        bytes.extend_from_slice(&seq_num.to_be_bytes());
        bytes.push(u8::from(content_type));
        bytes.extend([3, 3]);
        bytes.extend((fragment.len() as u16).to_be_bytes());
        bytes.extend_from_slice(fragment);

        let expected_mac = mac.compute(&bytes);
        if actual_mac != expected_mac {
            debug!("mac verification failed");
            return Err(Alert::fatal(AlertDesc::BadRecordMac).into());
        }

        Ok(TlsCompressed {
            content_type,
            version,
            fragment: fragment.to_vec(),
        })
    }

    fn decrypt_aead_cipher(
        ciphertext: TlsCiphertext,
        cipher: &AeadCipher,
        seq_num: u64,
    ) -> Result<TlsCompressed, TlsError> {
        let content_type = ciphertext.content_type;
        let version = ciphertext.version;
        let (explicit, ciphertext) = ciphertext.fragment.split_at(cipher.record_iv_length);
        let iv = [&cipher.write_iv, explicit].concat();
        let mut aad = Vec::<u8>::new();
        aad.extend_from_slice(&seq_num.to_be_bytes());
        aad.push(u8::from(content_type));
        aad.extend([3, 3]);

        // Remeber the -16 to remove the tag length
        aad.extend(((ciphertext.len() - 16) as u16).to_be_bytes());
        let fragment = match cipher.decrypt(ciphertext, &iv, &aad) {
            Ok(fragment) => fragment,
            Err(_) => return Err(Alert::fatal(AlertDesc::BadRecordMac).into()),
        };

        Ok(TlsCompressed {
            content_type,
            version,
            fragment,
        })
    }

    fn encrypt_stream_cipher(
        compressed: TlsCompressed,
        cipher: &StreamCipher,
        mac: &ConcreteMac,
        seq_num: u64,
    ) -> Result<TlsCiphertext, DecodingError> {
        let mut bytes = Vec::<u8>::new();
        bytes.extend_from_slice(&seq_num.to_be_bytes());
        bytes.push(u8::from(compressed.content_type));
        bytes.extend([compressed.version.major, compressed.version.minor]);
        bytes.extend((compressed.fragment.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&compressed.fragment);
        let mac = mac.compute(&bytes);

        let mut to_encrypt = Vec::<u8>::new();
        to_encrypt.extend_from_slice(&compressed.fragment);
        to_encrypt.extend_from_slice(&mac);

        let ciphertext = cipher.encrypt(&to_encrypt);
        Ok(TlsCiphertext {
            content_type: compressed.content_type,
            version: compressed.version,
            fragment: ciphertext,
        })
    }

    fn encrypt_block_cipher(
        compressed: TlsCompressed,
        cipher: &BlockCipher,
        mac: &ConcreteMac,
        seq_num: u64,
    ) -> Result<TlsCiphertext, DecodingError> {
        let mut bytes = Vec::<u8>::new();
        bytes.extend_from_slice(&seq_num.to_be_bytes());
        bytes.push(u8::from(compressed.content_type));
        bytes.extend([compressed.version.major, compressed.version.minor]);
        bytes.extend((compressed.fragment.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&compressed.fragment);
        let mac = mac.compute(&bytes);

        let block_len = cipher.block_length;
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

        let iv = utils::get_random_bytes(cipher.record_iv_length);
        let ciphertext = cipher.encrypt(&to_encrypt, &iv);

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
        compressed: TlsCompressed,
        cipher: &AeadCipher,
        seq_num: u64,
    ) -> Result<TlsCiphertext, DecodingError> {
        let implicit: [u8; 4] = cipher.write_iv.clone().try_into().unwrap();
        let explicit = utils::get_random_bytes(cipher.record_iv_length);
        let nonce = [&implicit[..], &explicit[..]].concat();
        assert_eq!(nonce.len(), 12);

        let mut aad = Vec::<u8>::new();
        aad.extend_from_slice(&seq_num.to_be_bytes());
        aad.push(u8::from(compressed.content_type));
        aad.extend([compressed.version.major, compressed.version.minor]);
        aad.extend((compressed.fragment.len() as u16).to_be_bytes());

        let ciphertext = cipher.encrypt(&compressed.fragment, &nonce, &aad);
        let fragment = [&explicit, &ciphertext[..]].concat();
        Ok(TlsCiphertext {
            content_type: compressed.content_type,
            version: compressed.version,
            fragment,
        })
    }

    pub fn compress(&mut self, plaintext: TlsPlaintext) -> TlsCompressed {
        match self.compression {
            CompressionMethod::Null => TlsCompressed {
                content_type: plaintext.content_type,
                version: plaintext.version,
                fragment: plaintext.fragment,
            },
            CompressionMethod::Unknown(x) => panic!("unknown compression method: {x}"),
        }
    }

    pub fn decompress(&mut self, compressed: TlsCompressed) -> Result<TlsPlaintext, TlsError> {
        match self.compression {
            CompressionMethod::Null => Ok(TlsPlaintext {
                content_type: compressed.content_type,
                version: compressed.version,
                fragment: compressed.fragment,
            }),
            CompressionMethod::Unknown(x) => panic!("unknown compression method: {x}"),
        }
    }

    pub fn encrypt(&mut self, plaintext: TlsPlaintext) -> Result<TlsCiphertext, DecodingError> {
        let compressed = self.compress(plaintext);
        let ciphertext = match &self.encryption {
            ConcreteEncryption::Block(cipher) => {
                ConnState::encrypt_block_cipher(compressed, &cipher, &self.mac, self.seq_num)
            }
            ConcreteEncryption::Aead(cipher) => {
                ConnState::encrypt_aead_cipher(compressed, &cipher, self.seq_num)
            }
            ConcreteEncryption::Stream(cipher) => {
                ConnState::encrypt_stream_cipher(compressed, &cipher, &self.mac, self.seq_num)
            }
        };
        self.seq_num += 1;
        ciphertext
    }

    pub fn decrypt(&mut self, ciphertext: TlsCiphertext) -> Result<TlsPlaintext, TlsError> {
        let compressed = match &self.encryption {
            ConcreteEncryption::Block(cipher) => {
                ConnState::decrypt_block_cipher(ciphertext, cipher, &self.mac, self.seq_num)?
            }
            ConcreteEncryption::Aead(cipher) => {
                ConnState::decrypt_aead_cipher(ciphertext, cipher, self.seq_num)?
            }
            ConcreteEncryption::Stream(cipher) => {
                ConnState::decrypt_stream_cipher(ciphertext, cipher, &self.mac, self.seq_num)?
            }
        };
        self.seq_num += 1;
        self.decompress(compressed)
    }
}

pub struct ConnStates {
    pub read: ConnState,
    pub write: ConnState,
}

impl Default for ConnStates {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnStates {
    pub fn new() -> Self {
        Self {
            read: ConnState::default(),
            write: ConnState::default(),
        }
    }
}

pub struct TlsConnection<T: Read + Write> {
    stream: T,
    pub handshake_state_machine: TlsStateMachine,
    conn_states: ConnStates,
    record_layer: RecordLayer,
    config: Rc<TlsConfig>,
    side: TlsEntity,
    is_closed: bool,
    max_fragment_len: usize,
}

impl<T: Read + Write> TlsConnection<T> {
    pub fn is_established(&self) -> bool {
        self.handshake_state_machine.is_established()
    }

    pub fn new(side: TlsEntity, stream: T, config: Rc<TlsConfig>) -> Self {
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
        for action in self.handshake_state_machine.handle(event) {
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
                TlsAction::ValidateSessionId(session_id) => {
                    trace!("Validating session...");
                    let Some(store) = &self.config.session_store else {
                        trace!("No session store configured -> invalid session");
                        self.process_message(TlsEvent::SessionValidation(
                            SessionValidation::Invalid,
                        ))?;
                        continue;
                    };

                    let validation = match store.get_session_id(&session_id)? {
                        None => {
                            trace!("Session is invalid");
                            SessionValidation::Invalid
                        }
                        Some(session_info) => {
                            trace!("Session is valid");
                            SessionValidation::Valid(session_info)
                        }
                    };

                    self.process_message(TlsEvent::SessionValidation(validation))?;
                }
                TlsAction::GetStekInfo(key_name) => {
                    trace!("Retrieving stek...");
                    let Some(store) = &self.config.session_store else {
                        trace!("No session store configured -> no stek");
                        self.process_message(TlsEvent::StekInfo(None))?;
                        continue;
                    };
                    let stek = store.get_stek(&key_name)?;
                    self.process_message(TlsEvent::StekInfo(stek))?;
                }
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
                TlsAction::InvalidateSessionId(session_id) => {
                    trace!("Invalidating session id");
                    if let Some(store) = &self.config.session_store {
                        store.delete_session_id(&session_id)?
                    }
                }
                TlsAction::InvalidateSessionTicket(session_ticket) => {
                    trace!("Invalidating session ticket");
                    if let Some(store) = &self.config.session_store {
                        store.delete_session_ticket(&session_ticket)?
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
                        self.send_alert(Alert::fatal(AlertDesc::DecodeError))?;
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
        for bytes in Fragmenter::new(msg.encode(), self.max_fragment_len) {
            let plaintext = TlsPlaintext::new(content_type, bytes.to_vec())?;
            let ciphertext = self.conn_states.write.encrypt(plaintext)?;
            self.send_bytes(&ciphertext.get_encoding())?;
        }

        Ok(())
    }

    fn send_alert(&mut self, alert: Alert) -> TlsResult<()> {
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
                            cipher_suite_id: info.cipher_suite,
                            max_fragment_len: info.max_fragment_len,
                            extended_master_secret: info.extended_master_secret,
                        })
                    }
                    None => match store.get_any_session_id()? {
                        Some((session_id, info)) => {
                            debug!("Using session id: {}", utils::bytes_to_hex(&session_id));

                            SessionResumption::SessionId(SessionIdResumption {
                                session_id,
                                master_secret: info.master_secret,
                                cipher_suite_id: info.cipher_suite,
                                max_fragment_len: info.max_fragment_len,
                                extended_master_secret: info.extended_master_secret,
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
        #[allow(clippy::never_loop)]
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
