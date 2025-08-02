use crate::alert::{TLSAlert, TLSAlertDesc, TLSAlertLevel};
use crate::ciphersuite::{
    CipherSuite, CipherSuiteId, CipherSuiteMethods, CipherType, CompressionAlgorithm, EncAlgorithm,
    MacAlgorithm, PrfAlgorithm,
};
use crate::client::TlsConfig;
use crate::encoding::TlsCodable;
use crate::encoding::{CodingError, Reconstrainable};
use crate::extensions::{
    ALPNExt, ExtendedMasterSecretExt, RenegotiationInfoExt, ServerNameExt, SessionTicketExt,
};
use crate::messages::{
    ClientHello, SessionId, TLSCiphertext, TlsCompressed, TlsHandshake, TlsMessage, TlsPlaintext,
};
use crate::record::RecordLayer;
use crate::state_machine::{ConnStates, TlsAction, TlsEntity, TlsHandshakeStateMachine, TlsState};
use crate::{TlsError, TlsResult, utils};
use log::{debug, trace};
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
    pub fn encrypt(&mut self, plaintext: TlsPlaintext) -> TLSCiphertext {
        self.seq_num += 1;
        TLSCiphertext {
            content_type: plaintext.content_type,
            version: plaintext.version,
            fragment: plaintext.fragment.reconstrain().expect(
                "Plaintext fragment length should always be less than ciphertext fragment length",
            ),
        }
    }

    pub fn decrypt(&mut self, ciphertext: TLSCiphertext) -> Result<TlsPlaintext, CodingError> {
        self.seq_num += 1;
        Ok(TlsPlaintext {
            content_type: ciphertext.content_type,
            version: ciphertext.version,
            fragment: ciphertext.fragment.reconstrain()?,
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

    fn decrypt_block_cipher(
        &self,
        ciphertext: TLSCiphertext,
    ) -> Result<TlsCompressed, CodingError> {
        let content_type = ciphertext.content_type;
        let version = ciphertext.version;
        let (iv, ciphertext) = ciphertext
            .fragment
            .split_at(self.params.enc_algorithm.record_iv_length());
        let decrypted = self
            .params
            .enc_algorithm
            .decrypt(ciphertext, &self.enc_key, iv, None);

        let len = decrypted.len();
        let padding = decrypted[len - 1] as usize;
        let mac_len = self.params.mac_algorithm.mac_length();
        let fragment = decrypted[..len - padding - 1 - mac_len].to_vec();
        let actual_mac = decrypted[len - padding - 1 - mac_len..len - padding - 1].to_vec();

        let mut bytes = Vec::<u8>::new();
        bytes.extend_from_slice(&self.seq_num.to_be_bytes());
        bytes.push(u8::from(content_type));
        bytes.extend([3, 3]);
        bytes.extend((fragment.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&fragment);

        let expected_mac = self.params.mac_algorithm.mac(&self.mac_key, &bytes);
        assert_eq!(expected_mac, actual_mac, "bad_record_mac");

        Ok(TlsCompressed {
            content_type,
            version,
            fragment: fragment.try_into()?,
        })
    }

    fn decrypt_aead_cipher(&self, ciphertext: TLSCiphertext) -> Result<TlsCompressed, CodingError> {
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
            self.params
                .enc_algorithm
                .decrypt(ciphertext, &self.enc_key, &iv, Some(&aad));
        Ok(TlsCompressed {
            content_type,
            version,
            fragment: fragment.try_into()?,
        })
    }

    fn encrypt_block_cipher(
        &self,
        compressed: TlsCompressed,
    ) -> Result<TLSCiphertext, CodingError> {
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
        Ok(TLSCiphertext {
            content_type: compressed.content_type,
            version: compressed.version,
            fragment: fragment.try_into()?,
        })
    }

    fn encrypt_aead_cipher(&self, compressed: TlsCompressed) -> Result<TLSCiphertext, CodingError> {
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
        Ok(TLSCiphertext {
            content_type: compressed.content_type,
            version: compressed.version,
            fragment: fragment.try_into()?,
        })
    }

    pub fn compress(&mut self, plaintext: TlsPlaintext) -> TlsCompressed {
        match self.params.compression_algorithm {
            CompressionAlgorithm::Null => TlsCompressed {
                content_type: plaintext.content_type,
                version: plaintext.version,
                fragment: plaintext.fragment.reconstrain().expect(
                    "Plaintext fragment length should always be less than compressed fragment length",
                ),
            },
        }
    }

    pub fn decompress(&mut self, compressed: TlsCompressed) -> Result<TlsPlaintext, CodingError> {
        match self.params.compression_algorithm {
            CompressionAlgorithm::Null => Ok(TlsPlaintext {
                content_type: compressed.content_type,
                version: compressed.version,
                fragment: compressed.fragment.reconstrain()?,
            }),
        }
    }

    pub fn encrypt(&mut self, plaintext: TlsPlaintext) -> Result<TLSCiphertext, CodingError> {
        let compressed = self.compress(plaintext);
        let ciphertext = match self.params.enc_algorithm.cipher_type() {
            CipherType::Block => self.encrypt_block_cipher(compressed),
            CipherType::Aead => self.encrypt_aead_cipher(compressed),
            CipherType::Stream => unimplemented!(),
        };
        self.seq_num += 1;
        ciphertext
    }

    pub fn decrypt(&mut self, ciphertext: TLSCiphertext) -> Result<TlsPlaintext, CodingError> {
        let compressed = match self.params.enc_algorithm.cipher_type() {
            CipherType::Block => self.decrypt_block_cipher(ciphertext),
            CipherType::Aead => self.decrypt_aead_cipher(ciphertext),
            CipherType::Stream => unimplemented!(),
        }?;
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
    pub fn encrypt<T: TryInto<TlsPlaintext, Error = CodingError>>(
        &mut self,
        plaintext: T,
    ) -> Result<TLSCiphertext, CodingError> {
        match self {
            Self::Initial(state) => Ok(state.encrypt(plaintext.try_into()?)),
            Self::Secure(state) => state.encrypt(plaintext.try_into()?),
        }
    }

    pub fn decrypt(&mut self, ciphertext: TLSCiphertext) -> Result<TlsPlaintext, CodingError> {
        match self {
            Self::Initial(state) => state.decrypt(ciphertext),
            Self::Secure(state) => state.decrypt(ciphertext),
        }
    }
}

pub struct TlsConnection<T: Read + Write> {
    stream: T,
    pub handshake_state_machine: TlsHandshakeStateMachine,
    conn_states: ConnStates,
    record_layer: RecordLayer,
    config: Arc<TlsConfig>,
    side: TlsEntity,
}

impl<T: Read + Write> TlsConnection<T> {
    pub fn is_established(&self) -> bool {
        self.handshake_state_machine.is_established()
    }

    pub fn new(side: TlsEntity, stream: T, config: Arc<TlsConfig>) -> Self {
        Self {
            side,
            stream,
            handshake_state_machine: TlsHandshakeStateMachine::new(side, config.clone()),
            config,
            conn_states: ConnStates::new(),
            record_layer: RecordLayer::new(),
        }
    }

    // pub fn new_with_context(domain: &str, ctx: TlsContext) -> TLSResult<Self> {
    //     info!("Establishing TLS with {}", domain);
    //     let port = if domain == "localhost" { "4433" } else { "443" };
    //     Ok(Self {
    //         stream: TcpStream::connect(format!("{domain}:{port}"))?,
    //         handshake_state_machine: TlsHandshakeStateMachine::from_context(ctx),
    //         conn_states: ConnStates::new(),
    //         record_layer: RecordLayer::new(),
    //     })
    // }

    fn process_message(&mut self, msg: &TlsMessage) -> TlsResult<()> {
        for action in self.handshake_state_machine.transition(msg)? {
            // println!("{:?}", action);
            match action {
                TlsAction::ChangeCipherSpec(side, spec) => {
                    if side == self.side {
                        let ciphertext = self
                            .conn_states
                            .write
                            .encrypt(TlsMessage::ChangeCipherSpec)?;
                        self.send_bytes(&ciphertext.get_encoding())?;
                        self.conn_states.write = spec;
                    } else {
                        self.conn_states.read = spec;
                    }
                }
                TlsAction::SendHandshakeMsg(handshake) => {
                    let ciphertext = self.conn_states.write.encrypt(handshake)?;
                    self.send_bytes(&ciphertext.get_encoding())?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub fn next_message(&mut self) -> TlsResult<TlsMessage> {
        loop {
            match self
                .record_layer
                .try_parse_message(&mut self.conn_states.read, &self.config.validation_policy)
            {
                Ok(msg) => {
                    // println!("{:?}", msg);
                    match &msg {
                        TlsMessage::Handshake(_) | TlsMessage::ChangeCipherSpec => {
                            self.process_message(&msg)?
                        }
                        _ => {}
                    }
                    return Ok(msg);
                }
                Err(e) => match e {
                    TlsError::Alert(alert) => self.send_alert(alert)?,
                    TlsError::Coding(e) => {
                        trace!("Record layer parsing failed: {e}")
                    }
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

    fn send_alert(&mut self, alert: TLSAlert) -> TlsResult<()> {
        let ciphertext = self.conn_states.write.encrypt(TlsMessage::Alert(alert))?;
        self.send_bytes(&ciphertext.get_encoding())?;
        Ok(())
    }

    pub fn complete_handshake(&mut self, side: TlsEntity, config: &TlsConfig) -> TlsResult<()> {
        let start_time = Instant::now();

        if side == TlsEntity::Client {
            let mut extensions = config.extensions.to_vec();
            if let Some(store) = &config.session_ticket_store {
                match store.get_one()? {
                    Some(ticket) => {
                        debug!(
                            "Using SessionTicket: {:?}",
                            ticket
                                .iter()
                                .map(|b| format!("{:02x}", b))
                                .collect::<String>()
                        );
                        extensions.push(SessionTicketExt::resume(ticket)?.into())
                    }
                    None => extensions.push(SessionTicketExt::new().into()),
                }
            }

            if let Some(server_name) = &config.server_name {
                extensions.push(ServerNameExt::new(&server_name).into());
            }

            let client_hello = TlsMessage::Handshake(TlsHandshake::ClientHello(ClientHello::new(
                &config.cipher_suites,
                extensions,
                None,
            )?));
            self.process_message(&client_hello)?;
        }

        while !self.handshake_state_machine.is_established() {
            if let TlsMessage::Alert(a) = self.next_message()? {
                println!("{:?}", a);
                return Err("Received alert during handshake".into());
            }
        }

        let elapsed = Instant::now() - start_time;
        println!("elapsed: {} seconds", elapsed.as_secs_f64());
        Ok(())
    }

    pub fn handshake(
        &mut self,
        cipher_suites: &[CipherSuiteId],
        session_id: Option<SessionId>,
        session_ticket: Option<Vec<u8>>,
    ) -> TlsResult<SessionId> {
        let mut extensions = match self.handshake_state_machine.state.as_ref().unwrap() {
            TlsState::Established(s) => {
                vec![RenegotiationInfoExt::renegotiation(&s.client_verify_data)?.into()]
            }
            _ => vec![RenegotiationInfoExt::initial().into()],
        };

        match session_ticket {
            None => extensions.push(SessionTicketExt::new().into()),
            Some(ticket) => extensions.push(SessionTicketExt::resume(ticket)?.into()),
        }

        extensions.push(ExtendedMasterSecretExt::new().into());
        extensions.push(ALPNExt::new(vec!["http/1.1".to_string()])?.into());

        let client_hello = TlsMessage::Handshake(TlsHandshake::ClientHello(ClientHello::new(
            cipher_suites,
            extensions,
            session_id,
        )?));

        let start_time = Instant::now();
        self.process_message(&client_hello)?;

        while !self.handshake_state_machine.is_established() {
            if let TlsMessage::Alert(a) = self.next_message()? {
                println!("{:?}", a);
                return Err("Received alert during handshake".into());
            }
        }

        let elapsed = Instant::now() - start_time;
        println!("elapsed: {} seconds", elapsed.as_secs_f64());

        let state = self
            .handshake_state_machine
            .state
            .as_ref()
            .unwrap()
            .as_established()?;
        return Ok(state.session_id.clone());
    }

    #[allow(dead_code)]
    pub fn write(&mut self, bytes: &[u8]) -> TlsResult<()> {
        let ciphertext = self
            .conn_states
            .write
            .encrypt(TlsMessage::new_appdata(bytes.to_vec()))?;
        self.send_bytes(&ciphertext.get_encoding())?;
        println!("Sent AppData: {:?}", String::from_utf8_lossy(bytes));
        Ok(())
    }

    #[allow(dead_code)]
    pub fn read(&mut self) -> TlsResult<Vec<u8>> {
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

    pub fn notify_close(&mut self) -> TlsResult<()> {
        let alert = TLSAlert::warning(TLSAlertDesc::CloseNotify);
        let ciphertext = self.conn_states.write.encrypt(alert)?;
        self.send_bytes(&ciphertext.get_encoding())?;
        Ok(())
    }
}
