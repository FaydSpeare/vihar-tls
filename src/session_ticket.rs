#![allow(dead_code)]
use aes::Aes128;

use crate::{
    ciphersuite::CipherSuiteId,
    encoding::{LengthPrefixedVec, MaybeEmpty, Reader, TlsCodable},
    errors::{DecodingError, InvalidEncodingError},
    gcm::{decrypt_aes_cbc, encrypt_aes_cbc},
    messages::{CeritificateList, CompressionMethodId, ProtocolVersion},
    prf::{HmacHashAlgo, hmac},
    utils,
};

type EncryptedState = LengthPrefixedVec<u16, u8, MaybeEmpty>;
struct SessionTicket {
    key_name: [u8; 16],
    iv: [u8; 16],
    encrypted_state: EncryptedState,
    mac: [u8; 32],
}

impl SessionTicket {
    pub fn decrypt(&self, aes_key: &[u8], mac_key: &[u8]) -> Result<StatePlaintext, DecodingError> {
        let data = [
            &self.key_name[..],
            &self.iv,
            &self.encrypted_state.get_encoding(),
        ]
        .concat();

        let expected_mac: [u8; 32] = hmac(mac_key, &data, HmacHashAlgo::Sha256)
            .try_into()
            .unwrap();

        if self.mac != expected_mac {
            return Err(InvalidEncodingError::InvalidSessionTicketMac.into());
        }

        let ciphertext: Vec<u8> = self.encrypted_state.to_vec();
        let plaintext = decrypt_aes_cbc::<Aes128>(&ciphertext, aes_key, &self.iv);
        // TODO: check padding

        let mut reader = Reader::new(&plaintext);
        Ok(StatePlaintext::read_from(&mut reader)?)
    }
}

#[derive(Debug, PartialEq)]
struct StatePlaintext {
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuiteId,
    compression_method: CompressionMethodId,
    master_secret: [u8; 48],
    client_identity: ClientIdentity,
    timestamp: u32,
}

impl TlsCodable for StatePlaintext {
    fn read_from(reader: &mut Reader) -> Result<Self, DecodingError> {
        Ok(Self {
            protocol_version: ProtocolVersion::read_from(reader)?,
            cipher_suite: CipherSuiteId::read_from(reader)?,
            compression_method: CompressionMethodId::read_from(reader)?,
            master_secret: <[u8; 48]>::read_from(reader)?,
            client_identity: ClientIdentity::read_from(reader)?,
            timestamp: u32::read_from(reader)?,
        })
    }
    fn write_to(&self, bytes: &mut Vec<u8>) {
        self.protocol_version.write_to(bytes);
        self.cipher_suite.write_to(bytes);
        self.compression_method.write_to(bytes);
        self.master_secret.write_to(bytes);
        self.client_identity.write_to(bytes);
        self.timestamp.write_to(bytes);
    }
}

impl StatePlaintext {
    pub fn encrypt(&self, key_name: [u8; 16], aes_key: &[u8], mac_key: &[u8]) -> SessionTicket {
        let mut plaintext = self.get_encoding();

        let pad_len = 16 - plaintext.len() % 16;
        plaintext.extend(std::iter::repeat(pad_len as u8).take(pad_len));

        let iv: [u8; 16] = utils::get_random_bytes(16).try_into().unwrap();
        let ciphertext = encrypt_aes_cbc::<Aes128>(&plaintext, aes_key, &iv);
        let encrypted_state =
            EncryptedState::try_from(ciphertext).expect("failed to convert to encrypted_state");
        let data = [&key_name[..], &iv, &encrypted_state.get_encoding()].concat();
        let mac: [u8; 32] = hmac(mac_key, &data, HmacHashAlgo::Sha256)
            .try_into()
            .unwrap();
        SessionTicket {
            key_name,
            iv,
            encrypted_state,
            mac,
        }
    }
}

tls_codable_enum! {
    #[repr(u8)]
    enum ClientAuthType {
        Anonymous = 0,
        ClientBased = 1,
    }
}

#[derive(Debug, PartialEq)]
enum ClientIdentity {
    Anonymous,
    CertificateBased(CeritificateList),
}

impl TlsCodable for ClientIdentity {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        match self {
            Self::Anonymous => {
                ClientAuthType::Anonymous.write_to(bytes);
            }
            Self::CertificateBased(list) => {
                ClientAuthType::ClientBased.write_to(bytes);
                list.write_to(bytes)
            }
        }
    }
    fn read_from(reader: &mut Reader) -> Result<Self, DecodingError> {
        Ok(match ClientAuthType::read_from(reader)? {
            ClientAuthType::Anonymous => Self::Anonymous,
            ClientAuthType::ClientBased => {
                Self::CertificateBased(CeritificateList::read_from(reader)?)
            }
            ClientAuthType::Unknown(x) => panic!("unknown client_auth_type: {x}"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_ticket_encryption() -> Result<(), Box<dyn std::error::Error>> {
        let state = StatePlaintext {
            protocol_version: ProtocolVersion::tls12(),
            cipher_suite: CipherSuiteId::RsaAes128CbcSha,
            compression_method: CompressionMethodId::Null,
            master_secret: [0; 48],
            client_identity: ClientIdentity::Anonymous,
            timestamp: 0u32,
        };

        let mac_key: [u8; 32] = utils::get_random_bytes(32).try_into().unwrap();
        let enc_key: [u8; 16] = utils::get_random_bytes(16).try_into().unwrap();
        let key_name: [u8; 16] = utils::get_random_bytes(16).try_into().unwrap();
        let ticket = state.encrypt(key_name, &enc_key, &mac_key);
        assert_eq!(state, ticket.decrypt(&enc_key, &mac_key)?);
        Ok(())
    }
}
