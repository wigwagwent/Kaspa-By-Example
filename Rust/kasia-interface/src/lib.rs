use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine, engine::general_purpose};
use kaspa_bip32::secp256k1;
use thiserror::Error;

pub mod cipher;

pub const BROADCAST_GROUP_MAXLEN: usize = 36;
pub const BROADCAST_MESSAGE_MAXLEN: usize = 15000;
pub const ALIAS_LEN: usize = 12;
pub const CIPH_MSG_PREFIX: &[u8] = b"ciph_msg:1:";

#[derive(Error, Debug)]
pub enum KaspaMessageError {
    #[error("Failed to decode hex payload: {0}")]
    HexDecodeError(#[from] hex::FromHexError),

    #[error("Failed to convert payload to UTF-8: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),

    #[error("Failed to json serialize payload: {0}")]
    SerdeSerializeError(#[from] serde_json::Error),

    #[error("Group name must be between 1 and {BROADCAST_GROUP_MAXLEN} characters")]
    InvalidGroupLength,

    #[error("Group name contains invalid characters (must be ASCII, no ':'")]
    InvalidGroupCharacters,

    #[error("Message must be between 1 and {BROADCAST_MESSAGE_MAXLEN} characters")]
    InvalidMessageLength,

    #[error("Invalid broadcast message format")]
    InvalidBroadcastFormat,

    #[error("Unknown message type")]
    UnknownMessageType,

    #[error("Cannot operate on invalid message")]
    InvalidMessage,

    #[error("Invalid encrypted communication format: expected 'alias:hex_data'")]
    InvalidEncryptCommFormat,

    #[error("Invalid alias length: must be {ALIAS_LEN} characters")]
    InvalidAliasLength,

    #[error("Invalid alias characters: only alphanumeric characters are allowed")]
    InvalidAliasCharacters,

    #[error("Encrypted message cannot be empty")]
    InvalidEncryptedMessageLength,

    #[error("Encryption failed")]
    EncryptionError,

    #[error("Decryption failed")]
    DecryptionError,

    #[error("Encryption must be performed before sending")]
    EncryptBeforeSending,
}

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HandshakeMessage {
    #[serde(rename = "type")]
    pub message_type: String, //handshake
    pub alias: String,
    #[serde(default)]
    pub their_alias: String,
    pub timestamp: u64,
    pub version: u32,
    #[serde(default)]
    pub is_response: bool,
}

#[derive(Debug, Clone)]
pub enum KaspaMessage {
    Broadcast {
        group: String,
        message: String,
    },
    EncryptCommunication {
        alias: String,
        encrypted_msg: cipher::EncryptedMessage,
    },
    DecryptCommunication {
        alias: String,
        decrypted_msg: String,
    },
    EncryptHandshake {
        encrypted_msg: cipher::EncryptedMessage,
    },
    DecryptHandshake {
        decrypted_msg: HandshakeMessage,
    },
    Invalid,
}

impl PartialEq for KaspaMessage {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Broadcast {
                    group: g1,
                    message: m1,
                },
                Self::Broadcast {
                    group: g2,
                    message: m2,
                },
            ) => g1 == g2 && m1 == m2,

            (
                Self::EncryptCommunication { alias: a1, .. },
                Self::EncryptCommunication { alias: a2, .. },
            ) => a1 == a2, // Ignore encrypted_msg

            (
                Self::DecryptCommunication {
                    alias: a1,
                    decrypted_msg: d1,
                },
                Self::DecryptCommunication {
                    alias: a2,
                    decrypted_msg: d2,
                },
            ) => a1 == a2 && d1 == d2,

            (Self::EncryptHandshake { .. }, Self::EncryptHandshake { .. }) => true, // Ignore all

            (
                Self::DecryptHandshake { decrypted_msg: d1 },
                Self::DecryptHandshake { decrypted_msg: d2 },
            ) => d1 == d2,

            (Self::Invalid, Self::Invalid) => true,

            _ => false, // Different variants
        }
    }
}

impl KaspaMessage {
    pub fn new_broadcast(group: impl Into<String>, message: impl Into<String>) -> Self {
        let broadcast = Self::Broadcast {
            group: group.into().to_lowercase(),
            message: message.into(),
        };

        broadcast
            .validate_broadcast()
            .map_or(Self::Invalid, |_| broadcast)
    }

    pub fn new_communication(alias: impl Into<String>, decrypted_msg: String) -> Self {
        let comm = Self::DecryptCommunication {
            alias: alias.into(),
            decrypted_msg,
        };

        comm.validate_decrypt_comm().map_or(Self::Invalid, |_| comm)
    }

    pub fn new_handshake_request(alias: String) -> Self {
        let handshake_msg = HandshakeMessage {
            message_type: "handshake".to_string(),
            alias,
            their_alias: String::new(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            version: 1,
            is_response: false,
        };

        let handshake = Self::DecryptHandshake {
            decrypted_msg: handshake_msg,
        };

        handshake
            .validate_decrypt_handshake()
            .map_or(Self::Invalid, |_| handshake)
    }

    pub fn new_handshake_response(their_alias: String, alias: String) -> Self {
        let handshake_msg = HandshakeMessage {
            message_type: "handshake".to_string(),
            alias,
            their_alias,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            version: 1,
            is_response: true,
        };

        let handshake = Self::DecryptHandshake {
            decrypted_msg: handshake_msg,
        };

        handshake
            .validate_decrypt_handshake()
            .map_or(Self::Invalid, |_| handshake)
    }

    pub fn is_invalid(&self) -> bool {
        matches!(self, Self::Invalid)
    }

    fn validate_alias(alias: &str) -> Result<(), KaspaMessageError> {
        if alias.len() != ALIAS_LEN {
            return Err(KaspaMessageError::InvalidAliasLength);
        }

        if !alias.chars().all(|c| c.is_alphanumeric()) {
            return Err(KaspaMessageError::InvalidAliasCharacters);
        }
        Ok(())
    }

    fn validate_broadcast(&self) -> Result<(), KaspaMessageError> {
        let (group, message) = match self {
            Self::Broadcast { group, message } => (group, message),
            _ => panic!("Not a broadcast message"),
        };

        if group.is_empty() || group.len() > BROADCAST_GROUP_MAXLEN {
            return Err(KaspaMessageError::InvalidGroupLength);
        }

        if !group.chars().all(|c| c.is_ascii() && c != ':') {
            return Err(KaspaMessageError::InvalidGroupCharacters);
        }

        if message.is_empty() || message.len() > BROADCAST_MESSAGE_MAXLEN {
            return Err(KaspaMessageError::InvalidMessageLength);
        }

        Ok(())
    }

    fn validate_encrypt_comm(&self) -> Result<(), KaspaMessageError> {
        let (alias, encrypted_msg) = match self {
            Self::EncryptCommunication {
                alias,
                encrypted_msg,
            } => (alias, encrypted_msg),
            _ => panic!("Not an encrypted communication message"),
        };

        Self::validate_alias(alias)?;

        // Validate encrypted message has required components
        if encrypted_msg.nonce.is_empty()
            || encrypted_msg.ephemeral_public_key.is_empty()
            || encrypted_msg.ciphertext.is_empty()
        {
            return Err(KaspaMessageError::InvalidEncryptedMessageLength);
        }

        Ok(())
    }

    fn validate_encrypt_handshake(&self) -> Result<(), KaspaMessageError> {
        let encrypted_msg = match self {
            Self::EncryptHandshake { encrypted_msg } => encrypted_msg,
            _ => panic!("Not an encrypted handshake message"),
        };

        // Validate encrypted message has required components
        if encrypted_msg.nonce.is_empty()
            || encrypted_msg.ephemeral_public_key.is_empty()
            || encrypted_msg.ciphertext.is_empty()
        {
            return Err(KaspaMessageError::InvalidEncryptedMessageLength);
        }

        Ok(())
    }

    fn validate_decrypt_comm(&self) -> Result<(), KaspaMessageError> {
        let (alias, decrypted_msg) = match self {
            Self::DecryptCommunication {
                alias,
                decrypted_msg,
            } => (alias, decrypted_msg),
            _ => panic!("Not an encrypted communication message"),
        };

        Self::validate_alias(alias)?;

        if decrypted_msg.is_empty() || decrypted_msg.len() > BROADCAST_MESSAGE_MAXLEN {
            return Err(KaspaMessageError::InvalidMessageLength);
        }

        Ok(())
    }

    fn validate_decrypt_handshake(&self) -> Result<(), KaspaMessageError> {
        let decrypted_msg = match self {
            Self::DecryptHandshake { decrypted_msg } => decrypted_msg,
            _ => panic!("Not an encrypted communication message"),
        };

        Self::validate_alias(&decrypted_msg.alias)?;

        if &decrypted_msg.message_type != "handshake" {
            return Err(KaspaMessageError::InvalidMessage);
        }

        if decrypted_msg.is_response {
            Self::validate_alias(&decrypted_msg.their_alias)?;
        }

        Ok(())
    }

    pub fn validate(&self) -> Result<(), KaspaMessageError> {
        match self {
            Self::Broadcast { .. } => self.validate_broadcast(),
            Self::EncryptCommunication { .. } => self.validate_encrypt_comm(),
            Self::DecryptCommunication { .. } => self.validate_decrypt_comm(),
            Self::EncryptHandshake { .. } => self.validate_encrypt_handshake(),
            Self::DecryptHandshake { .. } => self.validate_decrypt_handshake(),
            Self::Invalid => Err(KaspaMessageError::InvalidMessage),
            // _ => Err(KaspaMessageError::UnknownMessageType),
        }
    }

    pub fn to_payload(&self) -> Result<Vec<u8>, KaspaMessageError> {
        self.validate()?;

        match self {
            Self::Broadcast { group, message } => {
                Ok(format!("ciph_msg:1:bcast:{}:{}", group.to_lowercase(), message).into_bytes())
            }
            Self::EncryptCommunication {
                alias,
                encrypted_msg,
            } => {
                let hex = encrypted_msg.to_bytes();
                let b64 = general_purpose::STANDARD.encode(hex);
                Ok(format!("ciph_msg:1:comm:{}:{}", alias, b64).into_bytes())
            }
            Self::DecryptCommunication { .. } => Err(KaspaMessageError::EncryptBeforeSending),

            Self::EncryptHandshake { encrypted_msg } => {
                let msg = encrypted_msg.to_bytes();
                let mut result = b"ciph_msg:1:handshake:".to_vec();
                result.extend_from_slice(&msg);
                Ok(result)
            }

            Self::DecryptHandshake { .. } => Err(KaspaMessageError::EncryptBeforeSending),

            Self::Invalid => Err(KaspaMessageError::InvalidMessage),
            // _ => Err(KaspaMessageError::UnknownMessageType),
        }
    }

    fn parse_broadcast(payload: &[u8]) -> Result<Self, KaspaMessageError> {
        let payload_str = String::from_utf8(payload.to_vec())?;
        let parts: Vec<&str> = payload_str.splitn(2, ':').collect();

        if parts.len() != 2 {
            return Err(KaspaMessageError::InvalidBroadcastFormat);
        }

        let broadcast = Self::Broadcast {
            group: parts[0].to_string().to_lowercase(),
            message: parts[1].to_string(),
        };

        broadcast.validate_broadcast()?;
        Ok(broadcast)
    }

    fn parse_communication(payload: &[u8]) -> Result<Self, KaspaMessageError> {
        let payload_str = String::from_utf8(payload.to_vec())?;
        let parts: Vec<&str> = payload_str.splitn(2, ':').collect();

        if parts.len() != 2 {
            return Err(KaspaMessageError::InvalidEncryptCommFormat);
        }

        let alias = parts[0].to_string();

        let encrypted_bytes = general_purpose::STANDARD
            .decode(parts[1])
            .map_err(|_| KaspaMessageError::InvalidEncryptCommFormat)?;

        let hex_string = encrypted_bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();

        let encrypted_msg = cipher::EncryptedMessage::from_hex(&hex_string)
            .map_err(|_| KaspaMessageError::InvalidEncryptCommFormat)?;

        let comm = Self::EncryptCommunication {
            alias,
            encrypted_msg,
        };

        comm.validate_encrypt_comm()?;
        Ok(comm)
    }

    fn parse_handshake(payload: &[u8]) -> Result<Self, KaspaMessageError> {
        let encrypted_msg = cipher::EncryptedMessage::from_bytes(payload);

        let comm = Self::EncryptHandshake {
            encrypted_msg: encrypted_msg,
        };

        comm.validate_encrypt_handshake()?;
        Ok(comm)
    }

    pub fn get_alias(&self) -> Option<&str> {
        match self {
            Self::EncryptCommunication { alias, .. } | Self::DecryptCommunication { alias, .. } => {
                Some(alias)
            }
            _ => None,
        }
    }

    pub fn get_message(&self) -> String {
        match self {
            Self::Broadcast { message, .. } => message.clone(),
            Self::DecryptCommunication { decrypted_msg, .. } => decrypted_msg.clone(),
            Self::DecryptHandshake { decrypted_msg, .. } => {
                match serde_json::to_string(&decrypted_msg) {
                    Ok(json) => json,
                    Err(_) => String::new(),
                }
            }
            _ => String::new(),
        }
    }

    pub fn decrypt(
        &self,
        secp_secret_key: &secp256k1::SecretKey,
    ) -> Result<Self, KaspaMessageError> {
        match self {
            Self::EncryptCommunication {
                alias,
                encrypted_msg,
            } => {
                let decrypted_msg = cipher::decrypt_with_secret_key(
                    encrypted_msg.clone(),
                    &secp_secret_key.secret_bytes(),
                )
                .map_err(|_| KaspaMessageError::DecryptionError)?;

                Ok(Self::DecryptCommunication {
                    alias: alias.clone(),
                    decrypted_msg,
                })
            }
            Self::EncryptHandshake { encrypted_msg } => {
                let decrypted_msg = cipher::decrypt_with_secret_key(
                    encrypted_msg.clone(),
                    &secp_secret_key.secret_bytes(),
                )
                .map_err(|_| KaspaMessageError::DecryptionError)?;

                Ok(Self::DecryptHandshake {
                    decrypted_msg: serde_json::from_str(&decrypted_msg)?,
                })

                // self.validate_decrypt_handshake()?;
            }
            _ => Err(KaspaMessageError::InvalidMessage),
        }
    }

    /// Converts DecryptCommunication to EncryptCommunication
    /// Takes the decrypted message and encrypts it with the recipient's public key
    pub fn encrypt(&self, receiver_address: &str) -> Result<Self, KaspaMessageError> {
        match self {
            Self::DecryptCommunication {
                alias,
                decrypted_msg,
            } => {
                let encrypted_msg = cipher::encrypt_message(receiver_address, decrypted_msg)
                    .map_err(|_| KaspaMessageError::EncryptionError)?;

                Ok(Self::EncryptCommunication {
                    alias: alias.clone(),
                    encrypted_msg,
                })
            }
            Self::DecryptHandshake { decrypted_msg } => {
                let json_msg = serde_json::to_string(&decrypted_msg)?;
                let encrypted_msg = cipher::encrypt_message(receiver_address, &json_msg)
                    .map_err(|_| KaspaMessageError::EncryptionError)?;

                Ok(Self::EncryptHandshake { encrypted_msg })
            }
            _ => Err(KaspaMessageError::InvalidMessage),
        }
    }

    pub fn is_encrypted(&self) -> bool {
        matches!(
            self,
            Self::EncryptCommunication { .. } | Self::EncryptHandshake { .. }
        )
    }
}

impl TryFrom<&[u8]> for KaspaMessage {
    type Error = KaspaMessageError;

    fn try_from(payload: &[u8]) -> Result<Self, Self::Error> {
        // Check prefix as bytes first
        if !payload.starts_with(CIPH_MSG_PREFIX) {
            return Err(KaspaMessageError::UnknownMessageType);
        }

        // Strip the prefix
        let rest = &payload[CIPH_MSG_PREFIX.len()..];

        // Check message type prefixes as bytes
        if rest.starts_with(b"bcast:") {
            let content = &rest[6..]; // Skip "bcast:"
            Self::parse_broadcast(content)
        } else if rest.starts_with(b"comm:") {
            let content = &rest[5..]; // Skip "comm:"
            Self::parse_communication(content)
        } else if rest.starts_with(b"handshake:") {
            let content = &rest[10..]; // Skip "handshake:"
            Self::parse_handshake(content)
        } else {
            Err(KaspaMessageError::UnknownMessageType)
        }
    }
}

impl TryFrom<&Vec<u8>> for KaspaMessage {
    type Error = KaspaMessageError;

    fn try_from(payload: &Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(payload.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use crate::cipher::{decrypt_message, encrypt_message};

    use super::*;
    use chacha20poly1305::aead::OsRng;
    use k256::SecretKey;
    use kaspa_wallet_keys::{
        prelude::PublicKey as WalletPublicKey, privatekey::PrivateKey as WalletPrivateKey,
    };
    use kaspa_wrpc_client::prelude::NetworkType;
    use secp256k1::PublicKey as SecpPublicKey;

    #[test]
    fn test_broadcast_parsing() {
        let raw =
            "636970685f6d73673a313a62636173743a7665727972616e646f6d3a546869732069732074657374";
        let bytes = hex::decode(raw).unwrap();
        let message = KaspaMessage::try_from(&bytes);
        if message.is_err() {
            panic!("Failed to parse broadcast: {}", message.err().unwrap());
        }
        let message = message.unwrap();
        assert!(!message.is_invalid());
        if let KaspaMessage::Broadcast { group, message } = message {
            assert_eq!(group, "veryrandom");
            assert_eq!(message, "This is test");
        } else {
            panic!("Parsed message is not a broadcast");
        }
    }

    #[test]
    fn test_broadcast_creation() {
        let message = KaspaMessage::new_broadcast("veryrandom", "This is test");
        assert!(!message.is_invalid());
        if let KaspaMessage::Broadcast {
            group,
            message: text,
        } = message.clone()
        {
            assert_eq!(group, "veryrandom");
            assert_eq!(text, "This is test");
        } else {
            panic!("Created message is not a broadcast");
        }

        let payload = message.to_payload().unwrap();
        assert_eq!(
            payload,
            "ciph_msg:1:bcast:veryrandom:This is test".as_bytes()
        );
    }

    #[test]
    fn test_encode_decode() {
        let receiver_sk = SecretKey::random(&mut OsRng);
        let receiver_pk = receiver_sk.public_key();

        let sec_receiver_pk = SecpPublicKey::from_slice(&receiver_pk.to_sec1_bytes()).unwrap();
        let wallet_pk = WalletPublicKey::from(sec_receiver_pk);

        let receiver_address = wallet_pk.to_address(NetworkType::Testnet).unwrap();

        let wallet_private_key =
            WalletPrivateKey::try_from_slice(receiver_sk.to_bytes().as_ref()).unwrap();

        let message = "plaintext message";
        let encrypted_message = encrypt_message(&receiver_address.to_string(), message).unwrap();

        //encode
        let hex = encrypted_message.to_bytes();
        let b64 = general_purpose::STANDARD.encode(hex);

        //decode
        let encrypted_bytes = general_purpose::STANDARD
            .decode(b64)
            .map_err(|_| KaspaMessageError::InvalidEncryptCommFormat)
            .unwrap();

        let hex_string = encrypted_bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();

        let encrypted_msg = cipher::EncryptedMessage::from_hex(&hex_string)
            .map_err(|_| KaspaMessageError::InvalidEncryptCommFormat)
            .unwrap();

        let decrypted_message = decrypt_message(encrypted_msg, wallet_private_key).unwrap();
        assert_eq!(message.to_owned(), decrypted_message);
    }

    #[test]
    fn test_encode_decode_handshake_response() {
        let receiver_sk = secp256k1::SecretKey::new(&mut secp256k1::rand::thread_rng());
        let receiver_pk = secp256k1::PublicKey::from_secret_key_global(&receiver_sk);

        let wallet_pk = WalletPublicKey::from(receiver_pk);
        let receiver_address = wallet_pk.to_address(NetworkType::Testnet).unwrap();

        let msg = KaspaMessage::new_handshake_response(
            "abababababab".to_string(),
            "121212121212".to_string(),
        );
        assert!(!msg.is_invalid());

        let encrypted_message = msg.encrypt(&receiver_address.to_string()).unwrap();
        let output = encrypted_message.to_payload().unwrap();

        // Receive side
        let encrypted_msg = KaspaMessage::try_from(&output).unwrap();
        let decrypted_message = encrypted_msg.decrypt(&receiver_sk).unwrap();
        assert_eq!(msg, decrypted_message);
    }
}
