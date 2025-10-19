use thiserror::Error;

pub const BROADCAST_GROUP_MAXLEN: usize = 36;
pub const BROADCAST_MESSAGE_MAXLEN: usize = 1000; // TODO: get the actual size or at least a better estimate
pub const CIPH_MSG_PREFIX: &[u8] = b"ciph_msg:1:";

#[derive(Error, Debug)]
pub enum KaspaMessageError {
    #[error("Failed to decode hex payload: {0}")]
    HexDecodeError(#[from] hex::FromHexError),

    #[error("Failed to convert payload to UTF-8: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),

    #[error("Group name must be between 1 and {BROADCAST_GROUP_MAXLEN} characters")]
    InvalidGroupLength,

    #[error("Group name contains invalid characters (must be ASCII, no ':'")]
    InvalidGroupCharacters,

    #[error("Message must be between 1 and {BROADCAST_MESSAGE_MAXLEN} chacharacters")]
    InvalidMessageLength,

    #[error("Invalid broadcast message format")]
    InvalidBroadcastFormat,

    #[error("Unknown message type")]
    UnknownMessageType,

    #[error("Cannot operate on invalid message")]
    InvalidMessage,
}

#[derive(Debug, Clone)]
pub enum KaspaMessage {
    Broadcast { group: String, message: String },
    Communication { their_alias: String }, // TODO
    Invalid,
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

    pub fn is_invalid(&self) -> bool {
        matches!(self, Self::Invalid)
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

    pub fn validate(&self) -> Result<(), KaspaMessageError> {
        match self {
            Self::Broadcast { .. } => self.validate_broadcast(),
            Self::Communication { .. } => Ok(()), // TODO: Implement communication validation
            Self::Invalid => Err(KaspaMessageError::InvalidMessage),
        }
    }

    pub fn to_payload(&self) -> Result<Vec<u8>, KaspaMessageError> {
        self.validate()?;

        match self {
            Self::Broadcast { group, message } => {
                Ok(format!("ciph_msg:1:bcast:{}:{}", group.to_lowercase(), message).into_bytes())
            }
            Self::Invalid => Err(KaspaMessageError::InvalidMessage),
            _ => Err(KaspaMessageError::UnknownMessageType),
        }
    }

    fn parse_broadcast(payload_str: &str) -> Result<Self, KaspaMessageError> {
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
}

impl TryFrom<&[u8]> for KaspaMessage {
    type Error = KaspaMessageError;

    fn try_from(payload: &[u8]) -> Result<Self, Self::Error> {
        let payload_str = String::from_utf8(payload.to_vec())?;

        let payload_str = payload_str
            .strip_prefix("ciph_msg:1:")
            .expect("Invalid prefix");

        if let Some(rest) = payload_str.strip_prefix("bcast:") {
            Self::parse_broadcast(rest)
        } else if payload_str.starts_with("comm:") {
            Err(KaspaMessageError::UnknownMessageType) //todo!("Implement communication parsing")
        } else {
            Err(KaspaMessageError::UnknownMessageType)
        }
    }
}

impl TryFrom<&Vec<u8>> for KaspaMessage {
    type Error = KaspaMessageError;
    fn try_from(payload: &Vec<u8>) -> Result<Self, Self::Error> {
        let payload_str = String::from_utf8(payload.to_vec())?;

        let payload_str = payload_str
            .strip_prefix("ciph_msg:1:")
            .expect("Invalid prefix");

        if let Some(rest) = payload_str.strip_prefix("bcast:") {
            Self::parse_broadcast(rest)
        } else if payload_str.starts_with("comm:") {
            Err(KaspaMessageError::UnknownMessageType) //todo!("Implement communication parsing")
        } else {
            Err(KaspaMessageError::UnknownMessageType)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_broadcast_parsing() {
        let payload =
            "636970685f6d73673a313a62636173743a7665727972616e646f6d3a546869732069732074657374"
                .as_bytes();
        let message = KaspaMessage::try_from(payload);
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
}
