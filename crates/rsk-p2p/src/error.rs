use ethereum_types::H256;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("Invalid tag: {0:?}")]
    InvalidTag(H256),

    #[error("Invalid MAC")]
    InvalidMac,

    #[error("ConcatKdf error: {0}")]
    ConcatKdf(String),

    #[error("Unsupported message ID: {0}")]
    UnsupportedMessageId(u8),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("RLP error: {0}")]
    Rlp(String),

    #[error("Snappy decompress error: {0}")]
    Snappy(String),

    #[error("Other: {0}")]
    Other(String),
}

impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Self {
        Error::InvalidPublicKey(e.to_string())
    }
}

impl From<alloy_rlp::Error> for Error {
    fn from(e: alloy_rlp::Error) -> Self {
        Error::Rlp(e.to_string())
    }
}

impl From<rlp::DecoderError> for Error {
    fn from(e: rlp::DecoderError) -> Self {
        Error::Rlp(e.to_string())
    }
}

impl From<std::num::TryFromIntError> for Error {
    fn from(e: std::num::TryFromIntError) -> Self {
        Error::InvalidInput(e.to_string())
    }
}

impl From<hmac::digest::InvalidLength> for Error {
    fn from(e: hmac::digest::InvalidLength) -> Self {
        Error::InvalidInput(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
