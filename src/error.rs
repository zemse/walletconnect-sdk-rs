use crate::rpc_types;

pub type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug)]
pub enum Error {
    RelayProtocolNotMentioned,
    InvalidUri,
    SymKeyNotMentioned,
    PathEndNotFound,
    InvalidIrnTag(u16),
    ParseInt(std::num::ParseIntError),
    JsonRpc(rpc_types::JsonRpcError),
    Anyhow(anyhow::Error),
    Reqwest(reqwest::Error),
    InternalError(String),
    SerdeJsonError(serde_json::Error),
    FromHexError(alloy::hex::FromHexError),
    AesError(aes_gcm::Error),
    FromUtf8Error(std::string::FromUtf8Error),
    FmtError(std::fmt::Error),
    SignatureError(alloy::primitives::SignatureError),
    TimeError(time::error::Format),
    SystemTimeError(std::time::SystemTimeError),
}

impl From<&str> for Error {
    fn from(e: &str) -> Self {
        Error::InternalError(e.to_string())
    }
}

impl From<String> for Error {
    fn from(e: String) -> Self {
        Error::InternalError(e)
    }
}

impl From<std::num::ParseIntError> for Error {
    fn from(e: std::num::ParseIntError) -> Self {
        Error::ParseInt(e)
    }
}

impl From<rpc_types::JsonRpcError> for Error {
    fn from(e: rpc_types::JsonRpcError) -> Self {
        Error::JsonRpc(e)
    }
}

impl From<anyhow::Error> for Error {
    fn from(e: anyhow::Error) -> Self {
        Error::Anyhow(e)
    }
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Error::Reqwest(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::SerdeJsonError(e)
    }
}

impl From<alloy::hex::FromHexError> for Error {
    fn from(e: alloy::hex::FromHexError) -> Self {
        Error::FromHexError(e)
    }
}

impl From<aes_gcm::Error> for Error {
    fn from(e: aes_gcm::Error) -> Self {
        Error::AesError(e)
    }
}

impl From<std::string::FromUtf8Error> for Error {
    fn from(e: std::string::FromUtf8Error) -> Self {
        Error::FromUtf8Error(e)
    }
}

impl From<std::fmt::Error> for Error {
    fn from(e: std::fmt::Error) -> Self {
        Error::FmtError(e)
    }
}

impl From<alloy::primitives::SignatureError> for Error {
    fn from(e: alloy::primitives::SignatureError) -> Self {
        Error::SignatureError(e)
    }
}

impl From<time::error::Format> for Error {
    fn from(e: time::error::Format) -> Self {
        Error::TimeError(e)
    }
}

impl From<std::time::SystemTimeError> for Error {
    fn from(e: std::time::SystemTimeError) -> Self {
        Error::SystemTimeError(e)
    }
}
