use crate::rpc_types;

pub type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug)]
pub enum Error {
    RelayProtocolNotMentioned,
    InvalidUri,
    SymKeyNotMentioned,
    PathEndNotFound,
    ParseInt(std::num::ParseIntError),
    JsonRpc(rpc_types::JsonRpcError),
    Anyhow(anyhow::Error),
    Reqwest(reqwest::Error),
    InternalError(String),
    SerdeJsonError(serde_json::Error),
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
