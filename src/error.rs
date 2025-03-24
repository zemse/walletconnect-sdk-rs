#[derive(Debug, PartialEq)]
pub enum Error {
    RelayProtocolNotMentioned,
    InvalidUri,
    SymKeyNotMentioned,
    PathEndNotFound,
    ParseInt(std::num::ParseIntError),
}

impl From<std::num::ParseIntError> for Error {
    fn from(e: std::num::ParseIntError) -> Self {
        Error::ParseInt(e)
    }
}
