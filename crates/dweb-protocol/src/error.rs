use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid config: {0}")]
    Config(String),
    #[error("invalid name: {0}")]
    Name(String),
    #[error("invalid key or signature: {0}")]
    Crypto(String),
    #[error("invalid operation: {0}")]
    Op(String),
    #[error("encoding error: {0}")]
    Encoding(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
