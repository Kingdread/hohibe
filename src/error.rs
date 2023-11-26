use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("The supplied identity was too long")]
    IdentityTooLong,
    #[error("The supplied identity had no elements")]
    EmptyIdentity,
    #[error("The supplied ciphertext was malforemd")]
    MalformedCiphertext,
}

pub type Result<V, E=Error> = std::result::Result<V, E>;
