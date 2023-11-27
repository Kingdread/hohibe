//! Error definitions for HIBE operations.
use thiserror::Error;

/// Type for all errors that can occur when working with the HIBE implementations of this crate.
#[derive(Debug, Error)]
pub enum Error {
    /// Error returned when the identity that was supplied exceeded the given maximum hierarchy
    /// depth.
    ///
    /// Can also be returned when trying to derive a key that would exceed the maximum identity
    /// depth.
    #[error("The supplied identity was too long")]
    IdentityTooLong,

    /// Error returned when trying to derive the root identity, as there is no parent key for the
    /// root.
    #[error("Cannot derive the root identity")]
    DerivingRoot,

    /// Error when the given ciphertext was malformed.
    ///
    /// Note that this crate does not verify the integrity of ciphertexts. The absence of a
    /// malformation therefore does *not* mean that the ciphertext has not been tampered with!
    #[error("The supplied ciphertext was malforemd")]
    MalformedCiphertext,
}

/// Shortcut for [`std::result::Result`] with [`enum@Error`] as the default error.
pub type Result<V, E=Error> = std::result::Result<V, E>;
