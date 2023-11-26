pub mod error;
pub mod hibe;
pub mod kem;

use error::Result;

/// A trait to provide byte-level access to objects.
pub trait ByteAccess {
    /// Provides access to the bytes.
    ///
    /// Unlike [`AsRef`], there are no statements made about the performance of this operation.
    /// This operation will allocate a fresh vector, and the byte representation may or may not
    /// have to be computed first.
    fn bytes(&self) -> Vec<u8>;

    /// Provide a short fingerprint of the bytes.
    ///
    /// This can be used to "summarize" long keys when displaying them, to still provide
    /// distinguishing features but to not print out the whole key.
    ///
    /// By default, this method uses the first 16 bytes of the [`ByteAccess::bytes`]
    /// representation, and formats them as a hex string.
    fn fingerprint(&self) -> String {
        hex::encode(&self.bytes()[..16])
    }
}

/// A trait to mark objects that can map from an application-specific identity to a HIBE-specific
/// identity.
///
/// A mapper can be implemented multiple times for a single struct, thereby providing multiple
/// (equivalent) ways to map.
pub trait Mapper<F, T> {
    fn map_identity(&self, input: F) -> Result<Vec<T>>;
}

/// [`Mapper`] is automatically implemented for functions and closures that match the signature of
/// [`Mapper::map_identity`].
impl<X, Y, F: Fn(X) -> Result<Vec<Y>>> Mapper<X, Y> for F {
    fn map_identity(&self, input: X) -> Result<Vec<Y>> {
        self(input)
    }
}
