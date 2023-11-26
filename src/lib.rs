//! Implementation of Hierarchical Identity Based Encryption ([HIBE]), an extension of Identity
//! Based Encryption ([IBE]).
//!
//! # ⚠️ Warning: Cryptographic Hazmat ☣️
//!
//! This crate is made for playing around with HIBE and for prototyping of applications and
//! protocols using HIBE. It has *not* been audited, it is *not* battle tested, and *nobody* claims
//! it to be secure.
//!
//! Use it at **your own risk** and if you know what you are doing!
//!
//! # Introduction
//!
//! HIBEs are encryption schemes in which a party can encrypt data for a given recipient by using
//! the recipient's identity in the encryption process, instead of requiring an explicitely shared
//! public key. In addition, the hierarchical property allows holders of a secret key for an
//! identity to also generate the keys of subordinate identities.
//!
//! This library is intended to provide an easy-to-use implementation of HIBE for prototyping and
//! playing around. The library is not optimized for speed, but rather for usability (for example,
//! it requires the standard library and allocations, and it unconditionally requires `serde` for
//! serialization).
//!
//! # Crate Structure
//!
//! The [`hibe`] submodule contains the basic definitions of HIBE functionality, as [`hibe::Hibe`]
//! (basic parameter and key generation), [`hibe::HibeKem`] (HIBE key encapsulation) and
//! [`hibe::HibeCrypt`] (HIBE encryption). Those methods work directly on the group elements, as
//! they are defined in their respective papers.
//!
//! To aid in using those algorithms, a higher-level wrapper is provided in the [`kem`] submodule,
//! mainly in the [`kem::HybridKem`] struct. This allows you to deal with bytes instead of group
//! elements.
//!
//! The bridge between [`hibe`] and [`kem`] is provided by [`Mapper`], which translates from
//! arbitrary identities from the application domain to the low-level, mathematical representation
//! of identities in the context of HIBEs.
//!
//! Currently, [`kem::HybridKem`] is hardwired to [`hibe::BonehBoyenGoh`] to keep the amount of
//! generics and generic bounds low. This might change in the future, when more HIBEs might be
//! implemented.
//!
//! # Implemented Algorithms
//!
//! Currenly, this crate implements the HIBE of Boneh, Boyen and Goh, "Hierarchical Identity Based
//! Encryption with Constant Size Ciphertext" ([eprint](https://eprint.iacr.org/2005/015.pdf)).
//! This algorithm lives as [`hibe::BonehBoyenGoh`].
//!
//! The algorithms in this crate are implemented on top of
//! [`bls_12_381_plus`](https://crates.io/crates/bls12_381_plus), as it provides better `serde`
//! support and access to the internals of the group elements.
//!
//! [HIBE]: https://cryptowiki.tm.kit.edu/index.php/Hierarchical_Identity-Based_Encryption
//! [IBE]: https://en.wikipedia.org/wiki/Identity-based_encryption
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
