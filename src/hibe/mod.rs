//! Low-level implementation of HIBE primitives.
//!
//! The structs and traits in this module implement HIBEs in the way that they are defined in their
//! respective papers. For a higher-level interface, refer to the [`kem`][super::kem] module.
//!
//! To make this module more flexible, all methods that use randomness only use the [`Rng`] bound,
//! not [`CryptoRng`][rand::CryptoRng]. This does not mean that you should use them with insecure
//! randomness, but rather that you need to take care when using these low-level primitives!
//!
//! # Identity Handling
//!
//! This module assumes that identity hierarchies are represented by sequences of "identity
//! elements". The type of the identity elements is defined by the actual HIBE algorithm, but
//! usually ends up being a [`Scalar`][bls12_381_plus::Scalar]. The assumption is that the more
//! elements are provided, the deeper down the hierarchy goes. For example:
//!
//! ```ignore
//! let root = &[];  // Represents the root identity
//! let a = &[1];
//! let b = &[1, 1]; // ... is a descendent of a
//! let c = &[1, 2]; // ... is also a descendent of a and a sibling of b
//! let d = &[2];    // ... is a sibling of a
//! ```
use super::error::Result;

use rand::Rng;

mod bbg;
pub use self::bbg::BonehBoyenGoh;

/// Main trait for HIBE schemes.
///
/// This trait defines the basic functionality of HIBEs, namely the generation and derivation of
/// secret keys for identities.
///
/// For encryption functionality, the extension [`HibeCrypt`] needs to be used, and for key
/// encapsulation, [`HibeKem`].
///
/// Note that this trait represents a HIBE *algorithm* not a HIBE *instantiation*.
pub trait Hibe {
    /// Type of the private key.
    ///
    /// This refers to a single identity's private key.
    type PrivateKey;
    /// Type of the master key.
    ///
    /// This is the secret key that can be used to generate the secret key of any identity.
    type MasterKey;
    /// Type of the public key.
    ///
    /// As HIBEs use identities to derive public keys, this is the public key "of the whole
    /// system", sometimes also called *master public key* or *system parameters*. There is no
    /// distinct type to represent the public key of a single identity, as many schemes compute
    /// that implicitely in the encryption functionality.
    type PublicKey;
    /// Type of an identity element.
    ///
    /// The whole identity is represented by multiple [`Identity`][Self::Identity] elements, for
    /// example in a `&[Identity]` slice.
    type Identity;

    /// Set the system up.
    ///
    /// This method outputs the master public key and the master secret key.
    fn setup<R: Rng>(&self, rng: R) -> Result<(Self::PublicKey, Self::MasterKey)>;

    /// Generate the key for the given identity.
    ///
    /// Parameters:
    ///
    /// * `rng` - The randomness to use.
    /// * `public_key` - The master public key.
    /// * `master_key` - The master secret key.
    /// * `identity` - The identity elements.
    fn generate_key<R: Rng>(
        &self,
        rng: R,
        public_key: &Self::PublicKey,
        master_key: &Self::MasterKey,
        identity: &[Self::Identity],
    ) -> Result<Self::PrivateKey>;

    /// Derives a key from the given parent identity.
    ///
    /// Parameters:
    ///
    /// * `rng` - The randomness to use.
    /// * `public_key` - The master public key.
    /// * `parent_key` - The parent's secret key.
    /// * `parent_name` - The identity of the parent.
    /// * `child` - Which child element to generate the key for.
    fn derive_key<R: Rng>(
        &self,
        rng: R,
        public_key: &Self::PublicKey,
        parent_key: &Self::PrivateKey,
        parent_name: &[Self::Identity],
        child: &Self::Identity,
    ) -> Result<Self::PrivateKey>;
}

/// HIBE methods to do encryption.
pub trait HibeCrypt: Hibe {
    /// Type of the messages that this HIBE can encrypt.
    type Message;
    /// Type of the resulting ciphertext.
    type Ciphertext;

    /// Encrypt a message for the given identity.
    ///
    /// Parameters:
    ///
    /// * `rng` - The randomness to use.
    /// * `public_key` - The master public key.
    /// * `identity` - The identity for which to encrypt the message.
    /// * `message` - The actual message.
    fn encrypt<R: Rng>(
        &self,
        rng: R,
        public_key: &Self::PublicKey,
        identity: &[Self::Identity],
        message: &Self::Message,
    ) -> Result<Self::Ciphertext>;

    /// Decrypt a message given the secret key.
    fn decrypt(
        &self,
        public_key: &Self::PublicKey,
        key: &Self::PrivateKey,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::Message>;
}

/// HIBE methods to do key encapsulation.
pub trait HibeKem: Hibe {
    /// Type of the resulting key.
    type Key;
    /// Type of the encapsulation of the key.
    type EncapsulatedKey;

    /// Computes a key encapsulation.
    ///
    /// Returns the generated key and its encapsulation.
    ///
    /// Parameters:
    ///
    /// * `rng` - The randomness to use.
    /// * `public_key` - The master public key.
    /// * `identity` - The identity for which to encapsulate the key.
    fn encapsulate<R: Rng>(
        &self,
        rng: R,
        public_key: &Self::PublicKey,
        identity: &[Self::Identity],
    ) -> Result<(Self::Key, Self::EncapsulatedKey)>;

    /// Decapsulate a previously encapsulated key.
    fn decapsulate(
        &self,
        public_key: &Self::PublicKey,
        key: &Self::PrivateKey,
        encapsulation: &Self::EncapsulatedKey,
    ) -> Result<Self::Key>;
}

