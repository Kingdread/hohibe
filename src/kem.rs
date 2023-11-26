//! High-level wrapper around HIBE operations.
//!
//! Usually, people don't communicate by sending each other group elements. Therefore, we provide
//! this opinionated and easier-to-use wrapper over the raw HIBE operations.
//!
//! The main struct is [`HybridKem`], which wraps a [`Hibe`] to provide high-level operations. The
//! main differences include:
//!
//! * Generated keys (from [`HibeKem`]) are hashed to `[u8; 16]` (128 Bit) using SHA3 to make it
//!   easy to use them in other cryptographic primitives.
//! * Encryption and decryption (from [`HibeCrypt`][super::hibe::HibeCrypt]) is realized by using
//!   hybrid encryption, using the KEM and AES encryption on top. This allows you to easily encrypt
//!   byte sequences instead of group elements.
//! * Identities are mapped through a [`Mapper`], which makes it easier to specify identities at
//!   the call-site. You can for example provide a mapper that takes IP addresses as input, and
//!   outputs the correct "raw" identity.
//! * The types are wrapped in proper opaque structs instead of being type aliases. This makes it
//!   easier to implement new methods on those types or customize their behaviour (for example, by
//!   providing an easier-to-use [`Debug`] implementation).
//! * The methods in this module are restricted to [`CryptoRng`] random generators to enforce the
//!   use of cryptographically secure algorithms.
//!
//! To provide easier usability, this implementation is hardwired to use [`BonehBoyenGoh`] as the
//! underlying HIBE. This allows us to not fiddle around with too many generic parameters and
//! generic bounds. Maybe this will change in the future.
//!
//! As a default mapper, [`HashMapper`] is provided, which uses the existing [`std::hash::Hash`]
//! implementation on types to hash to a identity. Note that this may lead to collisions, like with
//! any hash — but they are expected to by unlikely, as the underlying hash is SHA3-256.
use super::{
    error::{Error, Result},
    hibe::{BonehBoyenGoh, Hibe, HibeKem},
    ByteAccess, Mapper,
};

use std::{
    fmt::{self, Debug},
    hash::{Hash, Hasher},
};

use aes::cipher::{KeyIvInit, StreamCipher};
use bls12_381_plus::{Gt, Scalar};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

type AesCtr = ctr::Ctr64LE<aes::Aes128>;
static IV: [u8; 16] = [0; 16];

/// Represents a public key.
///
/// In the context of HIBE, this is the "master public key", sometimes also called the "public
/// parameters". The key does not represent the public key for a single identity, but rather the
/// global public key. The encryption functionality then takes the identity as an additional
/// parameter.
///
/// You mainly want to pass this object around (e.g. to [`HybridKem::encrypt`]) without caring
/// about its internals. You can however serialize and deserialize a key to save or transmit it.
///
/// Note that the debug output does not output all inner bytes and instead outputs a small
/// fingerprint only. This makes it easier to use the debug output, as the actual value has too
/// many bytes to show nicely.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct PublicKey(<BonehBoyenGoh as Hibe>::PublicKey);

impl From<<BonehBoyenGoh as Hibe>::PublicKey> for PublicKey {
    fn from(value: <BonehBoyenGoh as Hibe>::PublicKey) -> Self {
        Self(value)
    }
}

impl ByteAccess for PublicKey {
    fn bytes(&self) -> Vec<u8> {
        bincode::serialize(&self.0).unwrap()
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PublicKey")
            .field(&self.fingerprint())
            .finish()
    }
}

/// Represents a the master secret key.
///
/// The master secret key allows the holder to generate secret keys for any identity.
///
/// You mainly want to pass this object around (e.g. to [`HybridKem::generate_key`]) without caring
/// about its internals. You can however serialize and deserialize a key to save or transmit it.
///
/// Note that the debug output does not output all inner bytes and instead outputs a small
/// fingerprint only. This makes it easier to use the debug output, as the actual value has too
/// many bytes to show nicely.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct MasterKey(<BonehBoyenGoh as Hibe>::MasterKey);

impl From<<BonehBoyenGoh as Hibe>::MasterKey> for MasterKey {
    fn from(value: <BonehBoyenGoh as Hibe>::MasterKey) -> Self {
        Self(value)
    }
}

impl ByteAccess for MasterKey {
    fn bytes(&self) -> Vec<u8> {
        bincode::serialize(&self.0).unwrap()
    }
}

impl Debug for MasterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("MasterKey")
            .field(&self.fingerprint())
            .finish()
    }
}

/// Represents an identity's secret key.
///
/// This private key allows the holder to decrypt ciphertexts for the identity it belongs to.
///
/// You mainly want to pass this object around (e.g. to [`HybridKem::decrypt`]) without caring
/// about its internals. You can however serialize and deserialize a key to save or transmit it.
///
/// Note that the debug output does not output all inner bytes and instead outputs a small
/// fingerprint only. This makes it easier to use the debug output, as the actual value has too
/// many bytes to show nicely.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct PrivateKey(<BonehBoyenGoh as Hibe>::PrivateKey);

impl From<<BonehBoyenGoh as Hibe>::PrivateKey> for PrivateKey {
    fn from(value: <BonehBoyenGoh as Hibe>::PrivateKey) -> Self {
        Self(value)
    }
}

impl ByteAccess for PrivateKey {
    fn bytes(&self) -> Vec<u8> {
        bincode::serialize(&self.0).unwrap()
    }
}

impl Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PrivateKey")
            .field(&self.fingerprint())
            .finish()
    }
}

/// Represents an encapsulated key.
///
/// An encapsulated key is the precursor to a shared secret: by applying their secret key to it, an
/// identity can generate the same key that has been embedded by the creator of the encapsulation.
///
/// You mainly want to pass this object around (e.g. to [`HybridKem::decapsulate`]) without caring
/// about its internals. You can however serialize and deserialize a key to save or transmit it.
///
/// Note that the debug output does not output all inner bytes and instead outputs a small
/// fingerprint only. This makes it easier to use the debug output, as the actual value has too
/// many bytes to show nicely.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct EncapsulatedKey(<BonehBoyenGoh as HibeKem>::EncapsulatedKey);

impl From<<BonehBoyenGoh as HibeKem>::EncapsulatedKey> for EncapsulatedKey {
    fn from(value: <BonehBoyenGoh as HibeKem>::EncapsulatedKey) -> Self {
        Self(value)
    }
}

impl ByteAccess for EncapsulatedKey {
    fn bytes(&self) -> Vec<u8> {
        bincode::serialize(&self.0).unwrap()
    }
}

impl Debug for EncapsulatedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("EncapsulatedKey")
            .field(&self.fingerprint())
            .finish()
    }
}

fn hash_from_curve(element: Gt) -> [u8; 16] {
    let mut result = [0; 16];
    result.copy_from_slice(&Sha3_256::digest(element.to_bytes())[..16]);
    result
}

/// High-level implementation of HIBE operations.
///
/// This struct internally uses the [`BonehBoyenGoh`]-HIBE to provide high-level key-encapsulation
/// and encryption. In addition, this struct keeps a [`Mapper`] around to do the mapping of
/// high-level identities to low-level identities.
///
/// For more information about the differences to [`Hibe`], see the [module-level][self] documentation.
#[derive(Clone, Debug)]
pub struct HybridKem<M> {
    hibe: BonehBoyenGoh,
    mapper: M,
}

impl HybridKem<HashMapper> {
    /// Create a new [`HybridKem`] using the [`HashMapper`] mapper.
    ///
    /// Parameters:
    ///
    /// * `max_depth` - Maximum depth that the hierarchy should support.
    pub fn new(max_depth: usize) -> HybridKem<HashMapper> {
        Self::new_with_mapper(max_depth, HashMapper)
    }
}

impl<M> HybridKem<M> {
    /// Create a new [`HybridKem`] with the given [`Mapper`].
    ///
    /// Parameters:
    ///
    /// * `max_depth` - Maximum depth that the hierarchy should support.
    /// * `mapper` - The mapper to use for identity mapping.
    pub fn new_with_mapper(max_depth: usize, mapper: M) -> HybridKem<M> {
        let hibe = BonehBoyenGoh::new(max_depth);
        Self { hibe, mapper }
    }

    /// Wraps an existing [`BonehBoyenGoh`] HIBE.
    ///
    /// This will result in the [`HybridKem`] supporting the same hierarchy depth that the wrapped
    /// HIBE supports.
    ///
    /// Parameters:
    ///
    /// * `hibe` - The inner HIBE to wrap.
    /// * `mapper` - The mapper to use for identity mapping.
    pub fn wrap(hibe: BonehBoyenGoh, mapper: M) -> HybridKem<M> {
        Self { hibe, mapper }
    }

    /// Sets up the system parameters.
    ///
    /// This operation will return the master public key and the master secret key.
    ///
    /// Parameters:
    ///
    /// * `rng` - The randomness to use.
    pub fn setup<R: Rng + CryptoRng>(&self, rng: R) -> Result<(PublicKey, MasterKey)> {
        let (public_key, master_key) = self.hibe.setup(rng)?;
        Ok((public_key.into(), master_key.into()))
    }

    /// Generates the secret key for a user using the master secret key.
    ///
    /// Parameters:
    ///
    /// * `rng` - The randomness to use.
    /// * `public_key` - The public key of the system.
    /// * `master_key` - The master secret key.
    /// * `identity` - The identity for which to generate the key.
    pub fn generate_key<I, R: Rng + CryptoRng>(
        &self,
        rng: R,
        public_key: &PublicKey,
        master_key: &MasterKey,
        identity: I,
    ) -> Result<PrivateKey>
    where
        M: Mapper<I, <BonehBoyenGoh as Hibe>::Identity>,
    {
        let identity = self.mapper.map_identity(identity)?;
        let private_key = self
            .hibe
            .generate_key(rng, &public_key.0, &master_key.0, &identity)?;
        Ok(private_key.into())
    }

    /// Derives the secret key for an identity given the secret key of its parent.
    ///
    /// If the given `parent_key` does not actually belong to the parent of `identity`, the
    /// resulting key will be wrong.
    ///
    /// Parameters:
    ///
    /// * `rng` - The randomness to use.
    /// * `public_key` - The public key of the system.
    /// * `parent_key` - The key of the parent identity.
    /// * `identity` - The identity for which to generate the key.
    pub fn derive_key<I, R: Rng + CryptoRng>(
        &self,
        rng: R,
        public_key: &PublicKey,
        parent_key: &PrivateKey,
        identity: I,
    ) -> Result<PrivateKey>
    where
        M: Mapper<I, <BonehBoyenGoh as Hibe>::Identity>,
    {
        let identity = self.mapper.map_identity(identity)?;
        let Some((child, parent)) = identity.split_last() else {
            return Err(Error::EmptyIdentity);
        };
        let private_key = self
            .hibe
            .derive_key(rng, &public_key.0, &parent_key.0, parent, child)?;
        Ok(private_key.into())
    }

    /// Encapsulate a key for the given identity.
    ///
    /// This returns the key and its encapsulation.
    ///
    /// Parameters:
    ///
    /// * `rng` - The randomness to use.
    /// * `public_key` - The public key of the system.
    /// * `identity` - The identity for which to generate the key.
    pub fn encapsulate<I, R: Rng + CryptoRng>(
        &self,
        rng: R,
        public_key: &PublicKey,
        identity: I,
    ) -> Result<([u8; 16], EncapsulatedKey)>
    where
        M: Mapper<I, <BonehBoyenGoh as Hibe>::Identity>,
    {
        let identity = self.mapper.map_identity(identity)?;
        let (key, encapsulation) = self.hibe.encapsulate(rng, &public_key.0, &identity)?;
        Ok((hash_from_curve(key), encapsulation.into()))
    }

    /// Decapsulate the given key.
    ///
    /// If the correct secret key is given, this will return the same key that the corresponding
    /// [`HybridKem::encapsulate`] call also returned.
    ///
    /// Parameters:
    ///
    /// * `public_key` - The public key of the system.
    /// * `key` - The private key of the receiving identity.
    /// * `encapsulation` - The encapsulation of the key.
    pub fn decapsulate(
        &self,
        public_key: &PublicKey,
        key: &PrivateKey,
        encapsulation: &EncapsulatedKey,
    ) -> Result<[u8; 16]> {
        let key = self
            .hibe
            .decapsulate(&public_key.0, &key.0, &encapsulation.0)?;
        Ok(hash_from_curve(key))
    }

    /// Encrypt the given byte sequence for the given identity.
    ///
    /// This internally uses a hybrid encryption where the key is encapsulated by the KEM, and the
    /// payload is then encrypted symetrically with AES (counter mode).
    ///
    /// Note that the resulting ciphertext is longer than the payload, as some space is needed for
    /// the encapsulated key. The key is automatically prepended to the encrypted payload.
    ///
    /// Parameters:
    ///
    /// * `rng` - The randomness to use.
    /// * `public_key` - The public key of the system.
    /// * `identity` - The identity for which to encrypt the payload.
    /// * `payload` - Payload to encrypt.
    pub fn encrypt<I, R: Rng + CryptoRng>(
        &self,
        rng: R,
        public_key: &PublicKey,
        identity: I,
        payload: &[u8],
    ) -> Result<Vec<u8>>
    where
        M: Mapper<I, <BonehBoyenGoh as Hibe>::Identity>,
    {
        let (key, encapsulation) = self.encapsulate(rng, public_key, identity)?;
        let mut buffer = Vec::from(payload);
        let mut cipher = AesCtr::new(&key.into(), &IV.into());
        cipher.apply_keystream(&mut buffer);
        Ok(bincode::serialize(&(encapsulation, buffer)).expect("Serialization failed"))
    }

    /// Decrypt the given ciphertext.
    ///
    /// Returns the payload.
    ///
    /// Parameters:
    ///
    /// * `public_key` - The public key of the system.
    /// * `key` - The private key of the receiving identity.
    /// * `ciphertext` - The ciphertext, as previously returned by [`HybridKem::encrypt`].
    pub fn decrypt(
        &self,
        public_key: &PublicKey,
        key: &PrivateKey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let (encapsulation, mut buffer): (EncapsulatedKey, Vec<u8>) =
            bincode::deserialize(ciphertext).map_err(|_| Error::MalformedCiphertext)?;
        let key = self.decapsulate(public_key, key, &encapsulation)?;
        let mut cipher = AesCtr::new(&key.into(), &IV.into());
        cipher.apply_keystream(&mut buffer);
        Ok(buffer)
    }
}

#[derive(Default)]
struct Sha3Hasher(Sha3_256);

impl Sha3Hasher {
    fn hash_to_scalar(self) -> Scalar {
        let mut bytes = [0; 48];
        bytes[..32].copy_from_slice(&self.0.finalize());
        Scalar::from_okm(&bytes)
    }

    fn hash<H: Hash>(element: &H) -> Scalar {
        let mut hasher = Sha3Hasher::default();
        element.hash(&mut hasher);
        hasher.hash_to_scalar()
    }
}

impl Hasher for Sha3Hasher {
    fn finish(&self) -> u64 {
        u64::from_be_bytes(self.0.clone().finalize()[..8].try_into().unwrap())
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }
}

/// A [`Mapper`] that works for all types implementing [`std::hash::Hash`].
///
/// This mapper uses the hash implementation to hash objects to [`Scalar`]s, the underlying
/// identity element for [`HybridKem`]. Internally, a SHA3-256 instance is used to provide
/// consistent hashing and collision resistance.
///
/// In order to provide a hierarchy, the mapper does not accept single elements, but rather
/// iterators over elements. The more elements the iterator produces, the deeper down the hierarchy
/// we go.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HashMapper;

impl HashMapper {
    /// Create a new [`HashMapper`].
    pub fn new() -> HashMapper {
        HashMapper
    }
}

impl<I, F> Mapper<I, Scalar> for HashMapper
where
    I: IntoIterator<Item = F>,
    F: Hash,
{
    fn map_identity(&self, input: I) -> Result<Vec<Scalar>> {
        Ok(input
            .into_iter()
            .map(|element| Sha3Hasher::hash(&element))
            .collect())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let mut rng = rand::thread_rng();
        let kem = HybridKem::new(5);
        let (public_key, master_key) = kem.setup(&mut rng).unwrap();

        let identity = &[1, 2, 3] as &[_];
        let secret_key = kem
            .generate_key(&mut rng, &public_key, &master_key, identity)
            .unwrap();
        let message = b"Hello, world!";
        let ciphertext = kem
            .encrypt(&mut rng, &public_key, identity, message)
            .unwrap();
        let decryption = kem.decrypt(&public_key, &secret_key, &ciphertext).unwrap();
        assert_eq!(message.as_slice(), decryption.as_slice());
    }
}
