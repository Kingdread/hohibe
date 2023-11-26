use super::error::Result;

use rand::Rng;

mod bbg;
pub use self::bbg::BonehBoyenGoh;

pub trait Hibe {
    type PrivateKey;
    type MasterKey;
    type PublicKey;
    type Identity;

    fn setup<R: Rng>(&self, rng: R) -> Result<(Self::PublicKey, Self::MasterKey)>;

    fn generate_key<R: Rng>(
        &self,
        rng: R,
        public_key: &Self::PublicKey,
        master_key: &Self::MasterKey,
        identity: &[Self::Identity],
    ) -> Result<Self::PrivateKey>;

    fn derive_key<R: Rng>(
        &self,
        rng: R,
        public_key: &Self::PublicKey,
        parent_key: &Self::PrivateKey,
        parent_name: &[Self::Identity],
        child: &Self::Identity,
    ) -> Result<Self::PrivateKey>;
}

pub trait HibeCrypt: Hibe {
    type Message;
    type Ciphertext;

    fn encrypt<R: Rng>(
        &self,
        rng: R,
        public_key: &Self::PublicKey,
        identity: &[Self::Identity],
        message: &Self::Message,
    ) -> Result<Self::Ciphertext>;

    fn decrypt(
        &self,
        public_key: &Self::PublicKey,
        key: &Self::PrivateKey,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::Message>;
}

pub trait HibeKem: Hibe {
    type Key;
    type EncapsulatedKey;

    fn encapsulate<R: Rng>(
        &self,
        rng: R,
        public_key: &Self::PublicKey,
        identity: &[Self::Identity],
    ) -> Result<(Self::Key, Self::EncapsulatedKey)>;

    fn decapsulate(
        &self,
        public_key: &Self::PublicKey,
        key: &Self::PrivateKey,
        encapsulation: &Self::EncapsulatedKey,
    ) -> Result<Self::Key>;
}

