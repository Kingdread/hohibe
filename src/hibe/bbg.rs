use std::iter;

use super::{Hibe, HibeCrypt, HibeKem};
use crate::error::{Error, Result};

use bls12_381_plus::{
    ff::Field, group::Group, pairing, G1Affine, G2Affine, G2Projective, Gt, Scalar,
};
use rand::Rng;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BonehBoyenGoh {
    max_depth: usize,
}

impl BonehBoyenGoh {
    pub fn new(max_depth: usize) -> Self {
        Self { max_depth }
    }

    pub fn max_depth(&self) -> usize {
        self.max_depth
    }
}

impl Hibe for BonehBoyenGoh {
    type PrivateKey = (G2Affine, G1Affine, Vec<G2Affine>);
    type MasterKey = G2Affine;
    type PublicKey = (G1Affine, G1Affine, G2Affine, G2Affine, Vec<G2Affine>);
    type Identity = Scalar;

    fn setup<R: Rng>(&self, mut rng: R) -> Result<(Self::PublicKey, Self::MasterKey)> {
        let g = G1Affine::generator();
        let alpha = Scalar::random(&mut rng);
        let g1 = g * alpha;
        let g2 = G2Projective::random(&mut rng);
        let g3 = G2Projective::random(&mut rng);
        let hs = (0..self.max_depth())
            .map(|_| G2Projective::random(&mut rng))
            .map(Into::into)
            .collect();
        Ok((
            (g, g1.into(), g2.into(), g3.into(), hs),
            (g2 * alpha).into(),
        ))
    }

    fn generate_key<R: Rng>(
        &self,
        rng: R,
        public_key: &Self::PublicKey,
        master_key: &Self::MasterKey,
        identity: &[Self::Identity],
    ) -> Result<Self::PrivateKey> {
        if identity.len() > self.max_depth() {
            return Err(Error::IdentityTooLong);
        }

        let r = Scalar::random(rng);
        Ok((
            (master_key
                + (public_key
                    .4
                    .iter()
                    .zip(identity)
                    .map(|(h, i)| h * i)
                    .sum::<G2Projective>()
                    + public_key.3)
                    * r)
                .into(),
            (public_key.0 * r).into(),
            public_key.4[identity.len()..]
                .iter()
                .map(|h| (h * r).into())
                .collect(),
        ))
    }

    fn derive_key<R: Rng>(
        &self,
        rng: R,
        public_key: &Self::PublicKey,
        parent_key: &Self::PrivateKey,
        parent_name: &[Self::Identity],
        child: &Self::Identity,
    ) -> Result<Self::PrivateKey> {
        if parent_name.len() > self.max_depth() - 1 {
            return Err(Error::IdentityTooLong);
        }

        let t = Scalar::random(rng);
        Ok((
            (parent_key.0
                + parent_key.2[0] * child
                + (public_key
                    .4
                    .iter()
                    .zip(parent_name.iter().chain(iter::once(child)))
                    .map(|(h, i)| h * i)
                    .sum::<G2Projective>()
                    + public_key.3)
                    * t)
                .into(),
            (parent_key.1 + public_key.0 * t).into(),
            parent_key.2[1..]
                .iter()
                .zip(public_key.4[parent_name.len() + 1..].iter())
                .map(|(b, h)| b + h * t)
                .map(Into::into)
                .collect(),
        ))
    }
}

impl HibeCrypt for BonehBoyenGoh {
    type Message = Gt;

    type Ciphertext = (Gt, G1Affine, G2Affine);

    fn encrypt<R: Rng>(
        &self,
        rng: R,
        public_key: &Self::PublicKey,
        identity: &[Self::Identity],
        message: &Self::Message,
    ) -> Result<Self::Ciphertext> {
        if identity.len() > self.max_depth() {
            return Err(Error::IdentityTooLong);
        }

        let s = Scalar::random(rng);
        Ok((
            pairing(&public_key.1, &public_key.2) * s + message,
            (public_key.0 * s).into(),
            ((public_key
                .4
                .iter()
                .zip(identity.iter())
                .map(|(h, i)| h * i)
                .sum::<G2Projective>()
                + public_key.3)
                * s)
                .into(),
        ))
    }

    fn decrypt(
        &self,
        _: &Self::PublicKey,
        key: &Self::PrivateKey,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::Message> {
        let (a, b, c) = ciphertext;
        Ok(a + pairing(&key.1, c) - pairing(b, &key.0))
    }
}

impl HibeKem for BonehBoyenGoh {
    type Key = Gt;

    type EncapsulatedKey = (G1Affine, G2Affine);

    fn encapsulate<R: Rng>(
        &self,
        rng: R,
        public_key: &Self::PublicKey,
        identity: &[Self::Identity],
    ) -> Result<(Self::Key, Self::EncapsulatedKey)> {
        if identity.len() > self.max_depth() {
            return Err(Error::IdentityTooLong);
        }

        let s = Scalar::random(rng);
        Ok((
            pairing(&public_key.1, &public_key.2) * s,
            (
                (public_key.0 * s).into(),
                ((public_key
                    .4
                    .iter()
                    .zip(identity.iter())
                    .map(|(h, i)| h * i)
                    .sum::<G2Projective>()
                    + public_key.3)
                    * s)
                    .into(),
            ),
        ))
    }

    fn decapsulate(
        &self,
        _: &Self::PublicKey,
        key: &Self::PrivateKey,
        encapsulation: &Self::EncapsulatedKey,
    ) -> Result<Self::Key> {
        let (b, c) = encapsulation;
        Ok(-pairing(&key.1, c) + pairing(b, &key.0))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn encrypt_decrypt_empty_identity() {
        let mut rng = rand::thread_rng();
        let bbg = BonehBoyenGoh::new(5);
        let (public_key, master_key) = bbg.setup(&mut rng).unwrap();
        let identity = &[];
        let secret_key = bbg
            .generate_key(&mut rng, &public_key, &master_key, identity.as_slice())
            .unwrap();
        let message = Gt::generator() * Scalar::from(4u32);
        let ciphertext = bbg
            .encrypt(&mut rng, &public_key, identity.as_slice(), &message)
            .unwrap();
        let decryption = bbg.decrypt(&public_key, &secret_key, &ciphertext).unwrap();
        assert_eq!(message, decryption);
    }

    #[test]
    fn encrypt_decrypt_keygen() {
        let mut rng = rand::thread_rng();
        let bbg = BonehBoyenGoh::new(5);
        let (public_key, master_key) = bbg.setup(&mut rng).unwrap();
        let identity = &[Scalar::from(1u32), Scalar::from(2u32), Scalar::from(3u32)];
        let secret_key = bbg
            .generate_key(&mut rng, &public_key, &master_key, identity.as_slice())
            .unwrap();
        let message = Gt::generator() * Scalar::from(4u32);
        let ciphertext = bbg
            .encrypt(&mut rng, &public_key, identity.as_slice(), &message)
            .unwrap();
        let decryption = bbg.decrypt(&public_key, &secret_key, &ciphertext).unwrap();
        assert_eq!(message, decryption);
    }

    #[test]
    fn encrypt_decrypt_max_length_identity() {
        let mut rng = rand::thread_rng();
        let bbg = BonehBoyenGoh::new(5);
        let (public_key, master_key) = bbg.setup(&mut rng).unwrap();
        let identity = &[
            Scalar::from(1u32),
            Scalar::from(2u32),
            Scalar::from(3u32),
            Scalar::from(4u32),
            Scalar::from(5u32),
        ];
        let secret_key = bbg
            .generate_key(&mut rng, &public_key, &master_key, identity.as_slice())
            .unwrap();
        let message = Gt::generator() * Scalar::from(4u32);
        let ciphertext = bbg
            .encrypt(&mut rng, &public_key, identity.as_slice(), &message)
            .unwrap();
        let decryption = bbg.decrypt(&public_key, &secret_key, &ciphertext).unwrap();
        assert_eq!(message, decryption);
    }

    #[test]
    fn encrypt_decrypt_derived() {
        let mut rng = rand::thread_rng();
        let bbg = BonehBoyenGoh::new(5);
        let (public_key, master_key) = bbg.setup(&mut rng).unwrap();
        let identity = &[Scalar::from(1u32), Scalar::from(2u32), Scalar::from(3u32)];
        let secret_key_0 = bbg
            .generate_key(&mut rng, &public_key, &master_key, &[])
            .unwrap();
        let secret_key_1 = bbg
            .derive_key(
                &mut rng,
                &public_key,
                &secret_key_0,
                &identity[..0],
                &identity[0],
            )
            .unwrap();
        let secret_key_2 = bbg
            .derive_key(
                &mut rng,
                &public_key,
                &secret_key_1,
                &identity[..1],
                &identity[1],
            )
            .unwrap();
        let secret_key_3 = bbg
            .derive_key(
                &mut rng,
                &public_key,
                &secret_key_2,
                &identity[..2],
                &identity[2],
            )
            .unwrap();
        let message = Gt::generator() * Scalar::from(4u32);
        let ciphertext = bbg
            .encrypt(&mut rng, &public_key, identity.as_slice(), &message)
            .unwrap();
        let decryption = bbg
            .decrypt(&public_key, &secret_key_3, &ciphertext)
            .unwrap();
        assert_eq!(message, decryption);
    }

    #[test]
    fn encrypt_decrypt_wrong_id() {
        let mut rng = rand::thread_rng();
        let bbg = BonehBoyenGoh::new(5);
        let (public_key, master_key) = bbg.setup(&mut rng).unwrap();
        let identity = &[Scalar::from(1u32), Scalar::from(2u32), Scalar::from(3u32)];
        let secret_key = bbg
            .generate_key(&mut rng, &public_key, &master_key, identity.as_slice())
            .unwrap();
        let message = Gt::generator() * Scalar::from(4u32);
        let ciphertext = bbg
            .encrypt(&mut rng, &public_key, &identity[..1], &message)
            .unwrap();
        let decryption = bbg.decrypt(&public_key, &secret_key, &ciphertext).unwrap();
        assert_ne!(message, decryption);
    }

    #[test]
    fn derive_max_length() {
        let mut rng = rand::thread_rng();
        let bbg = BonehBoyenGoh::new(5);
        let (public_key, master_key) = bbg.setup(&mut rng).unwrap();
        let identity = &[Scalar::from(1u32), Scalar::from(2u32), Scalar::from(3u32), Scalar::from(4u32), Scalar::from(5u32)];
        let secret_key_0 = bbg
            .generate_key(&mut rng, &public_key, &master_key, &[])
            .unwrap();
        let secret_key_1 = bbg
            .derive_key(
                &mut rng,
                &public_key,
                &secret_key_0,
                &identity[..0],
                &identity[0],
            )
            .unwrap();
        let secret_key_2 = bbg
            .derive_key(
                &mut rng,
                &public_key,
                &secret_key_1,
                &identity[..1],
                &identity[1],
            )
            .unwrap();
        let secret_key_3 = bbg
            .derive_key(
                &mut rng,
                &public_key,
                &secret_key_2,
                &identity[..2],
                &identity[2],
            )
            .unwrap();
        let secret_key_4 = bbg
            .derive_key(
                &mut rng,
                &public_key,
                &secret_key_3,
                &identity[..3],
                &identity[3],
            )
            .unwrap();
        let secret_key_5 = bbg
            .derive_key(
                &mut rng,
                &public_key,
                &secret_key_4,
                &identity[..4],
                &identity[4],
            )
            .unwrap();
        let message = Gt::generator() * Scalar::from(4u32);
        let ciphertext = bbg
            .encrypt(&mut rng, &public_key, identity.as_slice(), &message)
            .unwrap();
        let decryption = bbg
            .decrypt(&public_key, &secret_key_5, &ciphertext)
            .unwrap();
        assert_eq!(message, decryption);
    }

    #[test]
    fn encapsulate_decapsulate_keygen() {
        let mut rng = rand::thread_rng();
        let bbg = BonehBoyenGoh::new(5);
        let (public_key, master_key) = bbg.setup(&mut rng).unwrap();
        let identity = &[Scalar::from(1u32), Scalar::from(2u32), Scalar::from(3u32)];
        let secret_key = bbg
            .generate_key(&mut rng, &public_key, &master_key, identity.as_slice())
            .unwrap();
        let (generated_key, encapsulated_key) = bbg
            .encapsulate(&mut rng, &public_key, identity.as_slice())
            .unwrap();
        let decapsulated_key = bbg
            .decapsulate(&public_key, &secret_key, &encapsulated_key)
            .unwrap();
        assert_eq!(generated_key, decapsulated_key);
    }
}
