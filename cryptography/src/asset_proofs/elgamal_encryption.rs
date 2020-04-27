//! The `elgamal_encryption` library implements the
//! twisted-Elgamal encryption over the Ristretto 25519 curve.
//! Since Elgamal is a homomorphic encryption it also provides
//! addition and subtraction API over the cipher texts.

use crate::errors::{AssetProofError, Result};
use bulletproofs::PedersenGens;
use core::ops::{Add, Sub};
use core::ops::{AddAssign, SubAssign};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use failure::Error;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use zeroize::Zeroize;

use sp_std::prelude::*;

/// Prover's representation of the commitment secret.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct CommitmentWitness {
    /// The value to encrypt.
    ///
    /// Since Elgamal decryption involves searching the entire
    /// space of possible values, the decryption time doubles for
    /// for every additional bit of the value size. We have limited
    /// the size of value to 32 bits, but even that is very costly.
    /// To experiment with runtimes for different ranges use the
    /// benchmarking tool in this repo.
    ///
    /// Possible remedies are:
    /// #0 limit the range even further since confidential values
    ///     in the context of Polymesh could be limited.
    /// #1 use AVX2 instruction sets if available on the target
    ///    architectures. Our preliminary investigation using
    ///    `curve25519_dalek`'s AVX2 features doesn't show a
    ///    significant improvment.
    /// #2 Given the fact that encrypted Elgamal values are mostly used
    ///    for zero-knowledge proof generations, it is very likely that
    ///    we won't need to decrypt the encrypted values very often.
    ///    We can recommend that applications use a different faster
    ///    encryption mechanism to store the confidentional values on disk.
    value: u32,

    // A random blinding factor.
    pub blinding: Scalar,
}

impl CommitmentWitness {
    pub fn new(value: u32, blinding: Scalar) -> Result<CommitmentWitness> {
        // Since Elgamal decryption requires brute forcing over all possible values,
        // we limit the values to 32-bit integers.
        ensure!(
            value < u32::max_value(),
            AssetProofError::PlainTextRangeError
        );
        Ok(CommitmentWitness { value, blinding })
    }
}

impl TryFrom<u32> for CommitmentWitness {
    type Error = Error;

    fn try_from(v: u32) -> std::result::Result<Self, Self::Error> {
        CommitmentWitness::new(v, Scalar::random(&mut rand::thread_rng()))
    }
}

/// Zeroize the secret values before witness goes out of scope.
impl Zeroize for CommitmentWitness {
    fn zeroize(&mut self) {
        self.value = 0;
        self.blinding.zeroize();
    }
}

/// Prover's representation of the encrypted secret.
#[derive(Debug, PartialEq, Copy, Clone, Serialize, Deserialize)]
pub struct CipherText {
    pub x: RistrettoPoint,
    pub y: RistrettoPoint,
}

// ------------------------------------------------------------------------
// Arithmetic operations on the cipher text.
// ------------------------------------------------------------------------

impl<'a, 'b> Add<&'b CipherText> for &'a CipherText {
    type Output = CipherText;

    fn add(self, other: &'b CipherText) -> CipherText {
        CipherText {
            x: &self.x + &other.x,
            y: &self.y + &other.y,
        }
    }
}
define_add_variants!(LHS = CipherText, RHS = CipherText, Output = CipherText);

impl<'b> AddAssign<&'b CipherText> for CipherText {
    fn add_assign(&mut self, _rhs: &CipherText) {
        *self = (self as &CipherText) + _rhs;
    }
}
define_add_assign_variants!(LHS = CipherText, RHS = CipherText);

impl<'a, 'b> Sub<&'b CipherText> for &'a CipherText {
    type Output = CipherText;

    fn sub(self, other: &'b CipherText) -> CipherText {
        CipherText {
            x: &self.x - &other.x,
            y: &self.y - &other.y,
        }
    }
}
define_sub_variants!(LHS = CipherText, RHS = CipherText, Output = CipherText);

impl<'b> SubAssign<&'b CipherText> for CipherText {
    fn sub_assign(&mut self, _rhs: &CipherText) {
        *self = (self as &CipherText) - _rhs;
    }
}
define_sub_assign_variants!(LHS = CipherText, RHS = CipherText);

// ------------------------------------------------------------------------
// Elgamal Encryption.
// ------------------------------------------------------------------------

/// Elgamal key pair:
/// secret_key := scalar
/// public_key := secret_key * g
///
/// Encryption:
/// plaintext := (value, blinding_factor)
/// cipher_text := (X, Y)
/// X := blinding_factor * public_key
/// Y := blinding_factor * g + value * h
///
/// Decryption:
/// Given (secret_key, X, Y) find value such that:
/// value * h = Y - X / secret_key
///
/// where g and h are 2 orthogonal generators.

/// An Elgamal Secret Key is a random scalar.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElgamalSecretKey {
    secret: Scalar,
}

/// The Elgamal Public Key is the secret key multiplied by the blinding generator (g).
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct ElgamalPublicKey {
    pub pub_key: RistrettoPoint,
}

impl ElgamalPublicKey {
    pub fn encrypt(&self, witness: &CommitmentWitness) -> CipherText {
        let x = witness.blinding * self.pub_key;
        let gens = PedersenGens::default();
        let y = gens.commit(Scalar::from(witness.value), witness.blinding);
        CipherText { x, y }
    }

    pub fn encrypt_value(&self, value: u32) -> Result<CipherText> {
        Ok(self.encrypt(&CommitmentWitness::try_from(value)?))
    }
}

impl ElgamalSecretKey {
    pub fn new(secret: Scalar) -> Self {
        ElgamalSecretKey { secret }
    }

    pub fn get_public_key(&self) -> ElgamalPublicKey {
        let gens = PedersenGens::default();
        ElgamalPublicKey {
            pub_key: self.secret * gens.B_blinding,
        }
    }

    pub fn decrypt(&self, cipher_text: &CipherText) -> Result<u32> {
        let gens = PedersenGens::default();
        // value * h = Y - X / secret_key
        let value_h = cipher_text.y - self.secret.invert() * cipher_text.x;
        // Brute force all possible values to find the one that matches value * h.
        for v in 0..u32::max_value() {
            let m_scalar = Scalar::from(v);
            let result = m_scalar * gens.B;
            if result == value_h {
                return Ok(v);
            }
        }

        Err(AssetProofError::CipherTextDecryptionError.into())
    }
}

/// Zeroize the secret key before it goes out of scope.
impl Zeroize for ElgamalSecretKey {
    fn zeroize(&mut self) {
        self.secret.zeroize();
    }
}

// ------------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    extern crate wasm_bindgen_test;
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};
    use wasm_bindgen_test::*;

    const SEED_1: [u8; 32] = [42u8; 32];
    const SEED_2: [u8; 32] = [56u8; 32];

    #[test]
    #[wasm_bindgen_test]
    fn basic_enc_dec() {
        let mut rng = StdRng::from_seed(SEED_1);
        let v = 256u32;
        let w = CommitmentWitness::new(v, Scalar::random(&mut rng)).unwrap();

        let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let elg_pub = elg_secret.get_public_key();

        // Test encrypt().
        let mut cipher = elg_pub.encrypt(&w);

        let mut message = elg_secret.decrypt(&cipher).unwrap();
        assert_eq!(v, message);

        // Test encrypt_value().
        cipher = elg_pub.encrypt_value(v).unwrap();
        message = elg_secret.decrypt(&cipher).unwrap();
        assert_eq!(v, message);
    }

    #[test]
    #[wasm_bindgen_test]
    fn homomorphic_encryption() {
        let v1 = 623u32;
        let v2 = 456u32;
        let mut rng = StdRng::from_seed(SEED_2);
        let r1 = Scalar::random(&mut rng);
        let r2 = Scalar::random(&mut rng);

        let elg_secret_key = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let elg_pub = elg_secret_key.get_public_key();

        let cipher1 = elg_pub.encrypt(&CommitmentWitness {
            value: v1,
            blinding: r1,
        });
        let cipher2 = elg_pub.encrypt(&CommitmentWitness {
            value: v2,
            blinding: r2,
        });

        let mut cipher12 = elg_pub.encrypt(&CommitmentWitness {
            value: v1 + v2,
            blinding: r1 + r2,
        });
        assert_eq!(cipher1 + cipher2, cipher12);
        cipher12 -= cipher2;
        assert_eq!(cipher1, cipher12);

        cipher12 = elg_pub.encrypt(&CommitmentWitness {
            value: v1 - v2,
            blinding: r1 - r2,
        });
        assert_eq!(cipher1 - cipher2, cipher12);
        cipher12 += cipher2;
        assert_eq!(cipher1, cipher12);
    }
}
