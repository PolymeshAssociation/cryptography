use crate::Balance;
use bulletproofs::PedersenGens;
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use sp_std::prelude::*;

#[derive(Clone, PartialEq)]
#[cfg_attr(feature = "std", derive(Debug))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ElgamalWitness {
    /// Depending on how the witness was created this variable stores the
    /// balance value or the asset id in RistrettoPoint format.
    value: RistrettoPoint,

    // A random blinding factor.
    blinding: Scalar,
}

/// Prover's representation of the encrypted secret.
#[derive(PartialEq, Copy, Clone, Default)]
#[cfg_attr(feature = "std", derive(Debug))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ElgamalCipher {
    pub x: RistrettoPoint,
    pub y: RistrettoPoint,
}

fn balance_to_point(value: &Balance) -> RistrettoPoint {
    let mut value_array = [0u8; 64];
    value_array[0..4].copy_from_slice(&value.to_le_bytes());
    println!(
        "RistrettoPoint::from_uniform_bytes(&value_array): {:?}",
        RistrettoPoint::from_uniform_bytes(&value_array)
    );

    // We could only use compress()/decompress() if the byte array was a valid canonical encoding of a ristretto point.
    // From uniform bytes uses a Elligator map to convert byte arrays to a point on the ristretto curve.
    // Unfortunately the inverse of this map is not impelemented.
    // see https://ristretto.group/formulas/elligator.html for more details.
    RistrettoPoint::from_uniform_bytes(&value_array)
}

// ------------------------------------------------------------------------
// Untwisted Elgamal Encryption.
// ------------------------------------------------------------------------
/// Elgamal key pair:
/// secret_key := scalar
/// public_key := secret_key * B_blinding
///
/// Encryption:
/// plaintext := (value, blinding_factor)
/// cipher_text := (X, Y)
/// X := blinding_factor * B_blinding
/// Y := value + blinding_factor * public_key
///
/// Decryption:
/// Given (secret_key, X, Y) find value such that:
/// value = Y - secret_key * X
///
/// Question: now that we only need one generator, could we use `RISTRETTO_BASEPOINT_POINT`
/// instead of going through the bulletproof library to get the `B_blinding` generators.

/// An Elgamal Secret Key is a random scalar.
#[derive(Clone, Zeroize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "std", derive(Debug))]
#[zeroize(drop)]
pub struct UntwistedElgamalSecretKey {
    pub secret: Scalar,
}

/// The Elgamal Public Key is the secret key multiplied by the blinding generator (g).
#[derive(Copy, Clone, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct UntwistedElgamalPublicKey {
    pub pub_key: RistrettoPoint,
}

impl UntwistedElgamalPublicKey {
    fn encrypt_helper(&self, value: RistrettoPoint, blinding: Scalar) -> ElgamalCipher {
        let gens = PedersenGens::default();
        let x = blinding * gens.B_blinding;
        let y = value + blinding * self.pub_key;
        ElgamalCipher { x, y }
    }

    pub fn encrypt(&self, witness: &ElgamalWitness) -> ElgamalCipher {
        self.encrypt_helper(witness.value, witness.blinding)
    }

    /// Generates a blinding factor, and encrypts the value.
    pub fn encrypt_value<R: RngCore + CryptoRng>(
        &self,
        value: RistrettoPoint,
        rng: &mut R,
    ) -> (ElgamalWitness, ElgamalCipher) {
        let blinding = Scalar::random(rng);
        (
            ElgamalWitness { value, blinding },
            self.encrypt_helper(value, blinding),
        )
    }
}

impl UntwistedElgamalSecretKey {
    pub fn new(secret: Scalar) -> Self {
        UntwistedElgamalSecretKey { secret }
    }

    pub fn get_public_key(&self) -> UntwistedElgamalPublicKey {
        let gens = PedersenGens::default();
        UntwistedElgamalPublicKey {
            pub_key: self.secret * gens.B_blinding,
        }
    }

    /// Decrypt a cipher text that is known to encrypt a u32.
    pub fn decrypt(&self, cipher_text: &ElgamalCipher) -> u32 {
        // let gens = PedersenGens::default();
        // value = Y - secret_key * X
        let value = cipher_text.y - self.secret * cipher_text.x;
        println!("decrypted value: {:?}", value);
        let mut value_bytes = [0u8; 4];
        // value_bytes.copy_from_slice(&value.compress().to_bytes()[28..32]);
        value_bytes.copy_from_slice(&value.compress().to_bytes()[0..4]);
        u32::from_le_bytes(value_bytes)
    }
}

// ------------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    extern crate wasm_bindgen_test;
    use super::*;
    use crate::Balance;
    use rand::{rngs::StdRng, SeedableRng};
    use wasm_bindgen_test::*;

    const SEED_1: [u8; 32] = [42u8; 32];

    #[test]
    #[wasm_bindgen_test]
    fn basic_untwisted_enc_dec() {
        let mut rng = StdRng::from_seed(SEED_1);
        let elg_secret = UntwistedElgamalSecretKey::new(Scalar::random(&mut rng));
        let elg_pub = elg_secret.get_public_key();

        // Test encrypting balance.
        let balance: Balance = 1u32; //256u32;
        let blinding = Scalar::random(&mut rng);
        let balance_witness = ElgamalWitness {
            value: balance_to_point(&balance),
            blinding: blinding,
        };

        // Test encrypt().
        let cipher = elg_pub.encrypt(&balance_witness);
        let balance1 = elg_secret.decrypt(&cipher); //.unwrap();
        assert_eq!(balance1, balance);

        // Test encrypt_value().
        let (_, cipher) = elg_pub.encrypt_value(balance_witness.value, &mut rng);
        let balance2 = elg_secret.decrypt(&cipher); //.unwrap();
        assert_eq!(balance2, balance);
    }
}
