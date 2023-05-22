//! The `elgamal_encryption` library implements the
//! twisted-Elgamal encryption over the Ristretto 25519 curve.
//! Since Elgamal is a homomorphic encryption it also provides
//! addition and subtraction API over the cipher texts.

use crate::{
    asset_proofs::errors::{ErrorKind, Fallible},
    asset_proofs::Balance,
    codec_wrapper::{
        RistrettoPointDecoder, RistrettoPointEncoder, ScalarDecoder, ScalarEncoder,
        RISTRETTO_POINT_SIZE,
    },
};

use bulletproofs::PedersenGens;
use core::ops::{Add, AddAssign, Sub, SubAssign};
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
#[cfg(feature = "std")]
use rand::rngs::StdRng;
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use codec::{Decode, Encode, Error as CodecError, Input, Output};
use scale_info::{build::Fields, Path, Type, TypeInfo};
use sp_std::prelude::*;

/// Prover's representation of the commitment secret.
#[derive(Clone, PartialEq, Zeroize, Debug)]
#[zeroize(drop)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CommitmentWitness {
    /// Depending on how the witness was created this variable stores the
    /// balance value or the asset id in Scalar format.
    value: Scalar,

    /// A random blinding factor.
    blinding: Scalar,
}

impl CommitmentWitness {
    pub fn blinding(&self) -> Scalar {
        self.blinding
    }

    pub fn value(&self) -> Scalar {
        self.value
    }
}

impl CommitmentWitness {
    pub fn new(value: Scalar, blinding: Scalar) -> Self {
        CommitmentWitness { value, blinding }
    }
}

#[cfg(feature = "std")]
impl From<(Scalar, &mut StdRng)> for CommitmentWitness {
    fn from(v: (Scalar, &mut StdRng)) -> Self {
        CommitmentWitness {
            value: v.0,
            blinding: Scalar::random(v.1),
        }
    }
}

impl Encode for CommitmentWitness {
    #[inline]
    fn size_hint(&self) -> usize {
        ScalarEncoder(&self.value).size_hint() + ScalarEncoder(&self.blinding).size_hint()
    }

    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        ScalarEncoder(&self.value).encode_to(dest);
        ScalarEncoder(&self.blinding).encode_to(dest);
    }
}

impl Decode for CommitmentWitness {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let value = <ScalarDecoder>::decode(input)?.0;
        let blinding = <ScalarDecoder>::decode(input)?.0;

        Ok(CommitmentWitness { value, blinding })
    }
}

/// Prover's representation of the encrypted secret.
#[derive(PartialEq, Copy, Clone, Default, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CipherText {
    pub x: RistrettoPoint,
    pub y: RistrettoPoint,
}

impl Encode for CipherText {
    #[inline]
    fn size_hint(&self) -> usize {
        RistrettoPointEncoder(&self.x).size_hint() + RistrettoPointEncoder(&self.y).size_hint()
    }

    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        RistrettoPointEncoder(&self.x).encode_to(dest);
        RistrettoPointEncoder(&self.y).encode_to(dest);
    }
}

impl Decode for CipherText {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let x = <RistrettoPointDecoder>::decode(input)?.0;
        let y = <RistrettoPointDecoder>::decode(input)?.0;

        Ok(CipherText { x, y })
    }
}

impl TypeInfo for CipherText {
    type Identity = Self;
    fn type_info() -> Type {
        Type::builder()
            .path(Path::new("CipherText", module_path!()))
            .composite(
                Fields::named()
                    .field(|f| {
                        f.ty::<[u8; RISTRETTO_POINT_SIZE]>()
                            .name("x")
                            .type_name("CompressedRistretto")
                    })
                    .field(|f| {
                        f.ty::<[u8; RISTRETTO_POINT_SIZE]>()
                            .name("y")
                            .type_name("CompressedRistretto")
                    }),
            )
    }
}

// ------------------------------------------------------------------------
// Arithmetic operations on the ciphertext.
// ------------------------------------------------------------------------

impl<'a, 'b> Add<&'b CipherText> for &'a CipherText {
    type Output = CipherText;

    fn add(self, other: &'b CipherText) -> CipherText {
        CipherText {
            x: self.x + other.x,
            y: self.y + other.y,
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
            x: self.x - other.x,
            y: self.y - other.y,
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
#[derive(Clone, Zeroize, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[zeroize(drop)]
pub struct ElgamalSecretKey {
    pub secret: Scalar,
}

impl Encode for ElgamalSecretKey {
    #[inline]
    fn size_hint(&self) -> usize {
        ScalarEncoder(&self.secret).size_hint()
    }

    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        ScalarEncoder(&self.secret).encode_to(dest);
    }
}

impl Decode for ElgamalSecretKey {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let secret = <ScalarDecoder>::decode(input)?.0;

        Ok(ElgamalSecretKey { secret })
    }
}

/// Compressed ElgamalPublicKey.
#[derive(Copy, Clone, Default, Encode, Decode, TypeInfo, PartialEq, Eq, Debug)]
pub struct CompressedElgamalPublicKey([u8; 32]);

impl CompressedElgamalPublicKey {
    pub fn from_public_key(key: &ElgamalPublicKey) -> Self {
        Self(key.pub_key.compress().to_bytes())
    }

    pub fn into_public_key(&self) -> Option<ElgamalPublicKey> {
        let compressed = CompressedRistretto(self.0);
        compressed
            .decompress()
            .map(|pub_key| ElgamalPublicKey { pub_key })
    }
}

impl From<&ElgamalPublicKey> for CompressedElgamalPublicKey {
    fn from(other: &ElgamalPublicKey) -> Self {
        Self::from_public_key(other)
    }
}

impl From<ElgamalPublicKey> for CompressedElgamalPublicKey {
    fn from(other: ElgamalPublicKey) -> Self {
        Self::from_public_key(&other)
    }
}

/// The Elgamal Public Key is the secret key multiplied by the blinding generator (g).
#[derive(Copy, Clone, Default, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ElgamalPublicKey {
    pub pub_key: RistrettoPoint,
}

impl ElgamalPublicKey {
    fn encrypt_helper(&self, value: Scalar, blinding: Scalar) -> CipherText {
        let x = blinding * self.pub_key;
        let gens = PedersenGens::default();
        let y = gens.commit(value, blinding);
        CipherText { x, y }
    }

    pub fn encrypt(&self, witness: &CommitmentWitness) -> CipherText {
        self.encrypt_helper(witness.value, witness.blinding)
    }

    /// Generates a blinding factor, and encrypts the value.
    pub fn encrypt_value<R: RngCore + CryptoRng>(
        &self,
        value: Scalar,
        rng: &mut R,
    ) -> (CommitmentWitness, CipherText) {
        let blinding = Scalar::random(rng);
        (
            CommitmentWitness { value, blinding },
            self.encrypt_helper(value, blinding),
        )
    }
}

impl Encode for ElgamalPublicKey {
    #[inline]
    fn size_hint(&self) -> usize {
        RistrettoPointEncoder(&self.pub_key).size_hint()
    }

    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        RistrettoPointEncoder(&self.pub_key).encode_to(dest);
    }
}

impl Decode for ElgamalPublicKey {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let pub_key = <RistrettoPointDecoder>::decode(input)?.0;
        Ok(ElgamalPublicKey { pub_key })
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

    /// Decrypt a cipher text that is known to encrypt a Balance.
    pub fn decrypt(&self, cipher_text: &CipherText) -> Fallible<Balance> {
        let gens = PedersenGens::default();
        // value * h = Y - X / secret_key
        let value_h = cipher_text.y - self.secret.invert() * cipher_text.x;
        // Brute force all possible values to find the one that matches value * h.
        let mut result = Scalar::zero() * gens.B;
        for v in 0..Balance::max_value() {
            if result == value_h {
                return Ok(v);
            }
            result += gens.B;
        }

        Err(ErrorKind::CipherTextDecryptionError.into())
    }

    /// Decrypt a cipher text that is known to encrypt a Balance.
    #[cfg(feature = "discrete_log")]
    pub fn decrypt_discrete_log(&self, cipher_text: &CipherText) -> Fallible<Balance> {
        let gens = PedersenGens::default();
        // value * h = Y - X / secret_key
        let value_h = cipher_text.y - self.secret.invert() * cipher_text.x;
        let discrete_log = super::discrete_log::DiscreteLog::new(gens.B);
        if let Some(v) = discrete_log.decode(value_h) {
            return Ok(v as Balance);
        }

        Err(ErrorKind::CipherTextDecryptionError.into())
    }

    /// Decrypt a cipher text that is known to encrypt a Balance.
    pub fn decrypt_with_hint(
        &self,
        cipher_text: &CipherText,
        min: Balance,
        max: Balance,
    ) -> Option<Balance> {
        let gens = PedersenGens::default();
        // value * h = Y - X / secret_key
        let value_h = cipher_text.y - self.secret.invert() * cipher_text.x;
        // Brute force all possible values to find the one that matches value * h.
        let mut result = Scalar::from(min) * gens.B;
        for v in min..max {
            if result == value_h {
                return Some(v);
            }
            result += gens.B;
        }

        None
    }

    /// Decrypt a cipher text that is known to encrypt a Balance.
    #[cfg(feature = "rayon")]
    pub fn decrypt_parallel(&self, cipher_text: &CipherText) -> Fallible<Balance> {
        use rayon::prelude::*;
        use std::sync::atomic::{AtomicBool, Ordering};

        let gens = PedersenGens::default();
        // value * h = Y - X / secret_key
        let value_h = cipher_text.y - self.secret.invert() * cipher_text.x;

        const CHUNK_SIZE: Balance = 64 * 1024; // Needs to be a power of two.
        const CHUNK_COUNT: Balance = Balance::max_value() / CHUNK_SIZE;
        let mut tmp = Scalar::zero() * gens.B;
        // Search the first chunk.
        for v in 0..CHUNK_SIZE {
            if tmp == value_h {
                return Ok(v);
            }
            tmp += gens.B;
        }

        let found = AtomicBool::new(false);
        let chunk_b = tmp;
        let res = (1..CHUNK_COUNT)
            .into_iter()
            .map(|chunk_idx| {
                let chunk_start = tmp;
                tmp += chunk_b;
                (chunk_idx, chunk_start)
            })
            .par_bridge()
            .find_map_any(|(chunk_idx, mut tmp)| {
                let min = chunk_idx * CHUNK_SIZE;
                let max = min + CHUNK_SIZE;
                for v in min..max {
                    if found.load(Ordering::Relaxed) {
                        return None;
                    }
                    if tmp == value_h {
                        found.store(true, Ordering::Relaxed);
                        return Some(v);
                    }
                    tmp += gens.B;
                }
                None
            });
        if let Some(res) = res {
            return Ok(res);
        }

        Err(ErrorKind::CipherTextDecryptionError.into())
    }

    /// Verifies that a cipher text encrypts the given witness.
    /// This follows the same logic as decrypt(), except that it uses the `asset_id` as
    /// a hint as to what the message must be in order to avoid searching the entire
    /// message space.
    pub fn verify(&self, cipher_text: &CipherText, hinted_value: &Scalar) -> Fallible<()> {
        let gens = PedersenGens::default();
        // value * h = Y - X / secret_key.
        let value_h = cipher_text.y - self.secret.invert() * cipher_text.x;
        // Try the hinted asset id value and see if it matches value * h.
        let result = hinted_value * gens.B;
        if result == value_h {
            return Ok(());
        }

        Err(ErrorKind::CipherTextDecryptionError.into())
    }
}

pub fn encrypt_using_two_pub_keys(
    witness: &CommitmentWitness,
    pub_key1: ElgamalPublicKey,
    pub_key2: ElgamalPublicKey,
) -> (CipherText, CipherText) {
    let x1 = witness.blinding * pub_key1.pub_key;
    let x2 = witness.blinding * pub_key2.pub_key;
    let gens = PedersenGens::default();
    let y = gens.commit(witness.value, witness.blinding);
    let enc1 = CipherText { x: x1, y };
    let enc2 = CipherText { x: x2, y };

    (enc1, enc2)
}

// ------------------------------------------------------------------------
// CipherText Refreshment Method
// ------------------------------------------------------------------------

impl CipherText {
    pub fn refresh(&self, secret_key: &ElgamalSecretKey, blinding: Scalar) -> Fallible<CipherText> {
        let value: Scalar = secret_key.decrypt(self)?.into();
        let pub_key = secret_key.get_public_key();
        let new_witness = CommitmentWitness { value, blinding };
        let new_ciphertext = pub_key.encrypt(&new_witness);

        Ok(new_ciphertext)
    }

    pub fn refresh_with_hint(
        &self,
        secret_key: &ElgamalSecretKey,
        blinding: Scalar,
        hint: &Scalar,
    ) -> Fallible<CipherText> {
        secret_key.verify(self, hint)?;
        let pub_key = secret_key.get_public_key();
        let new_witness = CommitmentWitness {
            value: *hint,
            blinding,
        };
        let new_ciphertext = pub_key.encrypt(&new_witness);

        Ok(new_ciphertext)
    }
}

// ------------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    extern crate wasm_bindgen_test;
    use super::*;
    use crate::asset_proofs::{AssetId, Balance};
    use rand::{rngs::StdRng, SeedableRng};
    use wasm_bindgen_test::*;

    use sp_std::convert::TryFrom;

    const SEED_1: [u8; 32] = [42u8; 32];
    const SEED_2: [u8; 32] = [56u8; 32];

    #[test]
    #[wasm_bindgen_test]
    fn basic_enc_dec() {
        let mut rng = StdRng::from_seed(SEED_1);
        let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let elg_pub = elg_secret.get_public_key();

        // Test encrypting balance.
        let balance: Balance = 256;
        let blinding = Scalar::random(&mut rng);
        let balance_witness = CommitmentWitness {
            value: balance.into(),
            blinding,
        };
        // Test encrypt().
        let cipher = elg_pub.encrypt(&balance_witness);
        let balance1 = elg_secret.decrypt(&cipher).unwrap();
        assert_eq!(balance1, balance);

        // Test encrypt_value().
        let (_, cipher) = elg_pub.encrypt_value(balance_witness.value, &mut rng);
        let balance2 = elg_secret.decrypt(&cipher).unwrap();
        assert_eq!(balance2, balance);

        // Test encrypting asset id.
        let asset_id = AssetId::try_from(20u32).unwrap();
        let blinding = Scalar::random(&mut rng);
        let asset_id_witness = CommitmentWitness {
            value: asset_id.clone().into(),
            blinding,
        };
        // Test encrypt().
        let cipher = elg_pub.encrypt(&asset_id_witness);
        assert!(elg_secret.verify(&cipher, &asset_id.clone().into()).is_ok());

        // Test encrypt_value().
        let (_, cipher) = elg_pub.encrypt_value(asset_id_witness.value, &mut rng);
        assert!(elg_secret.verify(&cipher, &asset_id.into()).is_ok());
    }

    #[test]
    #[wasm_bindgen_test]
    fn decrypt_with_hint_test() {
        let mut rng = StdRng::from_seed(SEED_1);
        let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let elg_pub = elg_secret.get_public_key();

        // Test encrypting balance.
        let balance: Balance = 20_000;
        let blinding = Scalar::random(&mut rng);
        let balance_witness = CommitmentWitness {
            value: balance.into(),
            blinding,
        };
        // Test encrypt().
        let cipher = elg_pub.encrypt(&balance_witness);
        let balance1 = elg_secret
            .decrypt_with_hint(&cipher, 5_000, 25_000)
            .unwrap();
        assert_eq!(balance1, balance);
        // Wrong range.
        let balance1 = elg_secret.decrypt_with_hint(&cipher, 5_000, 15_000);
        assert!(balance1.is_none());

        // Test encrypt_value().
        let (_, cipher) = elg_pub.encrypt_value(balance_witness.value, &mut rng);
        let balance2 = elg_secret
            .decrypt_with_hint(&cipher, 5_000, 25_000)
            .unwrap();
        assert_eq!(balance2, balance);
        // Wrong range.
        let balance2 = elg_secret.decrypt_with_hint(&cipher, 5_000, 15_000);
        assert!(balance2.is_none());
    }

    #[test]
    #[wasm_bindgen_test]
    fn homomorphic_encryption() {
        let v1: Scalar = 623u32.into();
        let v2: Scalar = 456u32.into();
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

    #[test]
    #[wasm_bindgen_test]
    fn test_two_encryptions() {
        let mut rng = StdRng::from_seed([17u8; 32]);
        let value = 256;
        let blinding = Scalar::random(&mut rng);
        let w = CommitmentWitness {
            value: value.into(),
            blinding,
        };

        let scrt1 = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let pblc1 = scrt1.get_public_key();

        let scrt2 = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let pblc2 = scrt2.get_public_key();

        let (cipher1, cipher2) = encrypt_using_two_pub_keys(&w, pblc1, pblc2);
        let msg1 = scrt1.decrypt(&cipher1).unwrap();
        let msg2 = scrt2.decrypt(&cipher2).unwrap();
        assert_eq!(value, msg1);
        assert_eq!(value, msg2);
    }
}
