//! The `pedersen_commitments` library contains API for producing
//! DID and Claim labels for Asset Granularity Unique Identity
//! project.
//!
//! The investor will use the `commit()` function to calculate their
//! DID labels and Claim labels, and make those public.
//!
//! The validators of the blockchain will use the `label_prime()` function
//! to calculate the investor's public key which they will use to verify
//! the investor's signature on the claims.
//!
//! In this setup the entire system is using the same set of
//! 3 Pedersen generators: G0, G1, and G2. To create thse generators:
//! ```
//! use pedersen_commitments::*;
//!
//! let plg: PedersenLabelGenerators = PedersenLabelGenerators::new();
//! ```
//!
//! The pedersen commitments are calculated as:
//! commitment = commit(values_0, values_1, values_2) =
//!     values_0 * G_0 + values_1 * G_1 + values_2 * G2
//! The result is a Ristretto point.
//! To commit to a set 3 scalars:
//! ```
//! use curve25519_dalek::scalar::Scalar;
//! use curve25519_dalek::ristretto::RistrettoPoint;
//! use rand_core::OsRng;
//! use pedersen_commitments::*;
//!
//! let plg: PedersenLabelGenerators = PedersenLabelGenerators::new();
//! let mut rng = OsRng;
//! let rand_values: Vec<Scalar> = (0..PEDERSEN_COMMITMENT_NUM_GENERATORS)
//!     .map(|_| Scalar::random(&mut rng))
//!     .collect();
//! let result = plg.commit(&rand_values);
//! ```
//!
//! To calculate the label_prime:
//! ```
//! use curve25519_dalek::scalar::Scalar;
//! use curve25519_dalek::ristretto::RistrettoPoint;
//! use curve25519_dalek::ristretto::CompressedRistretto;
//! use pedersen_commitments::*;
//!
//! let plg: PedersenLabelGenerators = PedersenLabelGenerators::new();
//! // Generate 3 random values to commit to.
//! let id_bytes: [u8; 32] = [
//!     107, 60, 69, 84, 64, 107, 158, 230,
//!     145, 171, 237, 160, 43, 234, 92, 248,
//!     61, 60, 244, 233, 200, 54, 126, 199,
//!     133, 12, 151, 228, 54, 98, 164, 2
//! ];
//! let id: Scalar = Scalar::from_bits(id_bytes);
//!
//! let label_bytes: [u8; 32] = [
//!     172, 7, 166, 185, 187, 24, 79, 231,
//!     26, 142, 107, 99, 21, 94, 42, 106,
//!     178, 179, 40, 166, 90, 108, 103, 22,
//!     141, 180, 1, 29, 251, 137, 70, 31
//! ];
//! let label: RistrettoPoint =
//!     CompressedRistretto::from_slice(&label_bytes).decompress().unwrap();
//!
//! let label_prime = plg.label_prime(label, id);
//! ```
//!

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED;
use curve25519_dalek::traits::MultiscalarMul;
use curve25519_dalek::scalar::Scalar;
use sha3::Sha3_512;

pub const PEDERSEN_COMMITMENT_LABEL: [u8; 16] = *b"PolymathIdentity";
pub const PEDERSEN_COMMITMENT_NUM_GENERATORS: usize = 3;

pub struct PedersenLabelGenerators {
    /// Bases for the Pedersen commitment.
    ///
    /// The last generator, G2, is set to the Ristretto's base point,
    /// which is also the base point for the SR25519. The first
    /// generator, G0, is the hash of G2 in points format, and the
    /// second generator, G1, is the hash of G0 converted to a
    /// Ristretto point.
    pub generators: [RistrettoPoint; PEDERSEN_COMMITMENT_NUM_GENERATORS],
}

impl PedersenLabelGenerators {
    /// Create a set Pedersen generators.
    pub fn new() -> Self {
        let mut generators: [RistrettoPoint; PEDERSEN_COMMITMENT_NUM_GENERATORS] =
            [RistrettoPoint::default(); PEDERSEN_COMMITMENT_NUM_GENERATORS];

        let mut ristretto_base_bytes = Vec::with_capacity(
            PEDERSEN_COMMITMENT_LABEL.len() +
            RISTRETTO_BASEPOINT_COMPRESSED.as_bytes().len());
        ristretto_base_bytes.extend_from_slice(&PEDERSEN_COMMITMENT_LABEL.to_vec());
        ristretto_base_bytes.extend_from_slice(RISTRETTO_BASEPOINT_COMPRESSED.as_bytes());

        for i in 0..(PEDERSEN_COMMITMENT_NUM_GENERATORS - 1) {
            generators[i] = RistrettoPoint::hash_from_bytes::<Sha3_512>(
                ristretto_base_bytes.as_slice(),
            );
            ristretto_base_bytes = generators[i].compress().as_bytes().to_vec();
        }
        generators[PEDERSEN_COMMITMENT_NUM_GENERATORS - 1] = RISTRETTO_BASEPOINT_POINT;

        PedersenLabelGenerators {
            generators: generators,
        }
    }

    /// Commit to a set of `PEDERSEN_COMMITMENT_NUM_GENERATORS` scalars.
    /// # Input
    /// * `values` are the scalars to commit to.
    ///
    /// # Output
    /// A Ristretto point.
    pub fn commit(&self, values: &[Scalar]) -> RistrettoPoint {
        assert_eq!(values.len(), PEDERSEN_COMMITMENT_NUM_GENERATORS);
        RistrettoPoint::multiscalar_mul(values, &self.generators)
    }

    /// Calculate the label prime:
    /// result = label - id * G0
    ///
    /// # Inputs
    /// * `label` the result of a label commitment.
    /// * `id` an investor ID.
    ///
    /// # Output
    /// A Ristretto point.
    pub fn label_prime(&self, label: RistrettoPoint, id: Scalar) -> RistrettoPoint {
        label - RistrettoPoint::multiscalar_mul(&[id], &[self.generators[0]])
    }
}

// ------------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use rand_core::OsRng;
    use super::*;

    #[test]
    fn commit_randoms() {
        let plg: PedersenLabelGenerators = PedersenLabelGenerators::new();
        // Generate 3 random values to commit to.
        let mut rng = OsRng;
        let rand_values: Vec<Scalar> = (0..PEDERSEN_COMMITMENT_NUM_GENERATORS)
            .map(|_| Scalar::random(&mut rng))
            .collect();
        let result = plg.commit(&rand_values);
        println!("g0: {:?}", plg.generators[0].compress().as_bytes());
        println!("g1: {:?}", plg.generators[1].compress().as_bytes());
        println!("g2: {:?}", plg.generators[2].compress().as_bytes());
        println!("result: {:?}", result.compress().as_bytes());
    }

    #[test]
    fn commit_zeros() {
        let plg: PedersenLabelGenerators = PedersenLabelGenerators::new();
        let zeros: [Scalar; PEDERSEN_COMMITMENT_NUM_GENERATORS] = [Scalar::default(); PEDERSEN_COMMITMENT_NUM_GENERATORS];
        let result = plg.commit(&zeros);

        assert_eq!(result, RistrettoPoint::default());
        assert_eq!(result.compress().as_bytes(), &[0; 32]);
    }

    #[test]
    fn random_labels() {
        let plg: PedersenLabelGenerators = PedersenLabelGenerators::new();
        // Generate 3 random values to commit to.
        let mut rng = OsRng;
        let rand_values: Vec<Scalar> = (0..PEDERSEN_COMMITMENT_NUM_GENERATORS)
            .map(|_| Scalar::random(&mut rng))
            .collect();
        let result = plg.commit(&rand_values);

        plg.label_prime(result, rand_values[0]);
    }
}
