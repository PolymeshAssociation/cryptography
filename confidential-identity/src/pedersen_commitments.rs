//! The `pedersen_commitments` library contains helper API for producing
//! DID and Claim labels for Asset Granularity Unique Identity
//! project.
//!
//! The investor will use the `commit()` function to calculate their
//! DID labels and Claim labels, and make those public.
//!
//! The validators of the blockchain will use the `label_prime()` function
//! to calculate the investor's public key which they will use to verify
//! the investor's signature on his claims.
//!
//! In this setup the entire system is using the same set of
//! 3 Pedersen generators: G0, G1, and G2. To create thse generators:
//! ```
//! use confidential_identity::pedersen_commitments::PedersenGenerators;
//!
//! let pg = PedersenGenerators::default();
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
//! use confidential_identity::pedersen_commitments::PedersenGenerators;
//!
//! let pg = PedersenGenerators::default();
//! let values: [Scalar; 3] =
//!     [Scalar::from(111u64), Scalar::from(222u64), Scalar::from(333u64)];
//! let result = pg.commit(&values);
//! ```
//!
//! To calculate the label_prime:
//! ```
//! use curve25519_dalek::scalar::Scalar;
//! use curve25519_dalek::ristretto::RistrettoPoint;
//! use curve25519_dalek::ristretto::CompressedRistretto;
//! use confidential_identity::pedersen_commitments::PedersenGenerators;
//!
//! let pg = PedersenGenerators::default();
//! let id_bytes: [u8; 32] = [
//!     0xb5, 0xde, 0xb8, 0x5b, 0x87, 0x4a, 0x81, 0x6a,
//!     0x9f, 0x28, 0xd, 0xbc, 0x87, 0xef, 0x6a, 0xb8,
//!     0x6f, 0x54, 0xe4, 0xa1, 0xf, 0x7f, 0xcd, 0x7a,
//!     0x27, 0xe1, 0x2c, 0x9b, 0x42, 0xd7, 0x9b, 0x9 ];
//! let id: Scalar = Scalar::from_bits(id_bytes);
//!
//! let label_bytes: [u8; 32] = [
//!     0xec, 0x97, 0xad, 0x35, 0x2f, 0x9a, 0x22, 0x73,
//!     0x93, 0x23, 0x8c, 0x21, 0x87, 0x70, 0xa0, 0x6,
//!     0xa2, 0x7e, 0xcd, 0x4b, 0xa0, 0x89, 0x4a, 0x34,
//!     0x7e, 0x5, 0xc7, 0x7b, 0x12, 0x7, 0xa5, 0x3 ];
//! let label: RistrettoPoint =
//!     CompressedRistretto::from_slice(&label_bytes).decompress().unwrap();
//!
//! let label_prime = pg.label_prime(label, id);
//! ```

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_COMPRESSED, constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::RistrettoPoint, scalar::Scalar, traits::MultiscalarMul,
};
use sha3::Sha3_512;

use sp_std::prelude::*;

const PEDERSEN_COMMITMENT_LABEL: &[u8; 16] = b"PolymathIdentity";
pub const PEDERSEN_COMMITMENT_NUM_GENERATORS: usize = 3;

#[derive(Debug, Copy, Clone)]
pub struct PedersenGenerators {
    /// Bases for the Pedersen commitment.
    ///
    /// The last generator, G2, is set to the Ristretto's base point,
    /// which is also the base point for the SR25519. The first
    /// generator, G0, is the hash of G2 in points format, and the
    /// second generator, G1, is the hash of G0 converted to a
    /// Ristretto point.
    generators: [RistrettoPoint; PEDERSEN_COMMITMENT_NUM_GENERATORS],
}

impl Default for PedersenGenerators {
    /// Create the default set of Pedersen generators.
    /// This will always return the same set of generators, so it will be more
    /// efficient to precalculate and define them as `const static`s.
    fn default() -> Self {
        let mut generators: [RistrettoPoint; PEDERSEN_COMMITMENT_NUM_GENERATORS] =
            [RistrettoPoint::default(); PEDERSEN_COMMITMENT_NUM_GENERATORS];

        let mut ristretto_base_bytes = Vec::with_capacity(
            PEDERSEN_COMMITMENT_LABEL.len() + RISTRETTO_BASEPOINT_COMPRESSED.as_bytes().len(),
        );
        ristretto_base_bytes.extend_from_slice(&PEDERSEN_COMMITMENT_LABEL.to_vec());
        ristretto_base_bytes.extend_from_slice(RISTRETTO_BASEPOINT_COMPRESSED.as_bytes());

        generators
            .iter_mut()
            .take(PEDERSEN_COMMITMENT_NUM_GENERATORS - 1)
            .for_each(|generator| {
                *generator =
                    RistrettoPoint::hash_from_bytes::<Sha3_512>(ristretto_base_bytes.as_slice());
                ristretto_base_bytes = generator.compress().as_bytes().to_vec();
            });

        generators[PEDERSEN_COMMITMENT_NUM_GENERATORS - 1] = RISTRETTO_BASEPOINT_POINT;

        PedersenGenerators { generators }
    }
}

impl PedersenGenerators {
    /// Commit to a set of `PEDERSEN_COMMITMENT_NUM_GENERATORS` scalars.
    /// # Input
    /// * `values` are the scalars to commit to.
    ///
    /// # Output
    /// A Ristretto point.
    pub fn commit(&self, values: &[Scalar; PEDERSEN_COMMITMENT_NUM_GENERATORS]) -> RistrettoPoint {
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
    extern crate wasm_bindgen_test;
    use super::*;
    use curve25519_dalek::{
        constants::RISTRETTO_BASEPOINT_COMPRESSED, ristretto::CompressedRistretto,
        ristretto::RistrettoPoint, scalar::Scalar,
    };
    use wasm_bindgen_test::*;

    /// The snippet that was used to generate the test vectors:
    /// ```
    /// let pg = PedersenGenerators::default();
    /// println!("expected_g0: {:#x?}", pg.generators[0].compress().as_bytes());
    /// println!("expected_g1: {:#x?}", pg.generators[1].compress().as_bytes());
    /// println!("expected_g2: {:#x?}", pg.generators[2].compress().as_bytes());
    ///
    /// // Generate 3 random values to commit to.
    /// let mut rng = OsRng;
    /// let rand_values: [Scalar; 3] =
    ///    [Scalar::random(&mut rng), Scalar::random(&mut rng), Scalar::random(&mut rng)];
    /// println!("V0_BYTES: {:#x?}", rand_values[0].as_bytes());
    /// println!("V1_BYTES: {:#x?}", rand_values[1].as_bytes());
    /// println!("V2_BYTES: {:#x?}", rand_values[2].as_bytes());
    ///
    /// let result = pg.commit(&rand_values);
    /// println!("COMMIT_RESULT_BYTES: {:#x?}", result.compress().as_bytes());
    /// ```
    static V0_BYTES: [u8; 32] = [
        0xb5, 0xde, 0xb8, 0x5b, 0x87, 0x4a, 0x81, 0x6a, 0x9f, 0x28, 0xd, 0xbc, 0x87, 0xef, 0x6a,
        0xb8, 0x6f, 0x54, 0xe4, 0xa1, 0xf, 0x7f, 0xcd, 0x7a, 0x27, 0xe1, 0x2c, 0x9b, 0x42, 0xd7,
        0x9b, 0x9,
    ];

    static V1_BYTES: [u8; 32] = [
        0x7e, 0x5e, 0x6d, 0x42, 0xa0, 0xef, 0xc9, 0xcd, 0x11, 0xad, 0x6d, 0x3f, 0x74, 0x6, 0x97,
        0xf5, 0x6d, 0x5f, 0xb8, 0xad, 0x5f, 0xf4, 0xbb, 0x6f, 0xdf, 0x3f, 0xb4, 0xf2, 0x4a, 0x8e,
        0x57, 0xa,
    ];

    static V2_BYTES: [u8; 32] = [
        0xe7, 0xee, 0x1, 0x77, 0x67, 0xf2, 0x9e, 0x5a, 0xa7, 0x17, 0x98, 0xa7, 0xbc, 0x9b, 0xd4,
        0xc, 0xe, 0x4e, 0xd8, 0xeb, 0xf6, 0xa, 0xa3, 0x3d, 0x7a, 0xc6, 0x78, 0xda, 0x28, 0xd4,
        0x20, 0x3,
    ];

    static COMMIT_RESULT_BYTES: [u8; 32] = [
        0xec, 0x97, 0xad, 0x35, 0x2f, 0x9a, 0x22, 0x73, 0x93, 0x23, 0x8c, 0x21, 0x87, 0x70, 0xa0,
        0x6, 0xa2, 0x7e, 0xcd, 0x4b, 0xa0, 0x89, 0x4a, 0x34, 0x7e, 0x5, 0xc7, 0x7b, 0x12, 0x7,
        0xa5, 0x3,
    ];

    #[test]
    #[wasm_bindgen_test]
    fn default_generators() {
        let expected_g0 = [
            0x90, 0x6b, 0xff, 0x34, 0x42, 0x25, 0x5f, 0xd9, 0x2c, 0xf0, 0x2d, 0xad, 0x4c, 0x86,
            0xec, 0xff, 0x3e, 0x8b, 0xc4, 0x6, 0x9e, 0xe5, 0x49, 0xc5, 0xc3, 0x98, 0xf0, 0x9c,
            0x28, 0x8a, 0x4e, 0x5d,
        ];
        let expected_g1 = [
            0xbe, 0xda, 0x2, 0x0, 0x86, 0xbd, 0x74, 0x8f, 0xef, 0x9, 0x28, 0xf2, 0xa3, 0xca, 0x14,
            0x51, 0xc0, 0x9d, 0xde, 0x4d, 0x9a, 0xb5, 0x32, 0x45, 0x41, 0x98, 0xba, 0x83, 0x33,
            0xb7, 0x5a, 0x40,
        ];
        let expected_g2 = RISTRETTO_BASEPOINT_COMPRESSED.as_bytes();

        let pg = PedersenGenerators::default();

        assert_eq!(pg.generators[0].compress().as_bytes(), &expected_g0);
        assert_eq!(pg.generators[1].compress().as_bytes(), &expected_g1);
        assert_eq!(pg.generators[2].compress().as_bytes(), expected_g2);
    }

    #[test]
    #[wasm_bindgen_test]
    fn commit_fixed_values() {
        let values = [
            Scalar::from_bits(V0_BYTES),
            Scalar::from_bits(V1_BYTES),
            Scalar::from_bits(V2_BYTES),
        ];

        let pg = PedersenGenerators::default();
        let result = pg.commit(&values);

        let expected_result = CompressedRistretto::from_slice(&COMMIT_RESULT_BYTES)
            .decompress()
            .unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    #[wasm_bindgen_test]
    fn commit_zeros() {
        let pg = PedersenGenerators::default();
        let zeros = [Scalar::zero(); PEDERSEN_COMMITMENT_NUM_GENERATORS];
        let result = pg.commit(&zeros);

        assert_eq!(result, RistrettoPoint::default());
        assert_eq!(result.compress().as_bytes(), &[0; 32]);

        let result_prime = pg.label_prime(result, zeros[0]);
        assert_eq!(result_prime, RistrettoPoint::default());
        assert_eq!(result_prime.compress().as_bytes(), &[0; 32]);
    }

    #[test]
    #[wasm_bindgen_test]
    fn fixed_label_prime() {
        let expected_commit_result_prime = [
            0xdc, 0xc6, 0x18, 0x1f, 0x65, 0x4d, 0xdf, 0x28, 0x41, 0xb2, 0xd9, 0x57, 0x8d, 0xd0,
            0x47, 0xa1, 0xe7, 0xaa, 0xfc, 0x87, 0x96, 0x55, 0xf6, 0xec, 0xf7, 0xcd, 0xe0, 0x2f,
            0xf8, 0xde, 0xea, 0x27,
        ];

        let pg = PedersenGenerators::default();
        let values_0 = Scalar::from_bits(V0_BYTES);
        let commit_result = CompressedRistretto::from_slice(&COMMIT_RESULT_BYTES)
            .decompress()
            .unwrap();
        let commit_result_prime = pg.label_prime(commit_result, values_0);

        assert_eq!(
            commit_result_prime.compress().as_bytes(),
            &expected_commit_result_prime
        );
    }
}
