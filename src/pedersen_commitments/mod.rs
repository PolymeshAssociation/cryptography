//! The library to generate Pedersen Commitements, which are
//! used to produce Labels for investor DIDs and claims.
//!
//! In this scenario the entire system is using the same set of
//! 3 Pedersen generators.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED;
use curve25519_dalek::traits::MultiscalarMul;
use curve25519_dalek::scalar::Scalar;
use sha3::Sha3_512;

pub const PEDERSEN_COMMITMENT_LABEL: [u8; 16] = *b"PolymathIdentity";
pub const PEDERSEN_COMMITMENT_NUM_GENERATORS : usize = 3;

pub struct PedersenLabelGenerators {
    /// Bases for the Pedersen commitment.
    ///
    /// The last generator, G2, is set to the Ristretto's base point,
    /// which is also the base point for the SR25519. The first
    /// generator, G1, is the hash of G2 in points format, and the
    /// second generator, G1, is the hash of G1 converted to a
    /// Ristretto point.
    pub generators : [RistrettoPoint; PEDERSEN_COMMITMENT_NUM_GENERATORS],
}

impl PedersenLabelGenerators {
    fn new() -> Self {
        // Generate the Pedersen generators.
        // [PA] todo: This must be refactored to work with any PEDERSEN_COMMITMENT_NUM_GENERATORS value.
        let ristretto_base_bytes : &[u8] = &[PEDERSEN_COMMITMENT_LABEL.to_vec(),
                                             RISTRETTO_BASEPOINT_COMPRESSED.as_bytes().to_vec()]
                                             .concat();
        let g0 = RistrettoPoint::hash_from_bytes::<Sha3_512>(
            ristretto_base_bytes,
        );

        let g1 = RistrettoPoint::hash_from_bytes::<Sha3_512>(
            g0.compress().as_bytes(),
        );

        PedersenLabelGenerators {
            generators: [g0, g1, RISTRETTO_BASEPOINT_POINT],
        }
    }

    pub fn commit(&self, values: &[Scalar]) -> RistrettoPoint {
        assert_eq!(values.len(), PEDERSEN_COMMITMENT_NUM_GENERATORS);
        RistrettoPoint::multiscalar_mul(values, &self.generators)
    }
}

// ------------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use curve25519_dalek::scalar::Scalar;
    use rand_core::OsRng;
    use super::*;

    #[test]
    fn commit_randoms() {
        let plg : PedersenLabelGenerators = PedersenLabelGenerators::new();
        // Generate 3 random values to commit to.
        let mut rng = OsRng;
        let rand_values : Vec<Scalar> = (0..PEDERSEN_COMMITMENT_NUM_GENERATORS)
                                        .map(|_| Scalar::random(&mut rng))
                                        .collect();
        let result = plg.commit(&rand_values);
        // [PA] todo: do something with the result.
    }
}
