//! The proofs library implements proof of different properties
//! of the plain text, given the cipher text without revealing the
//! plain text. For example proving that the value that was encrypted
//! is within a range.

use crate::errors::{ErrorKind, Fallible};
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use merlin::Transcript;
use serde::{Deserialize, Serialize};

const RANGE_PROOF_LABEL: &[u8] = b"PolymathRangeProof";

// ------------------------------------------------------------------------
// Range Proof
// ------------------------------------------------------------------------

#[derive(Serialize, Deserialize, PartialEq, Copy, Clone, Debug)]
pub struct RangeProofInitialMessage(pub CompressedRistretto);

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RangeProofFinalResponse(RangeProof);

/// Generate a range proof for a commitment to a secret value.
/// Range proof commitments are equevalant to the second term (Y)
/// of the Elgamal encryption.
pub fn prove_within_range(
    secret_value: u64,
    rand_blind: Scalar,
    range: usize,
) -> Fallible<(RangeProofInitialMessage, RangeProofFinalResponse, usize)> {
    // Generators for Pedersen commitments.
    let pc_gens = PedersenGens::default();

    // Generators for Bulletproofs, valid for proofs up to bitsize 64
    // and aggregation size up to 1.
    // Note that we are not supporting aggregating more than one value
    // from a single party into an aggretated proof yet.
    let bp_gens = BulletproofGens::new(64, 1);

    // Transcripts eliminate the need for a dealer by employing
    // the Fiat-Shamir huristic.
    let mut prover_transcript = Transcript::new(RANGE_PROOF_LABEL);

    let (proof, commitment) = RangeProof::prove_single(
        &bp_gens,
        &pc_gens,
        &mut prover_transcript,
        secret_value,
        &rand_blind,
        range,
    )
    .map_err(|source| ErrorKind::ProvingError { source })?;

    Ok((
        RangeProofInitialMessage(commitment),
        RangeProofFinalResponse(proof),
        range,
    ))
}

/// Verify that a range proof is valid given a commitment to a secret value.
pub fn verify_within_range(
    init: RangeProofInitialMessage,
    response: RangeProofFinalResponse,
    range: usize,
) -> Fallible<()> {
    // Generators for Pedersen commitments.
    let pc_gens = PedersenGens::default();

    // Generators for Bulletproofs, valid for proofs up to bitsize 64
    // and aggregation size up to 1.
    let bp_gens = BulletproofGens::new(64, 1);

    // Transcripts eliminate the need for a dealer by employing
    // the Fiat-Shamir huristic.
    let mut verifier_transcript = Transcript::new(RANGE_PROOF_LABEL);

    response
        .0
        .verify_single(&bp_gens, &pc_gens, &mut verifier_transcript, &init.0, range)
        .map_err(|_| ErrorKind::VerificationError.into())
}

// ------------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    extern crate wasm_bindgen_test;
    use super::*;
    use crate::asset_proofs::*;
    use bincode::{deserialize, serialize};
    use rand::{rngs::StdRng, SeedableRng};
    use wasm_bindgen_test::*;

    const SEED_1: [u8; 32] = [42u8; 32];

    #[test]
    #[wasm_bindgen_test]
    fn basic_range_proof() {
        let mut rng = StdRng::from_seed(SEED_1);
        let secret_value = 42u32;

        let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let elg_pub = elg_secret.get_public_key();
        let (witness, cipher) = elg_pub.encrypt_value(secret_value.into(), &mut rng);

        // Positive test: secret value within range [0, 2^32)
        let (initial_message, final_response, range) =
            prove_within_range(secret_value as u64, witness.blinding().clone(), 32)
                .expect("This shouldn't happen.");
        assert_eq!(range, 32);
        assert!(verify_within_range(initial_message, final_response, 32).is_ok());

        // Make sure the second part of the elgamal encryption is the same as the commited value in the range proof.
        assert_eq!(initial_message.0, cipher.y.compress());

        // Negative test: secret value outside the allowed range
        let large_secret_value: u64 = u64::from(u32::max_value()) + 3;
        let (bad_proof, bad_commitment, _) =
            prove_within_range(large_secret_value, witness.blinding().clone(), 32).unwrap();
        assert!(!verify_within_range(bad_proof, bad_commitment, 32).is_ok());
    }

    #[test]
    #[wasm_bindgen_test]
    fn serialize_deserialize_range_proof() {
        let mut rng = StdRng::from_seed(SEED_1);
        let secret_value = 42u32;
        let rand_blind = Scalar::random(&mut rng);

        let (initial_message, final_response, range) =
            prove_within_range(secret_value as u64, rand_blind, 32)
                .unwrap();
        assert_eq!(range, 32);

        let initial_message_bytes: Vec<u8> = serialize(&initial_message).unwrap();
        let final_response_bytes: Vec<u8> = serialize(&final_response).unwrap();
        let recovered_initial_message: RangeProofInitialMessage =
            deserialize(&initial_message_bytes).unwrap();
        let recovered_final_response: RangeProofFinalResponse =
            deserialize(&final_response_bytes).unwrap();
        assert_eq!(recovered_initial_message, initial_message);
        assert_eq!(
            final_response_bytes,
            serialize(&recovered_final_response).unwrap()
        );
    }
}
