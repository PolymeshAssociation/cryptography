//! The proofs library implements proof of different properties
//! of the plain text, given the cipher text without revealing the
//! plain text. For example proving that the value that was encrypted
//! is within a range.

use crate::asset_proofs::{AssetProofError, CipherText, CommitmentWitness, ElgamalPublicKey};
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};

const RANGE_PROOF_LABEL: &[u8] = b"PolymathRangeProof";

// ------------------------------------------------------------------------
// Range Proof
// ------------------------------------------------------------------------

/// Generate a range proof for a commitment to a secret value.
/// Range proof commitments are equevalant to the second term (Y)
/// of the Elgamal encryption.
pub fn prove_within_range(
    secret_value: u64,
    rand_blind: Scalar,
    range: usize,
) -> Result<(RangeProof, CompressedRistretto), AssetProofError> {
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

    RangeProof::prove_single(
        &bp_gens,
        &pc_gens,
        &mut prover_transcript,
        secret_value,
        &rand_blind,
        range,
    )
    .map_err(|e| AssetProofError::ProvingError(e))
}

/// Verify that a range proof is valid given a commitment to a secret value.
pub fn verify_within_range(
    proof: RangeProof,
    commitment: CompressedRistretto,
    range: usize,
) -> bool {
    // Generators for Pedersen commitments.
    let pc_gens = PedersenGens::default();

    // Generators for Bulletproofs, valid for proofs up to bitsize 64
    // and aggregation size up to 1.
    let bp_gens = BulletproofGens::new(64, 1);

    // Transcripts eliminate the need for a dealer by employing
    // the Fiat-Shamir huristic.
    let mut verifier_transcript = Transcript::new(RANGE_PROOF_LABEL);

    proof
        .verify_single(
            &bp_gens,
            &pc_gens,
            &mut verifier_transcript,
            &commitment,
            range,
        )
        .is_ok()
}

// ------------------------------------------------------------------------
// Proof of Correct Encryption of the Given Value
// ------------------------------------------------------------------------

pub trait AssetProofProver {
    type Commitment;
    type Challenge;
    type ChallengeResponse;

    fn prover_generate_commitment<T: RngCore + CryptoRng>(
        &mut self,
        pc_gens: &PedersenGens,
        rng: &mut T,
    ) -> Self::Commitment;
    fn prover_apply_challenge(&self, c: Self::Challenge) -> Self::ChallengeResponse;
}

trait AssetProofVerifier {
    type Commitment;
    type Challenge;
    type ChallengeResponse;

    fn verifier_generate_challenge<T: RngCore + CryptoRng>(
        &mut self,
        c: Self::Commitment,
        rng: &mut T,
    ) -> Self::Challenge;
    fn verifier_verify(&self, pc_gens: &PedersenGens, z: Self::ChallengeResponse) -> bool;
}

pub struct LCorrectProver {
    pub_key: ElgamalPublicKey,
    w: CommitmentWitness,
    u: Scalar,
}

impl LCorrectProver {
    pub fn new(pub_key: &ElgamalPublicKey, w: &CommitmentWitness) -> Self {
        LCorrectProver {
            pub_key: pub_key.clone(),
            w: w.clone(),
            u: Scalar::default()
        }
    }
}

impl AssetProofProver for LCorrectProver {
    type Commitment = (RistrettoPoint, RistrettoPoint);
    type Challenge = Scalar;
    type ChallengeResponse = Scalar;

    fn prover_generate_commitment<T: RngCore + CryptoRng>(
        &mut self,
        pc_gens: &PedersenGens,
        rng: &mut T,
    ) -> Self::Commitment {
        let rand_commitment = Scalar::random(rng);
        self.u = rand_commitment;

        (
            rand_commitment * self.pub_key.pub_key,
            rand_commitment * pc_gens.B_blinding,
        )
    }

    fn prover_apply_challenge(&self, c: Self::Challenge) -> Self::ChallengeResponse {
        self.u + c * self.w.blinding
    }
}

pub struct LCorrectVerifier {
    value: u32,
    pub_key: ElgamalPublicKey,
    cipher: CipherText,
    rc: (RistrettoPoint, RistrettoPoint),
    challenge: Scalar,
}

impl LCorrectVerifier {
    pub fn new(value: &u32, pub_key: &ElgamalPublicKey, cipher: &CipherText) -> Self {
        LCorrectVerifier {
            value: value.clone(),
            pub_key: pub_key.clone(),
            cipher: cipher.clone(),
            rc: (RistrettoPoint::default(), RistrettoPoint::default()),
            challenge: Scalar::default(),
        }
    }
}

impl AssetProofVerifier for LCorrectVerifier {
    type Commitment = (RistrettoPoint, RistrettoPoint);
    type Challenge = Scalar;
    type ChallengeResponse = Scalar;

    fn verifier_generate_challenge<T: RngCore + CryptoRng>(
        &mut self,
        c: Self::Commitment,
        rng: &mut T,
    ) -> Self::Challenge {
        self.rc = c;
        let rand_challenge = Scalar::random(rng);
        self.challenge = rand_challenge.clone();
        rand_challenge
    }

    fn verifier_verify(&self, pc_gens: &PedersenGens, z: Self::ChallengeResponse) -> bool {
        if z * self.pub_key.pub_key != self.rc.0 + self.challenge * self.cipher.x {
            return false;
        }
        let y_prime = self.cipher.y - (Scalar::from(self.value) * pc_gens.B);
        if z * pc_gens.B_blinding != self.rc.1 + self.challenge * y_prime {
            return false;
        }
        true
    }
}

// ------------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    extern crate wasm_bindgen_test;
    use super::*;
    use crate::asset_proofs::*;
    use rand::{rngs::StdRng, SeedableRng};
    use wasm_bindgen_test::*;

    const SEED_1: [u8; 32] = [42u8; 32];

    #[test]
    #[wasm_bindgen_test]
    fn basic_range_proof() {
        let mut rng = StdRng::from_seed(SEED_1);
        // Positive test: secret value within range [0, 2^32)
        let secret_value = 42u32;
        let rand_blind = Scalar::random(&mut rng);

        let (proof, commitment) = prove_within_range(secret_value as u64, rand_blind, 32)
            .expect("This shouldn't happen.");
        assert!(verify_within_range(proof, commitment, 32));

        // Make sure the second part of the elgamal encryption is the same as the commited value in the range proof.
        let w = CommitmentWitness::new(secret_value, rand_blind).unwrap();
        let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let elg_pub = elg_secret.get_public_key();
        let cipher = elg_pub.encrypt(&w);
        assert_eq!(commitment, cipher.y.compress());

        // Negative test: secret value outside the allowed range
        let large_secret_value: u64 = u64::from(u32::max_value()) + 3;
        let (bad_proof, bad_commitment) =
            prove_within_range(large_secret_value, rand_blind, 32).expect("This shouldn't happen.");
        assert!(!verify_within_range(bad_proof, bad_commitment, 32));
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_correctness_proof() {
        let gens = PedersenGens::default();
        // todo: turn this into a helper function
        let mut rng = StdRng::from_seed(SEED_1);
        // Positive test: secret value within range [0, 2^32)
        let secret_value = 42u32;
        let rand_blind = Scalar::random(&mut rng);

        // Make sure the second part of the elgamal encryption is the same as the commited value in the range proof.
        let w = CommitmentWitness::new(secret_value, rand_blind).unwrap();
        let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let elg_pub = elg_secret.get_public_key();
        let cipher = elg_pub.encrypt(&w);

        // assert_eq!(cipher.y, Scalar::from(secret_value) * gens.B_blinding + rand_blind * gens.B);
        let mut prover = LCorrectProver::new(&elg_pub, &w);
        let mut verifier = LCorrectVerifier::new(&secret_value, &elg_pub, &cipher);

        let commitment = prover.prover_generate_commitment(&gens, &mut rng);
        let challenge = verifier.verifier_generate_challenge(commitment, &mut rng);
        let proof = prover.prover_apply_challenge(challenge);
        let result = verifier.verifier_verify(&gens, proof);
        assert!(result);
    }
}
