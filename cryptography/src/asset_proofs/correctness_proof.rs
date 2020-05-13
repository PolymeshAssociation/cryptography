//! The proof of correct encryption of the given value.
//! For more details see section 5.2 of the whitepaper.

use crate::asset_proofs::{
    encryption_proofs::{
        AssetProofProver, AssetProofProverAwaitingChallenge, AssetProofVerifier, ProofGenerators,
        ZKPChallenge,
    },
    errors::{AssetProofError, Result},
    transcript::{TranscriptProtocol, UpdateTranscript},
    CipherText, CommitmentWitness, ElgamalPublicKey,
};
use bulletproofs::PedersenGens;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use merlin::{Transcript, TranscriptRng};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

/// The domain label for the correctness proof.
pub const CORRECTNESS_PROOF_FINAL_RESPONSE_LABEL: &[u8] = b"PolymathCorrectnessFinalResponse";
/// The domain label for the challenge.
pub const CORRECTNESS_PROOF_CHALLENGE_LABEL: &[u8] = b"PolymathCorrectnessChallenge";

// ------------------------------------------------------------------------
// Proof of Correct Encryption of the Given Value
// ------------------------------------------------------------------------

pub type CorrectnessFinalResponse = Scalar;

#[derive(Copy, Clone, Debug)]
pub struct CorrectnessInitialMessage {
    a: RistrettoPoint,
    b: RistrettoPoint,
}

/// A default implementation used for testing.
impl Default for CorrectnessInitialMessage {
    fn default() -> Self {
        CorrectnessInitialMessage {
            a: RISTRETTO_BASEPOINT_POINT,
            b: RISTRETTO_BASEPOINT_POINT,
        }
    }
}

impl UpdateTranscript for CorrectnessInitialMessage {
    fn update_transcript(&self, transcript: &mut Transcript) -> Result<()> {
        transcript.append_domain_separator(CORRECTNESS_PROOF_CHALLENGE_LABEL);
        transcript.append_validated_point(b"A", &self.a.compress())?;
        transcript.append_validated_point(b"B", &self.b.compress())?;
        Ok(())
    }
}

pub struct CorrectnessProverAwaitingChallenge {
    /// The public key used for the elgamal encryption.
    pub_key: ElgamalPublicKey,

    /// The secret commitment witness.
    w: CommitmentWitness,
}

impl CorrectnessProverAwaitingChallenge {
    pub fn new(pub_key: ElgamalPublicKey, w: CommitmentWitness) -> Self {
        CorrectnessProverAwaitingChallenge { pub_key, w }
    }
}

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct CorrectnessProver {
    /// The secret commitment witness.
    w: CommitmentWitness,

    /// The randomness generate in the first round.
    u: Scalar,
}

impl AssetProofProverAwaitingChallenge for CorrectnessProverAwaitingChallenge {
    type ZKInitialMessage = CorrectnessInitialMessage;
    type ZKFinalResponse = CorrectnessFinalResponse;
    type ZKProver = CorrectnessProver;

    fn create_transcript_rng<T: RngCore + CryptoRng>(
        &self,
        rng: &mut T,
        transcript: &Transcript,
    ) -> TranscriptRng {
        transcript.create_transcript_rng_from_witness(rng, &self.w)
    }

    fn generate_initial_message(
        &self,
        pc_gens: &ProofGenerators,
        rng: &mut TranscriptRng,
    ) -> (Self::ZKProver, Self::ZKInitialMessage) {
        let rand_commitment = Scalar::random(rng);

        let g: PedersenGens = match pc_gens {
            ProofGenerators::PedersenGens(gens) => *gens,
            _ => PedersenGens::default(),
        };

        (
            CorrectnessProver {
                w: self.w.clone(),
                u: rand_commitment,
            },
            CorrectnessInitialMessage {
                a: rand_commitment * self.pub_key.pub_key,
                b: rand_commitment * g.B_blinding,
            },
        )
    }
}

impl AssetProofProver<CorrectnessFinalResponse> for CorrectnessProver {
    fn apply_challenge(&self, c: &ZKPChallenge) -> CorrectnessFinalResponse {
        self.u + c.x() * self.w.blinding()
    }
}

pub struct CorrectnessVerifier {
    /// The encrypted value (aka the plain text).
    value: u32,

    /// The public key to which the `value` is encrypted.
    pub_key: ElgamalPublicKey,

    /// The encryption cipher text.
    cipher: CipherText,
}

impl CorrectnessVerifier {
    pub fn new(value: u32, pub_key: ElgamalPublicKey, cipher: CipherText) -> Self {
        CorrectnessVerifier {
            value,
            pub_key,
            cipher,
        }
    }
}

impl AssetProofVerifier for CorrectnessVerifier {
    type ZKInitialMessage = CorrectnessInitialMessage;
    type ZKFinalResponse = CorrectnessFinalResponse;

    fn verify(
        &self,
        pc_gens: &ProofGenerators,
        challenge: &ZKPChallenge,
        initial_message: &Self::ZKInitialMessage,
        z: &Self::ZKFinalResponse,
    ) -> Result<()> {
        let generators: &PedersenGens;
        let new_gens: PedersenGens;
        if let ProofGenerators::PedersenGens(g) = &pc_gens {
            generators = g;
        } else {
            new_gens = PedersenGens::default();
            generators = &new_gens;
        };

        let y_prime = self.cipher.y - (Scalar::from(self.value) * generators.B);

        ensure!(
            z * self.pub_key.pub_key == initial_message.a + challenge.x() * self.cipher.x,
            AssetProofError::CorrectnessFinalResponseVerificationError { check: 1 }
        );
        ensure!(
            z * generators.B_blinding == initial_message.b + challenge.x() * y_prime,
            AssetProofError::CorrectnessFinalResponseVerificationError { check: 2 }
        );
        Ok(())
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
    use std::convert::TryFrom;
    use wasm_bindgen_test::*;

    const SEED_1: [u8; 32] = [17u8; 32];

    #[test]
    #[wasm_bindgen_test]
    fn test_correctness_proof() {
        //let gens = PedersenGens::default();
        let gens = ProofGenerators::PedersenGens(PedersenGens::default());
        let mut rng = StdRng::from_seed(SEED_1);
        let secret_value = 13u32;
        let rand_blind = Scalar::random(&mut rng);

        let w = CommitmentWitness::try_from((secret_value, rand_blind)).unwrap();
        let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let elg_pub = elg_secret.get_public_key();
        let cipher = elg_pub.encrypt(&w);

        let prover = CorrectnessProverAwaitingChallenge::new(elg_pub, w);
        let verifier = CorrectnessVerifier::new(secret_value, elg_pub, cipher);
        let mut transcript = Transcript::new(CORRECTNESS_PROOF_FINAL_RESPONSE_LABEL);

        // Positive tests
        let mut transcript_rng = prover.create_transcript_rng(&mut rng, &transcript);
        let (prover, initial_message) = prover.generate_initial_message(&gens, &mut transcript_rng);
        initial_message.update_transcript(&mut transcript).unwrap();
        let challenge = transcript
            .scalar_challenge(CORRECTNESS_PROOF_CHALLENGE_LABEL)
            .unwrap();
        let final_response = prover.apply_challenge(&challenge);

        let result = verifier.verify(&gens, &challenge, &initial_message, &final_response);
        assert!(result.is_ok());

        // Negative tests
        let bad_initial_message = CorrectnessInitialMessage::default();
        let result = verifier.verify(&gens, &challenge, &bad_initial_message, &final_response);
        assert_err!(
            result,
            AssetProofError::CorrectnessFinalResponseVerificationError { check: 1 }
        );

        let bad_final_response = Scalar::default();
        let result = verifier.verify(&gens, &challenge, &initial_message, &bad_final_response);
        assert_err!(
            result,
            AssetProofError::CorrectnessFinalResponseVerificationError { check: 1 }
        );
    }
}
