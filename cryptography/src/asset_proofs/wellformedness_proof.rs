//! The proof of the wellformed encryption of the given value.
//! This proofs the knoweledge about the encrypted value.
//! For more details see section 5.1 of the whitepaper.

use crate::asset_proofs::{
    encryption_proofs::{
        AssetProofProver, AssetProofProverAwaitingChallenge, AssetProofVerifier, ZKPChallenge,
    },
    errors::{AssetProofError, Result},
    transcript::{TranscriptProtocol, UpdateTranscript},
    CipherText, CommitmentWitness, ElgamalPublicKey,
};
use bulletproofs::PedersenGens;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

/// The domain label for the wellformedness proof.
pub const WELLFORMEDNESS_PROOF_FINAL_RESPONSE_LABEL: &[u8] = b"PolymathWellformednessFinalResponse";
/// The domain label for the challenge.
pub const WELLFORMEDNESS_PROOF_CHALLENGE_LABEL: &[u8] = b"PolymathWellformednessProofChallenge";

#[derive(Copy, Clone, Debug)]
pub struct WellformednessFinalResponse {
    z1: Scalar,
    z2: Scalar,
}

#[derive(Copy, Clone, Debug)]
pub struct WellformednessInitialMessage {
    a: RistrettoPoint,
    b: RistrettoPoint,
}

/// A default implementation used for testing.
impl Default for WellformednessInitialMessage {
    fn default() -> Self {
        WellformednessInitialMessage {
            a: RISTRETTO_BASEPOINT_POINT,
            b: RISTRETTO_BASEPOINT_POINT,
        }
    }
}

impl UpdateTranscript for WellformednessInitialMessage {
    fn update_transcript(&self, transcript: &mut Transcript) -> Result<()> {
        transcript.append_domain_separator(WELLFORMEDNESS_PROOF_CHALLENGE_LABEL);
        transcript.append_validated_point(b"A", &self.a.compress())?;
        transcript.append_validated_point(b"B", &self.b.compress())?;
        Ok(())
    }
}

#[derive(Clone, Debug, Zeroize)]
#[zeroize(drop)]
pub struct WellformednessProver {
    /// The secret commitment witness.
    w: Zeroizing<CommitmentWitness>,
    /// The randomness generate in the first round.
    rand_a: Scalar,
    rand_b: Scalar,
}

#[derive(Clone, Debug)]
pub struct WellformednessProverAwaitingChallenge {
    /// The public key used for the elgamal encryption.
    pub_key: ElgamalPublicKey,
    /// The secret commitment witness.
    w: Zeroizing<CommitmentWitness>,
}

impl AssetProofProverAwaitingChallenge for WellformednessProverAwaitingChallenge {
    type ZKInitialMessage = WellformednessInitialMessage;
    type ZKFinalResponse = WellformednessFinalResponse;
    type ZKProver = WellformednessProver;

    fn generate_initial_message<T: RngCore + CryptoRng>(
        &self,
        pc_gens: &PedersenGens,
        rng: &mut T,
    ) -> (Self::ZKProver, Self::ZKInitialMessage) {
        let rand_a = Scalar::random(rng);
        let rand_b = Scalar::random(rng);
        (
            WellformednessProver {
                w: self.w.clone(),
                rand_a,
                rand_b,
            },
            WellformednessInitialMessage {
                a: rand_a * self.pub_key.pub_key,
                b: rand_a * pc_gens.B_blinding + rand_b * pc_gens.B,
            },
        )
    }
}

impl AssetProofProver<WellformednessFinalResponse> for WellformednessProver {
    fn apply_challenge(&self, c: &ZKPChallenge) -> WellformednessFinalResponse {
        WellformednessFinalResponse {
            z1: self.rand_a + c.x * self.w.blinding,
            z2: self.rand_b + c.x * Scalar::from(self.w.value),
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub struct WellformednessVerifier {
    pub_key: ElgamalPublicKey,
    cipher: CipherText,
}

impl AssetProofVerifier for WellformednessVerifier {
    type ZKInitialMessage = WellformednessInitialMessage;
    type ZKFinalResponse = WellformednessFinalResponse;

    fn verify(
        &self,
        pc_gens: &PedersenGens,
        challenge: &ZKPChallenge,
        initial_message: &Self::ZKInitialMessage,
        response: &Self::ZKFinalResponse,
    ) -> Result<()> {
        ensure!(
            response.z1 * self.pub_key.pub_key == initial_message.a + challenge.x * self.cipher.x,
            AssetProofError::WellformednessFinalResponseVerificationError { check: 1 }
        );
        ensure!(
            response.z1 * pc_gens.B_blinding + response.z2 * pc_gens.B
                == initial_message.b + challenge.x * self.cipher.y,
            AssetProofError::WellformednessFinalResponseVerificationError { check: 2 }
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    extern crate wasm_bindgen_test;
    use super::*;
    use crate::asset_proofs::encryption_proofs::{
        single_property_prover, single_property_verifier,
    };
    use crate::asset_proofs::*;
    use rand::{rngs::StdRng, SeedableRng};
    use wasm_bindgen_test::*;

    const SEED_1: [u8; 32] = [42u8; 32];

    #[test]
    #[wasm_bindgen_test]
    fn test_wellformedness_proof() {
        let gens = PedersenGens::default();
        let mut rng = StdRng::from_seed(SEED_1);
        let secret_value = 42u32;
        let rand_blind = Scalar::random(&mut rng);

        let w = CommitmentWitness::new(secret_value, rand_blind).unwrap();
        let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let pub_key = elg_secret.get_public_key();
        let cipher = pub_key.encrypt(&w);

        let prover = WellformednessProverAwaitingChallenge {
            pub_key,
            w: Zeroizing::new(w.clone()),
        };
        let verifier = WellformednessVerifier { pub_key, cipher };
        let mut dealer_transcript = Transcript::new(WELLFORMEDNESS_PROOF_FINAL_RESPONSE_LABEL);

        // ------------------------------- Interactive case
        // Positive tests
        // 1st round
        let (prover, initial_message) = prover.generate_initial_message(&gens, &mut rng);

        // 2nd round
        initial_message
            .update_transcript(&mut dealer_transcript)
            .unwrap();
        let challenge = dealer_transcript.scalar_challenge(WELLFORMEDNESS_PROOF_CHALLENGE_LABEL);

        // 3rd round
        let final_response = prover.apply_challenge(&challenge);

        // 4th round
        // in the interactive case, verifier is the dealer and therefore, the challenge is saved
        // on the verifier side and passed to this function.
        let result = verifier.verify(&gens, &challenge, &initial_message, &final_response);
        assert!(result.is_ok());

        // Negative tests
        let bad_initial_message = WellformednessInitialMessage::default();
        let result = verifier.verify(&gens, &challenge, &bad_initial_message, &final_response);
        assert_err!(
            result,
            AssetProofError::WellformednessFinalResponseVerificationError { check: 1 }
        );

        let bad_final_response = WellformednessFinalResponse {
            z1: Scalar::default(),
            z2: Scalar::default(),
        };
        let result = verifier.verify(&gens, &challenge, &initial_message, &bad_final_response);
        assert_err!(
            result,
            AssetProofError::WellformednessFinalResponseVerificationError { check: 1 }
        );

        // ------------------------------- Non-interactive case
        let prover = WellformednessProverAwaitingChallenge {
            pub_key,
            w: Zeroizing::new(w),
        };
        let verifier = WellformednessVerifier { pub_key, cipher };

        // 1st to 3rd rounds
        let (initial_message, final_response) = single_property_prover::<
            StdRng,
            WellformednessProverAwaitingChallenge,
        >(prover, &mut rng)
        .unwrap();

        // Positive test
        assert!(
            // 4th round
            single_property_verifier(&verifier, initial_message, final_response.clone()).is_ok()
        );

        // Negative tests
        let bad_initial_message = WellformednessInitialMessage::default();
        assert_err!(
            // 4th round
            single_property_verifier(&verifier, bad_initial_message, final_response),
            AssetProofError::WellformednessFinalResponseVerificationError { check: 1 }
        );

        assert_err!(
            // 4th round
            single_property_verifier(&verifier, initial_message, bad_final_response),
            AssetProofError::WellformednessFinalResponseVerificationError { check: 1 }
        );
    }
}
