//! The proof of two ciphertexts encrypting the same value
//! under different public keys.
//! For more details see section 5.4 of the whitepaper.

use crate::{
    asset_proofs::{
        encryption_proofs::{
            AssetProofProver, AssetProofProverAwaitingChallenge, AssetProofVerifier, ZKPChallenge,
        },
        transcript::{TranscriptProtocol, UpdateTranscript},
        CipherText, CommitmentWitness, ElgamalPublicKey,
    },
    errors::{ErrorKind, Fallible},
};
use bulletproofs::PedersenGens;
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;
use zeroize::Zeroizing;

/// The domain label for the encrypting the same value proof.
pub const ENCRYPTING_SAME_VALUE_PROOF_FINAL_RESPONSE_LABEL: &[u8] =
    b"PolymathEncryptingSameValueFinalResponse";
/// The domain label for the challenge.
pub const ENCRYPTING_SAME_VALUE_PROOF_CHALLENGE_LABEL: &[u8] =
    b"PolymathEncryptingSameValueFinalResponseChallenge";

// ------------------------------------------------------------------------
// Proof of Two Ciphertexts Encrypting the Same Value Under Different
// Public Keys
// ------------------------------------------------------------------------

#[derive(Copy, Clone, Debug, Default)]
pub struct EncryptingSameValueFinalResponse {
    z1: Scalar,
    z2: Scalar,
}

#[derive(Copy, Clone, Debug)]
pub struct EncryptingSameValueInitialMessage {
    a1: RistrettoPoint,
    a2: RistrettoPoint,
    b: RistrettoPoint,
}

/// A default implementation used for testing.
impl Default for EncryptingSameValueInitialMessage {
    fn default() -> Self {
        EncryptingSameValueInitialMessage {
            a1: RISTRETTO_BASEPOINT_POINT,
            a2: RISTRETTO_BASEPOINT_POINT,
            b: RISTRETTO_BASEPOINT_POINT,
        }
    }
}

impl UpdateTranscript for EncryptingSameValueInitialMessage {
    fn update_transcript(&self, transcript: &mut Transcript) -> Fallible<()> {
        transcript.append_domain_separator(ENCRYPTING_SAME_VALUE_PROOF_CHALLENGE_LABEL);
        transcript.append_validated_point(b"A1", &self.a1.compress())?;
        transcript.append_validated_point(b"A2", &self.a2.compress())?;
        transcript.append_validated_point(b"B", &self.b.compress())?;
        Ok(())
    }
}

pub struct EncryptingSameValueProverAwaitingChallenge {
    /// The first public key used for the elgamal encryption.
    pub pub_key1: ElgamalPublicKey,

    /// The second public key used for the elgamal encryption.
    pub pub_key2: ElgamalPublicKey,

    /// The secret commitment witness.
    pub w: Zeroizing<CommitmentWitness>,
}

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct EncryptingSameValueProver {
    /// The secret commitment witness.
    w: Zeroizing<CommitmentWitness>,

    /// The randomness generated in the first round.
    u1: Scalar,

    /// The randomness generated in the first round.
    u2: Scalar,
}

impl AssetProofProverAwaitingChallenge for EncryptingSameValueProverAwaitingChallenge {
    type ZKInitialMessage = EncryptingSameValueInitialMessage;
    type ZKFinalResponse = EncryptingSameValueFinalResponse;
    type ZKProver = EncryptingSameValueProver;

    fn generate_initial_message<T: RngCore + CryptoRng>(
        &self,
        pc_gens: &PedersenGens,
        rng: &mut T,
    ) -> (Self::ZKProver, Self::ZKInitialMessage) {
        let rand_commitment1 = Scalar::random(rng);
        let rand_commitment2 = Scalar::random(rng);

        (
            EncryptingSameValueProver {
                w: self.w.clone(),
                u1: rand_commitment1,
                u2: rand_commitment2,
            },
            EncryptingSameValueInitialMessage {
                a1: rand_commitment1 * self.pub_key1.pub_key,
                a2: rand_commitment1 * self.pub_key2.pub_key,
                b: rand_commitment1 * pc_gens.B_blinding + rand_commitment2 * pc_gens.B,
            },
        )
    }
}

impl AssetProofProver<EncryptingSameValueFinalResponse> for EncryptingSameValueProver {
    fn apply_challenge(&self, c: &ZKPChallenge) -> EncryptingSameValueFinalResponse {
        EncryptingSameValueFinalResponse {
            z1: self.u1 + c.x() * self.w.blinding(),
            z2: self.u2 + c.x() * Scalar::from(self.w.value()),
        }
    }
}

pub struct EncryptingSameValueVerifier {
    /// The first public key to which the `value` is encrypted.
    pub pub_key1: ElgamalPublicKey,

    /// The second public key to which the `value` is encrypted.
    pub pub_key2: ElgamalPublicKey,

    /// The first encryption cipher text.
    pub cipher1: CipherText,

    /// The second encryption cipher text.
    pub cipher2: CipherText,
}

impl AssetProofVerifier for EncryptingSameValueVerifier {
    type ZKInitialMessage = EncryptingSameValueInitialMessage;
    type ZKFinalResponse = EncryptingSameValueFinalResponse;

    fn verify(
        &self,
        pc_gens: &PedersenGens,
        challenge: &ZKPChallenge,
        initial_message: &Self::ZKInitialMessage,
        final_response: &Self::ZKFinalResponse,
    ) -> Fallible<()> {
        // 2 ciphertexts that encrypt the same witness must have the same Y value.
        ensure!(
            self.cipher1.y == self.cipher2.y,
            ErrorKind::VerificationError
        );

        ensure!(
            final_response.z1 * self.pub_key1.pub_key
                == initial_message.a1 + challenge.x() * self.cipher1.x,
            ErrorKind::EncryptingSameValueFinalResponseVerificationError { check: 1 }
        );
        ensure!(
            final_response.z1 * self.pub_key2.pub_key
                == initial_message.a2 + challenge.x() * self.cipher2.x,
            ErrorKind::EncryptingSameValueFinalResponseVerificationError { check: 2 }
        );
        ensure!(
            final_response.z1 * pc_gens.B_blinding + final_response.z2 * pc_gens.B
                == initial_message.b + challenge.x() * self.cipher1.y,
            ErrorKind::EncryptingSameValueFinalResponseVerificationError { check: 3 }
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
    fn test_encrypting_same_value_proof() {
        let gens = PedersenGens::default();
        let mut rng = StdRng::from_seed(SEED_1);
        let secret_value = 49u32;
        let rand_blind = Scalar::random(&mut rng);

        let w = CommitmentWitness::try_from((secret_value, rand_blind)).unwrap();

        let elg_pub1 = ElgamalSecretKey::new(Scalar::random(&mut rng)).get_public_key();
        let cipher1 = elg_pub1.encrypt(&w);

        let elg_pub2 = ElgamalSecretKey::new(Scalar::random(&mut rng)).get_public_key();
        let cipher2 = elg_pub2.encrypt(&w);

        let prover_ac = EncryptingSameValueProverAwaitingChallenge {
            pub_key1: elg_pub1,
            pub_key2: elg_pub2,
            w: Zeroizing::new(w),
        };
        let verifier = EncryptingSameValueVerifier {
            pub_key1: elg_pub1,
            pub_key2: elg_pub2,
            cipher1: cipher1,
            cipher2: cipher2,
        };
        let mut transcript = Transcript::new(ENCRYPTING_SAME_VALUE_PROOF_FINAL_RESPONSE_LABEL);

        // Positive tests
        let (prover, initial_message) = prover_ac.generate_initial_message(&gens, &mut rng);
        initial_message.update_transcript(&mut transcript).unwrap();
        let challenge = transcript
            .scalar_challenge(ENCRYPTING_SAME_VALUE_PROOF_CHALLENGE_LABEL)
            .unwrap();
        let final_response = prover.apply_challenge(&challenge);

        let result = verifier.verify(&gens, &challenge, &initial_message, &final_response);
        assert!(result.is_ok());

        // Negative tests
        let bad_initial_message = EncryptingSameValueInitialMessage::default();
        let result = verifier.verify(&gens, &challenge, &bad_initial_message, &final_response);
        assert_err!(
            result,
            ErrorKind::EncryptingSameValueFinalResponseVerificationError { check: 1 }
        );

        let bad_final_response = EncryptingSameValueFinalResponse::default();
        let result = verifier.verify(&gens, &challenge, &initial_message, &bad_final_response);
        assert_err!(
            result,
            ErrorKind::EncryptingSameValueFinalResponseVerificationError { check: 1 }
        );

        // Non-Interactive ZKP test
        let (initial_message, final_response) =
            encryption_proofs::single_property_prover(prover_ac, &mut rng).unwrap();
        assert!(encryption_proofs::single_property_verifier(
            &verifier,
            initial_message,
            final_response
        )
        .is_ok());
    }
}
