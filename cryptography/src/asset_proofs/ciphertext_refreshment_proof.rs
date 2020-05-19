//! The proof that 2 cipher texts encrypt the same value
//! under the same public key.
//! This proof is useful to prove the correctness of a
//! ciphertext refreshment method.
//! For more details see sections 3.6 and 5.3 of the
//! whitepaper.

use crate::asset_proofs::{
    encryption_proofs::{
        AssetProofProver, AssetProofProverAwaitingChallenge, AssetProofVerifier, ZKPChallenge,
    },
    errors::{AssetProofError, Result},
    transcript::{TranscriptProtocol, UpdateTranscript},
    CipherText, ElgamalPublicKey, ElgamalSecretKey,
};
use bulletproofs::PedersenGens;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use merlin::{Transcript, TranscriptRng};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// The domain label for the ciphertext refreshment proof.
pub const CIPHERTEXT_REFRESHMENT_FINAL_RESPONSE_LABEL: &[u8] =
    b"PolymathCipherTextRefreshmentFinalResponse";
/// The domain label for the challenge.
pub const CIPHERTEXT_REFRESHMENT_PROOF_CHALLENGE_LABEL: &[u8] =
    b"PolymathCipherTextRefreshmentChallenge";

// ------------------------------------------------------------------------
// Proof of two ciphertext encrypting the same value under the same
// public key
// ------------------------------------------------------------------------

#[derive(Serialize, Deserialize, PartialEq, Copy, Clone, Debug)]
pub struct CipherTextRefreshmentFinalResponse(Scalar);

#[derive(Serialize, Deserialize, PartialEq, Copy, Clone, Debug)]
pub struct CipherTextRefreshmentInitialMessage {
    a: RistrettoPoint,
    b: RistrettoPoint,
}

/// A default implementation used for testing.
impl Default for CipherTextRefreshmentInitialMessage {
    fn default() -> Self {
        CipherTextRefreshmentInitialMessage {
            a: RISTRETTO_BASEPOINT_POINT,
            b: RISTRETTO_BASEPOINT_POINT,
        }
    }
}

impl UpdateTranscript for CipherTextRefreshmentInitialMessage {
    fn update_transcript(&self, transcript: &mut Transcript) -> Result<()> {
        transcript.append_domain_separator(CIPHERTEXT_REFRESHMENT_PROOF_CHALLENGE_LABEL);
        transcript.append_validated_point(b"A", &self.a.compress())?;
        transcript.append_validated_point(b"B", &self.b.compress())?;
        Ok(())
    }
}

pub struct CipherTextRefreshmentProverAwaitingChallenge {
    /// The public key used for the elgamal encryption.
    secret_key: ElgamalSecretKey,

    /// The difference between the Y part of the two ciphertexts:
    /// Y = ciphertext1.y - ciphertext2.y
    y: RistrettoPoint,
}

impl CipherTextRefreshmentProverAwaitingChallenge {
    pub fn new(
        secret_key: ElgamalSecretKey,
        ciphertext1: CipherText,
        ciphertext2: CipherText,
    ) -> Self {
        CipherTextRefreshmentProverAwaitingChallenge {
            secret_key: secret_key,
            y: ciphertext1.y - ciphertext2.y,
        }
    }
}

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct CipherTextRefreshmentProver {
    /// The secret key.
    secret_key: ElgamalSecretKey,

    /// The randomness generated in the first round.
    u: Scalar,
}

impl AssetProofProverAwaitingChallenge for CipherTextRefreshmentProverAwaitingChallenge {
    type ZKInitialMessage = CipherTextRefreshmentInitialMessage;
    type ZKFinalResponse = CipherTextRefreshmentFinalResponse;
    type ZKProver = CipherTextRefreshmentProver;

    fn create_transcript_rng<T: RngCore + CryptoRng>(
        &self,
        rng: &mut T,
        transcript: &Transcript,
    ) -> TranscriptRng {
        transcript
            .build_rng()
            .rekey_with_witness_bytes(b"y", self.y.compress().as_bytes())
            .finalize(rng)
    }

    fn generate_initial_message(
        &self,
        pc_gens: &PedersenGens,
        rng: &mut TranscriptRng,
    ) -> (Self::ZKProver, Self::ZKInitialMessage) {
        let rand_commitment = Scalar::random(rng);

        let initial_message = CipherTextRefreshmentInitialMessage {
            a: rand_commitment * self.y,
            b: rand_commitment * pc_gens.B_blinding,
        };

        let prover = CipherTextRefreshmentProver {
            secret_key: self.secret_key.clone(),
            u: rand_commitment,
        };
        (prover, initial_message)
    }
}

impl AssetProofProver<CipherTextRefreshmentFinalResponse> for CipherTextRefreshmentProver {
    fn apply_challenge(&self, c: &ZKPChallenge) -> CipherTextRefreshmentFinalResponse {
        CipherTextRefreshmentFinalResponse(self.u + c.x() * self.secret_key.secret)
    }
}

pub struct CipherTextRefreshmentVerifier {
    /// The public key to which the `value` is encrypted.
    pub_key: ElgamalPublicKey,

    /// The difference between the X part of the two ciphertexts:
    /// X = ciphertext1.x - ciphertext2.x
    x: RistrettoPoint,

    /// The difference between the Y part of the two ciphertexts:
    /// Y = ciphertext1.y - ciphertext2.y
    y: RistrettoPoint,
}

impl CipherTextRefreshmentVerifier {
    pub fn new(
        pub_key: ElgamalPublicKey,
        ciphertext1: CipherText,
        ciphertext2: CipherText,
    ) -> Self {
        CipherTextRefreshmentVerifier {
            pub_key: pub_key,
            x: ciphertext1.x - ciphertext2.x,
            y: ciphertext1.y - ciphertext2.y,
        }
    }
}

impl AssetProofVerifier for CipherTextRefreshmentVerifier {
    type ZKInitialMessage = CipherTextRefreshmentInitialMessage;
    type ZKFinalResponse = CipherTextRefreshmentFinalResponse;

    fn verify(
        &self,
        pc_gens: &PedersenGens,
        challenge: &ZKPChallenge,
        initial_message: &Self::ZKInitialMessage,
        z: &Self::ZKFinalResponse,
    ) -> Result<()> {
        ensure!(
            z.0 * self.y == initial_message.a + challenge.x() * self.x,
            AssetProofError::CiphertextRefreshmentFinalResponseVerificationError { check: 1 }
        );
        ensure!(
            z.0 * pc_gens.B_blinding == initial_message.b + challenge.x() * self.pub_key.pub_key,
            AssetProofError::CiphertextRefreshmentFinalResponseVerificationError { check: 2 }
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
    use bincode::{deserialize, serialize};
    use rand::{rngs::StdRng, SeedableRng};
    use std::convert::TryFrom;
    use wasm_bindgen_test::*;

    const SEED_1: [u8; 32] = [17u8; 32];
    const SEED_2: [u8; 32] = [19u8; 32];

    #[test]
    #[wasm_bindgen_test]
    fn test_ciphertext_refreshment_proof() {
        let gens = PedersenGens::default();
        let mut rng = StdRng::from_seed(SEED_1);
        let secret_value = 13u32;

        let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let elg_pub = elg_secret.get_public_key();
        let ciphertext1 = elg_pub.encrypt_value(secret_value.clone()).unwrap();
        let ciphertext2 = elg_pub.encrypt_value(secret_value.clone()).unwrap();

        let prover =
            CipherTextRefreshmentProverAwaitingChallenge::new(elg_secret, ciphertext1, ciphertext2);
        let verifier = CipherTextRefreshmentVerifier::new(elg_pub, ciphertext1, ciphertext2);
        let mut transcript = Transcript::new(CIPHERTEXT_REFRESHMENT_FINAL_RESPONSE_LABEL);

        // Positive tests
        let mut transcript_rng = prover.create_transcript_rng(&mut rng, &transcript);
        let (prover, initial_message) = prover.generate_initial_message(&gens, &mut transcript_rng);
        initial_message.update_transcript(&mut transcript).unwrap();
        let challenge = transcript
            .scalar_challenge(CIPHERTEXT_REFRESHMENT_PROOF_CHALLENGE_LABEL)
            .unwrap();
        let final_response = prover.apply_challenge(&challenge);

        let result = verifier.verify(&gens, &challenge, &initial_message, &final_response);
        assert!(result.is_ok());

        // Negative tests
        let bad_initial_message = CipherTextRefreshmentInitialMessage::default();
        let result = verifier.verify(&gens, &challenge, &bad_initial_message, &final_response);
        assert_err!(
            result,
            AssetProofError::CiphertextRefreshmentFinalResponseVerificationError { check: 1 }
        );

        let bad_final_response = CipherTextRefreshmentFinalResponse(Scalar::default());
        assert_err!(
            verifier.verify(&gens, &challenge, &initial_message, &bad_final_response),
            AssetProofError::CiphertextRefreshmentFinalResponseVerificationError { check: 1 }
        );
    }

    #[test]
    #[wasm_bindgen_test]
    fn verify_ciphertext_refreshment_method() {
        let mut rng = StdRng::from_seed(SEED_2);
        let rand_blind = Scalar::random(&mut rng);
        let w = CommitmentWitness::try_from((3u32, rand_blind)).unwrap();

        let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let elg_pub = elg_secret.get_public_key();
        let cipher = elg_pub.encrypt(&w);

        let new_cipher = cipher
            .ciphertext_refreshment_method(&elg_secret, &mut rng)
            .unwrap();

        let prover =
            CipherTextRefreshmentProverAwaitingChallenge::new(elg_secret, cipher, new_cipher);
        let verifier = CipherTextRefreshmentVerifier::new(elg_pub, cipher, new_cipher);

        let (initial_message, final_response) =
            encryption_proofs::single_property_prover(prover, &mut rng).unwrap();

        assert!(encryption_proofs::single_property_verifier(
            &verifier,
            initial_message,
            final_response
        )
        .is_ok());
    }

    #[test]
    #[wasm_bindgen_test]
    fn serialize_deserialize_proof() {
        let mut rng = StdRng::from_seed(SEED_1);
        let secret_value = 13u32;

        let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let elg_pub = elg_secret.get_public_key();
        let ciphertext1 = elg_pub.encrypt_value(secret_value.clone()).unwrap();
        let ciphertext2 = elg_pub.encrypt_value(secret_value.clone()).unwrap();

        let prover =
            CipherTextRefreshmentProverAwaitingChallenge::new(elg_secret, ciphertext1, ciphertext2);
        let (initial_message0, final_response0) = encryption_proofs::single_property_prover::<
            StdRng,
            CipherTextRefreshmentProverAwaitingChallenge,
        >(prover, &mut rng)
        .unwrap();

        let initial_message_bytes: Vec<u8> = serialize(&initial_message0).unwrap();
        let final_response_bytes: Vec<u8> = serialize(&final_response0).unwrap();
        let recovered_initial_message: CipherTextRefreshmentInitialMessage =
            deserialize(&initial_message_bytes).unwrap();
        let recovered_final_response: CipherTextRefreshmentFinalResponse =
            deserialize(&final_response_bytes).unwrap();
        assert_eq!(recovered_initial_message, initial_message0);
        assert_eq!(recovered_final_response, final_response0);
    }
}
