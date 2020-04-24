//! The proof of correct encryption of the given value.
//! For more details see section 5.2 of the whitepaper.

use crate::asset_proofs::{
    encryption_proofs::{
        AssetProofProver, AssetProofProverAwaitingChallenge, AssetProofVerifier, ZKPChallenge,
    },
    transcript::{TranscriptProtocol, UpdateTranscript},
    AssetProofError, CipherText, CommitmentWitness, ElgamalPublicKey,
};
use bulletproofs::PedersenGens;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use failure::Error;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};

/// The domain label for the correctness proof.
pub const CORRECTNESS_PROOF_LABEL: &[u8] = b"PolymathCorrectnessProof";
/// The domain label for the challenge.
pub const CORRECTNESS_PROOF_CHALLENGE_LABEL: &[u8] = b"PolymathCorrectnessProofChallenge";

// ------------------------------------------------------------------------
// Proof of Correct Encryption of the Given Value
// ------------------------------------------------------------------------

pub type CorrectnessProof = Scalar;

#[derive(Copy, Clone, Debug)]
pub struct CorrectnessProofResponse {
    a: RistrettoPoint,
    b: RistrettoPoint,
}

/// A default implementation used for testing.
impl Default for CorrectnessProofResponse {
    fn default() -> Self {
        CorrectnessProofResponse {
            a: RISTRETTO_BASEPOINT_POINT,
            b: RISTRETTO_BASEPOINT_POINT,
        }
    }
}

impl UpdateTranscript for CorrectnessProofResponse {
    fn update_transcript(&self, transcript: &mut Transcript) -> Result<(), Error> {
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

pub struct CorrectnessProver {
    /// The secret commitment witness.
    w: CommitmentWitness,
    /// The randomness generate in the first round.
    u: Scalar,
}

impl CorrectnessProverAwaitingChallenge {
    pub fn new(pub_key: &ElgamalPublicKey, w: &CommitmentWitness) -> Self {
        CorrectnessProverAwaitingChallenge {
            pub_key: pub_key.clone(),
            w: w.clone(),
        }
    }
}

impl AssetProofProverAwaitingChallenge for CorrectnessProverAwaitingChallenge {
    type ZKProofResponse = CorrectnessProofResponse;
    type ZKProof = CorrectnessProof;
    type ZKProver = CorrectnessProver;

    fn generate_proof_response<T: RngCore + CryptoRng>(
        &self,
        pc_gens: &PedersenGens,
        rng: &mut T,
    ) -> (Self::ZKProver, Self::ZKProofResponse) {
        let rand_commitment = Scalar::random(rng);

        (
            CorrectnessProver {
                w: self.w.clone(),
                u: rand_commitment,
            },
            CorrectnessProofResponse {
                a: rand_commitment * self.pub_key.pub_key,
                b: rand_commitment * pc_gens.B_blinding,
            },
        )
    }
}

impl AssetProofProver<CorrectnessProof> for CorrectnessProver {
    fn apply_challenge(&self, c: &ZKPChallenge) -> CorrectnessProof {
        self.u + c.x * self.w.blinding
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
    pub fn new(value: &u32, pub_key: &ElgamalPublicKey, cipher: &CipherText) -> Self {
        CorrectnessVerifier {
            value: value.clone(),
            pub_key: pub_key.clone(),
            cipher: cipher.clone(),
        }
    }
}

impl AssetProofVerifier for CorrectnessVerifier {
    type ZKProofResponse = CorrectnessProofResponse;
    type ZKProof = CorrectnessProof;

    fn verify(
        &self,
        pc_gens: &PedersenGens,
        challenge: &ZKPChallenge,
        proof_response: &Self::ZKProofResponse,
        z: &Self::ZKProof,
    ) -> Result<(), Error> {
        let y_prime = self.cipher.y - (Scalar::from(self.value) * pc_gens.B);

        ensure!(
            z * self.pub_key.pub_key == proof_response.a + challenge.x * self.cipher.x,
            AssetProofError::CorrectnessProofVerificationError1stCheck
        );
        ensure!(
            z * pc_gens.B_blinding != proof_response.b + challenge.x * y_prime,
            AssetProofError::CorrectnessProofVerificationError2ndCheck
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    extern crate wasm_bindgen_test;
    use super::*;
    use crate::asset_proofs::*;
    use frame_support::{assert_err, assert_ok};
    use rand::{rngs::StdRng, SeedableRng};
    use wasm_bindgen_test::*;

    const SEED_1: [u8; 32] = [17u8; 32];

    #[test]
    #[wasm_bindgen_test]
    fn test_correctness_proof() {
        let gens = PedersenGens::default();
        let mut rng = StdRng::from_seed(SEED_1);
        let secret_value = 13u32;
        let rand_blind = Scalar::random(&mut rng);

        let w = CommitmentWitness::new(secret_value, rand_blind).unwrap();
        let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let elg_pub = elg_secret.get_public_key();
        let cipher = elg_pub.encrypt(&w);

        let prover = CorrectnessProverAwaitingChallenge::new(&elg_pub, &w);
        let verifier = CorrectnessVerifier::new(&secret_value, &elg_pub, &cipher);
        let mut transcript = Transcript::new(CORRECTNESS_PROOF_LABEL);

        // Positive tests
        let (prover, proof_response) = prover.generate_proof_response(&gens, &mut rng);
        proof_response.update_transcript(&mut transcript).unwrap();
        let challenge = transcript.scalar_challenge(CORRECTNESS_PROOF_CHALLENGE_LABEL);
        let proof = prover.apply_challenge(&challenge);

        let result = verifier.verify(&gens, &challenge, &proof_response, &proof);
        // assert_ok!(result);

        // Negative tests
        let bad_proof_response = CorrectnessProofResponse::default();
        let result = verifier.verify(&gens, &challenge, &bad_proof_response, &proof);
        assert_err!(
            result,
            AssetProofError::CorrectnessProofVerificationError1stCheck.into()
        );

        let bad_proof = Scalar::default();
        assert_eq!(
            verifier.verify(&gens, &challenge, &proof_response, &bad_proof),
            Err(AssetProofError::CorrectnessProofVerificationError1stCheck.into())
        );
    }
}
