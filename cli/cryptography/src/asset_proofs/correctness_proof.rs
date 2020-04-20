//! The proof of correct encryption of the given value.
//! For more details see section 5.2 of the whitepaper.

use crate::asset_proofs::{
    encryption_proofs::{
        AssetProofProver, AssetProofVerifier, UpdateZKPDealer, ZKPChallenge, ZKPDealer,
    },
    AssetProofError, CipherText, CommitmentWitness, ElgamalPublicKey,
};
use bulletproofs::PedersenGens;
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
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
pub struct CorrectnessPartialProof {
    a: RistrettoPoint,
    b: RistrettoPoint,
}

impl UpdateZKPDealer for CorrectnessPartialProof {
    fn update_dealer(&self, d: &mut ZKPDealer) -> Result<(), AssetProofError> {
        d.dealer_append_message(CORRECTNESS_PROOF_CHALLENGE_LABEL);
        d.dealer_append_validated_point(b"A", &self.a.compress())?;
        d.dealer_append_validated_point(b"B", &self.b.compress())?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct CorrectnessProver {
    /// The public key used for the elgamal encryption.
    pub_key: ElgamalPublicKey,
    /// The secret commitment witness.
    w: CommitmentWitness,
    /// The randomness generate in the first round.
    u: Scalar,
}

impl CorrectnessProver {
    pub fn new(pub_key: &ElgamalPublicKey, w: &CommitmentWitness) -> Self {
        CorrectnessProver {
            pub_key: pub_key.clone(),
            w: w.clone(),
            u: Scalar::default(),
        }
    }
}

impl AssetProofProver for CorrectnessProver {
    type ZKPartialProof = CorrectnessPartialProof;
    type ZKProof = CorrectnessProof;

    fn generate_partial_proof<T: RngCore + CryptoRng>(
        &mut self,
        pc_gens: &PedersenGens,
        rng: &mut T,
    ) -> Self::ZKPartialProof {
        let rand_commitment = Scalar::random(rng);
        self.u = rand_commitment;

        Self::ZKPartialProof {
            a: rand_commitment * self.pub_key.pub_key,
            b: rand_commitment * pc_gens.B_blinding,
        }
    }

    fn apply_challenge(&self, c: &ZKPChallenge) -> Self::ZKProof {
        self.u + c.x * self.w.blinding
    }
}

#[derive(Copy, Clone, Debug)]
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
    type ZKPartialProof = CorrectnessPartialProof;
    type ZKProof = CorrectnessProof;

    fn verify(
        &self,
        pc_gens: &PedersenGens,
        challenge: &ZKPChallenge,
        partial_proof: &Self::ZKPartialProof,
        z: &Self::ZKProof,
    ) -> Result<(), AssetProofError> {
        let y_prime = self.cipher.y - (Scalar::from(self.value) * pc_gens.B);

        if z * self.pub_key.pub_key != partial_proof.a + challenge.x * self.cipher.x {
            Err(AssetProofError::CorrectnessProofVerificationError)
        } else if z * pc_gens.B_blinding != partial_proof.b + challenge.x * y_prime {
            Err(AssetProofError::CorrectnessProofVerificationError)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate wasm_bindgen_test;
    use super::*;
    use crate::asset_proofs::*;
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

        let mut prover = CorrectnessProver::new(&elg_pub, &w);
        let verifier = CorrectnessVerifier::new(&secret_value, &elg_pub, &cipher);
        let mut dealer = ZKPDealer::new(CORRECTNESS_PROOF_LABEL);

        // Positive tests
        let partial_proof = prover.generate_partial_proof(&gens, &mut rng);
        partial_proof.update_dealer(&mut dealer).unwrap();
        let challenge = dealer.dealer_scalar_challenge(CORRECTNESS_PROOF_CHALLENGE_LABEL);
        let proof = prover.apply_challenge(&challenge);

        let result = verifier.verify(&gens, &challenge, &partial_proof, &proof);
        assert!(result.is_ok());

        // Negative tests
        let bad_partial_proof = CorrectnessPartialProof {a: RistrettoPoint::default(), b: RistrettoPoint::default()};
        let result = verifier.verify(&gens, &challenge, &bad_partial_proof, &proof);
        assert!(result.is_err());

        let bad_proof = Scalar::default();
        let result = verifier.verify(&gens, &challenge, &partial_proof, &bad_proof);
        assert!(result.is_err());
    }
}
