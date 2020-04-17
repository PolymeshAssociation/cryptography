use crate::asset_proofs::{
    encryption_proofs::{
        AssetProofProver, AssetProofVerifier, UpdateZKDealer, ZKChallenge, ZKDealer,
    },
    CipherText, CommitmentWitness, ElgamalPublicKey,
};
use bulletproofs::PedersenGens;
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use rand_core::{CryptoRng, RngCore};

// ------------------------------------------------------------------------
// Proof of Correct Encryption of the Given Value
// ------------------------------------------------------------------------

pub type CorrectnessProof = Scalar;

pub struct CorrectnessPartialProof {
    a: RistrettoPoint,
    b: RistrettoPoint,
}

impl UpdateZKDealer for CorrectnessPartialProof {
    fn update_dealer(&self, d: &mut ZKDealer) {
        d.dealer_append_point(b"A", &self.a.compress());
        d.dealer_append_point(b"B", &self.b.compress());
    }
}

#[derive(Clone, Debug)]
pub struct CorrectnessProver {
    pub_key: ElgamalPublicKey,
    w: CommitmentWitness,
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

    fn prover_generate_partial_proof<T: RngCore + CryptoRng>(
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

    fn prover_apply_challenge(&self, c: &ZKChallenge) -> Self::ZKProof {
        self.u + c.x * self.w.blinding
    }
}

#[derive(Clone, Debug)]
pub struct CorrectnessVerifier {
    value: u32,
    pub_key: ElgamalPublicKey,
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

    fn verifier_verify(
        &self,
        pc_gens: &PedersenGens,
        challenge: &ZKChallenge,
        pp: &Self::ZKPartialProof,
        z: &Self::ZKProof,
    ) -> bool {
        if z * self.pub_key.pub_key != pp.a + challenge.x * self.cipher.x {
            return false;
        }
        let y_prime = self.cipher.y - (Scalar::from(self.value) * pc_gens.B);
        if z * pc_gens.B_blinding != pp.b + challenge.x * y_prime {
            return false;
        }
        true
    }
}

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
        let mut prover = CorrectnessProver::new(&elg_pub, &w);
        let verifier = CorrectnessVerifier::new(&secret_value, &elg_pub, &cipher);
        // todo use a different label.
        // let mut t = Transcript::new(RANGE_PROOF_LABEL);
        let mut dealer = ZKDealer::new();

        let partial_proof = prover.prover_generate_partial_proof(&gens, &mut rng);
        partial_proof.update_dealer(&mut dealer);
        let challenge = dealer.dealer_scalar_challenge(b"finalize");
        let proof = prover.prover_apply_challenge(&challenge);

        let result = verifier.verifier_verify(&gens, &challenge, &partial_proof, &proof);
        assert!(result);
    }
}
