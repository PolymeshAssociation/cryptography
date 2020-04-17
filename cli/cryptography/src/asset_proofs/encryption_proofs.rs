use bulletproofs::PedersenGens;
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};

const ENCRYPTION_PROOF_LABEL: &[u8] = b"PolymathEncryptionProof";

// todo better names
pub struct ZKChallenge {
    pub x: Scalar,
}

pub struct ZKDealer {
    transcript: Transcript,
}

impl ZKDealer {
    // pub fn new(transcript: &'a mut Transcript) -> Self {
    pub fn new() -> Self {
        let t = Transcript::new(&ENCRYPTION_PROOF_LABEL);
        ZKDealer { transcript: t }
    }

    pub fn dealer_append_point(&mut self, label: &'static [u8], m: &CompressedRistretto) {
        // todo this could potentially do a check and return error
        // this could take in a label as well
        self.transcript.append_message(label, m.as_bytes());
    }

    pub fn dealer_scalar_challenge(&mut self, label: &'static [u8]) -> ZKChallenge {
        let mut buf = [0u8; 64];
        self.transcript.challenge_bytes(label, &mut buf);

        ZKChallenge {
            x: Scalar::from_bytes_mod_order_wide(&buf),
        }
    }
}

pub trait UpdateZKDealer {
    fn update_dealer(&self, d: &mut ZKDealer);
}

/// The interface for 3-Sigma proofs of properties of an encrypted value.
///
// pub trait AssetProofProver<ZKPartialProof: UpdateZKDealer, ZKProof> {
pub trait AssetProofProver {
    type ZKPartialProof: UpdateZKDealer;
    type ZKProof;
    fn prover_generate_partial_proof<T: RngCore + CryptoRng>(
        &mut self,
        pc_gens: &PedersenGens,
        rng: &mut T,
    ) -> Self::ZKPartialProof;

    fn prover_apply_challenge(&self, c: &ZKChallenge) -> Self::ZKProof;
}

// pub trait AssetProofVerifier<ZKPartialProof: UpdateZKDealer, ZKProof> {
pub trait AssetProofVerifier {
    type ZKPartialProof: UpdateZKDealer;
    type ZKProof;

    fn verifier_verify(
        &self,
        pc_gens: &PedersenGens,
        challenge: &ZKChallenge,
        pp: &Self::ZKPartialProof,
        z: &Self::ZKProof,
    ) -> bool;
}

pub fn single_property_prover<T: RngCore + CryptoRng, Prover: AssetProofProver>(
    prover: &mut Prover,
    rng: &mut T,
) -> (Prover::ZKPartialProof, Prover::ZKProof) {
    // todo use a different label.
    // let mut t = Transcript::new(ENCRYPTION_PROOF_LABEL);
    let mut dealer = ZKDealer::new();
    let gens = PedersenGens::default();
    let message = prover.prover_generate_partial_proof(&gens, rng);

    message.update_dealer(&mut dealer);

    let challenge = dealer.dealer_scalar_challenge(b"finalize");

    (message, prover.prover_apply_challenge(&challenge))
}

pub fn single_property_verifier<Verifier: AssetProofVerifier>(
    verifier: &Verifier,
    pp: &Verifier::ZKPartialProof,
    p: &Verifier::ZKProof,
) -> bool {
    // todo use a different label.
    // let mut t = Transcript::new(ENCRYPTION_PROOF_LABEL);
    let mut dealer = ZKDealer::new();
    let gens = PedersenGens::default();

    pp.update_dealer(&mut dealer);
    let challenge = dealer.dealer_scalar_challenge(b"finalize");
    verifier.verifier_verify(&gens, &challenge, pp, p)
}

#[cfg(test)]
mod tests {
    extern crate wasm_bindgen_test;
    use super::*;
    use crate::asset_proofs::correctness_proof::{CorrectnessProver, CorrectnessVerifier};
    use crate::asset_proofs::{CommitmentWitness, ElgamalSecretKey};
    use rand::{rngs::StdRng, SeedableRng};
    use wasm_bindgen_test::*;

    const SEED_1: [u8; 32] = [42u8; 32];

    #[test]
    #[wasm_bindgen_test]
    fn test_single_proof() {
        // todo: turn this into a helper function
        let mut rng = StdRng::from_seed(SEED_1);
        let secret_value = 42u32;
        let rand_blind = Scalar::random(&mut rng);

        // Make sure the second part of the elgamal encryption is the same as the commited value in the range proof.
        let w = CommitmentWitness::new(secret_value, rand_blind).unwrap();
        let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let elg_pub = elg_secret.get_public_key();
        let cipher = elg_pub.encrypt(&w);

        let mut prover = CorrectnessProver::new(&elg_pub, &w);
        let mut verifier = CorrectnessVerifier::new(&secret_value, &elg_pub, &cipher);

        let (partial_proof, proof) = single_property_prover(&mut prover, &mut rng);

        assert!(single_property_verifier(
            &mut verifier,
            &partial_proof,
            &proof
        ));
    }
}
