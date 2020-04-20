//! The `encryption_proofs` library contains API for generating
//! and verifying proofs of various properties of an encrypted
//! value proofs as part of the MERCAT
//! (Mediated, Encrypted, Reversible, SeCure Asset Transfers)
//! Project.
//!
//! For a full description of these proofs see section 5 of the
//! whitepaper. [todo: Add a link to the whitepaper.]
//!
//! Sigma protocols are a 3 round interactive protocols where
//! the prover convinces the verifier that a statement is true.
//!
//! Prover                         Dealer
//! - selects some random values
//!                       -->  [partial proof]
//!                            - records the partial proof
//!                            - deterministically calculates
//!                              a random challenge
//!           [challenge] <--
//! - generates a proof from the
//!   selected random values and
//!   the challenge
//!                       -->  [proof]
//!
//! Now given the `partial proof` and the proof any verifier
//! can verify the prover's statement. Verifier uses the dealer
//! to generate the challenge:
//!
//! Verifier                       Dealer
//! - receives the [partial proof, proof]
//!                       -->  [partial proof]
//!                            - records the partial proof
//!                            - deterministically calculates
//!                              a random challenge
//!           [challenge] <--
//! - verifies the proof
//!
//! The role of the dealer can be eliminated if the challenge
//! could be generated deterministically but unpredictably from
//! the `partial proof`. This technique is known as the
//! Fiat-Shamir huristic.

use crate::asset_proofs::AssetProofError;
use bulletproofs::PedersenGens;
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};

/// The domain label for the encryption proofs.
pub const ENCRYPTION_PROOFS_LABEL: &[u8] = b"PolymathEncryptionProofs";
/// The domain label for the challenge.
pub const ENCRYPTION_PROOFS_CHALLENGE_LABEL: &[u8] = b"PolymathEncryptionProofsChallenge";

// ------------------------------------------------------------------------
// Dealer Implementation
// ------------------------------------------------------------------------

/// The role of a dealer in a non-interactive zero knowledge proof system
/// is to provide a challenge without revealing any information about the
/// secrets while protecting against Chosen Message attacks.
///
/// ZKPDealer implements the Fiat-Shamir huristic via Merlin transcripts.
pub struct ZKPDealer {
    transcript: Transcript,
}

impl ZKPDealer {
    pub fn new(label: &'static [u8]) -> Self {
        let t = Transcript::new(label);
        ZKPDealer { transcript: t }
    }

    /// If the inputted message is not trivial append it to the Dealer's
    /// state.
    /// # Inputs
    /// * `label`   a domain label for the point to append.
    /// * `message` a compressed Ristretto point.
    ///
    /// # Output
    /// Ok on success, or an error on failure.
    pub fn dealer_append_validated_point(
        &mut self,
        label: &'static [u8],
        message: &CompressedRistretto,
    ) -> Result<(), AssetProofError> {
        use curve25519_dalek::traits::IsIdentity;
        if message.is_identity() {
            Err(AssetProofError::VerificationError)
        } else {
            Ok(self.transcript.append_message(label, message.as_bytes()))
        }
    }

    pub fn dealer_append_message(&mut self, message: &'static [u8]) {
        self.transcript.append_message(b"message", message)
    }

    /// Get the protocol's challenge.
    ///
    /// # Inputs
    /// * `label` a domain label.
    ///
    /// # Output
    /// A scalar challenge.
    pub fn dealer_scalar_challenge(&mut self, label: &'static [u8]) -> ZKPChallenge {
        let mut buf = [0u8; 64];
        self.transcript.challenge_bytes(label, &mut buf);

        ZKPChallenge {
            x: Scalar::from_bytes_mod_order_wide(&buf),
        }
    }
}

/// A trait that is used to update the dealer with the partial proof
/// that results from the first round of the protocol.
pub trait UpdateZKPDealer {
    fn update_dealer(&self, d: &mut ZKPDealer) -> Result<(), AssetProofError>;
}

// ------------------------------------------------------------------------
// Sigma Protocol's Prover and Verifier Interfaces
// ------------------------------------------------------------------------

// todo better names?
/// A scalar challenge.
pub struct ZKPChallenge {
    pub x: Scalar,
}

/// The interface for a 3-Sigma protocol.
/// Abstracting the prover and verifier roles.
///
/// Each proof needs to use the same `ZKPartialProof` and `ZKProof` types.
/// Each `ZKPartialProof` needs to implement the `UpdateZKPDealer` trait.
pub trait AssetProofProver {
    type ZKPartialProof: UpdateZKPDealer;
    type ZKProof;

    /// First round of the Sigma protocol. Prover generates a partial proof.
    ///
    /// # Inputs
    /// `pc_gens` The Pedersen Generators used for the Elgamal encryption.
    /// `rng`     An RNG.
    ///
    /// # Output
    /// A partial proof.
    fn generate_partial_proof<T: RngCore + CryptoRng>(
        &mut self,
        pc_gens: &PedersenGens,
        rng: &mut T,
    ) -> Self::ZKPartialProof;

    /// Third round of the Sigma protocol. Prover receives a challenge and
    /// uses it to generate the proof.
    ///
    /// # Inputs
    /// `challenge` The scalar challenge, generated by the Dealer.
    ///
    /// # Output
    /// A proof.
    fn apply_challenge(&self, challenge: &ZKPChallenge) -> Self::ZKProof;
}

pub trait AssetProofVerifier {
    type ZKPartialProof: UpdateZKPDealer;
    type ZKProof;

    /// Forth round of the Sigma protocol. Verifier receives the partial proof
    /// and the proof, and verifies them.
    ///
    /// # Inputs
    /// `pc_gens`       The Pedersen Generators used for the Elgamal encryption.
    /// `challenge`     The scalar challenge, generated by the Dealer.
    /// `partial_proof` The partial proof, generated by the Prover.
    /// `proof`         The proof, generated by the Prover.
    ///
    /// # Output
    /// Ok on success, or an error on failure.
    fn verify(
        &self,
        pc_gens: &PedersenGens,
        challenge: &ZKPChallenge,
        partial_proof: &Self::ZKPartialProof,
        proof: &Self::ZKProof,
    ) -> Result<(), AssetProofError>;
}

// ------------------------------------------------------------------------
// Non-Interactive Zero Knowledge Proofs API
// ------------------------------------------------------------------------

/// The non-interactive implementation of the protocol for a single
/// encryption proof's prover role.
///
/// # Inputs
/// `prover` Any prover that implements the `AssetProofProver` trait.
/// `rng`    An RNG.
///
/// # Outputs
/// A partial proof and a proof on success, or failure on an error.
pub fn single_property_prover<T: RngCore + CryptoRng, Prover: AssetProofProver>(
    prover: &mut Prover,
    rng: &mut T,
) -> Result<(Prover::ZKPartialProof, Prover::ZKProof), AssetProofError> {
    let mut dealer = ZKPDealer::new(ENCRYPTION_PROOFS_LABEL);
    let gens = PedersenGens::default();
    let message = prover.generate_partial_proof(&gens, rng);

    message.update_dealer(&mut dealer)?;

    let challenge = dealer.dealer_scalar_challenge(ENCRYPTION_PROOFS_CHALLENGE_LABEL);

    Ok((message, prover.apply_challenge(&challenge)))
}

/// The non-interactive implementation of the protocol for a single
/// encryption proof's verifier role.
///
/// # Inputs
/// `verifier` Any verifier that implements the `AssetProofVerifier` trait.
/// `rng`      An RNG.
///
/// # Outputs
/// Ok on success, or failure on error.
pub fn single_property_verifier<Verifier: AssetProofVerifier>(
    verifier: &Verifier,
    partial_proof: Verifier::ZKPartialProof,
    proof: Verifier::ZKProof,
) -> Result<(), AssetProofError> {
    verify_multiple_encryption_properties(&[verifier], (&[partial_proof], &[proof]))
}

/// The non-interactive implementation of the protocol for multiple provers
/// which use the same challenge. In this scenario the Dealer combines all
/// the partial proofs to generate a single challenge.
///
/// # Inputs
/// `provers` An array of provers that implement the `AssetProofProver` trait.
/// `rng`     An RNG.
///
/// # Outputs
/// An array of partial proofs and proofs on success, or failure on error.
pub fn prove_multiple_encryption_properties<T: RngCore + CryptoRng, Prover: AssetProofProver>(
    provers: &mut Vec<Prover>,
    rng: &mut T,
) -> Result<(Vec<Prover::ZKPartialProof>, Vec<Prover::ZKProof>), AssetProofError> {
    let mut dealer = ZKPDealer::new(ENCRYPTION_PROOFS_LABEL);
    let gens = PedersenGens::default();

    let partial_proofs: Vec<_> = provers
        .iter_mut()
        .map(|prover| prover.generate_partial_proof(&gens, rng))
        .collect();

    // Combine all the partial proofs to create a single challenge.
    partial_proofs
        .iter()
        .map(|partial_proof| partial_proof.update_dealer(&mut dealer))
        .collect::<Result<(), _>>()?;

    let challenge = dealer.dealer_scalar_challenge(ENCRYPTION_PROOFS_CHALLENGE_LABEL);

    let proofs: Vec<_> = provers
        .iter()
        .map(|p| p.apply_challenge(&challenge))
        .collect();

    Ok((partial_proofs, proofs))
}

/// The non-interactive implementation of the protocol for multiple verifiers
/// which use the same challenge. In this scenario the Dealer combines all
/// the partial proofs to generate a single challenge.
///
/// # Inputs
/// `verifiers` An array of verifiers that implement the `AssetProofVerifier` trait.
/// `rng`       An RNG.
///
/// # Outputs
/// Ok on success, or failure on error.
pub fn verify_multiple_encryption_properties<Verifier: AssetProofVerifier>(
    verifiers: &[&Verifier],
    (partial_proofs, proofs): (&[Verifier::ZKPartialProof], &[Verifier::ZKProof]),
) -> Result<(), AssetProofError> {
    if partial_proofs.len() != proofs.len() || verifiers.len() != proofs.len() {
        return Err(AssetProofError::VerificationError);
    }

    let mut dealer = ZKPDealer::new(ENCRYPTION_PROOFS_LABEL);
    let gens = PedersenGens::default();

    // Combine all the partial proofs to create a single challenge.
    partial_proofs
        .iter()
        .map(|partial_proof| partial_proof.update_dealer(&mut dealer))
        .collect::<Result<(), _>>()?;

    let challenge = dealer.dealer_scalar_challenge(ENCRYPTION_PROOFS_CHALLENGE_LABEL);
    for i in 0..verifiers.len() {
        verifiers[i].verify(&gens, &challenge, &partial_proofs[i], &proofs[i])?;
    }

    Ok(())
}

// ------------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    extern crate wasm_bindgen_test;
    use super::*;
    use crate::asset_proofs::correctness_proof::{CorrectnessProver, CorrectnessVerifier};
    use crate::asset_proofs::{CommitmentWitness, ElgamalSecretKey};
    use rand::{rngs::StdRng, SeedableRng};
    use rand_core::{CryptoRng, RngCore};
    use wasm_bindgen_test::*;

    const SEED_1: [u8; 32] = [42u8; 32];
    const SEED_2: [u8; 32] = [7u8; 32];

    fn create_correctness_proof_objects_helper<T: RngCore + CryptoRng>(
        plain_text: u32,
        rng: &mut T,
    ) -> (CorrectnessProver, CorrectnessVerifier) {
        let rand_blind = Scalar::random(rng);
        let w = CommitmentWitness::new(plain_text, rand_blind).unwrap();

        let elg_secret = ElgamalSecretKey::new(Scalar::random(rng));
        let elg_pub = elg_secret.get_public_key();
        let cipher = elg_pub.encrypt(&w);

        let prover = CorrectnessProver::new(&elg_pub, &w);
        let verifier = CorrectnessVerifier::new(&plain_text, &elg_pub, &cipher);

        (prover, verifier)
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_single_proof() {
        let mut rng = StdRng::from_seed(SEED_1);
        let secret_value = 42u32;

        let (prover, verifier) = create_correctness_proof_objects_helper(secret_value, &mut rng);
        let mut cloned_prover = prover.clone();
        let (partial_proof, proof) = single_property_prover(&mut cloned_prover, &mut rng).unwrap();

        assert!(single_property_verifier(&verifier, partial_proof, proof).is_ok());
    }

    #[test]
    #[wasm_bindgen_test]
    fn multiple_proofs() {
        let mut rng = StdRng::from_seed(SEED_2);
        let secret_value1 = 6u32;
        let secret_value2 = 7u32;

        let (prover1, verifier1) = create_correctness_proof_objects_helper(secret_value1, &mut rng);
        let (prover2, verifier2) = create_correctness_proof_objects_helper(secret_value2, &mut rng);

        let mut provers_vec = Vec::new();
        provers_vec.push(prover1);
        provers_vec.push(prover2);

        let (partial_proofs, proofs) =
            prove_multiple_encryption_properties(&mut provers_vec, &mut rng).unwrap();

        let mut verifiers_vec = Vec::new();
        verifiers_vec.push(&verifier1);
        verifiers_vec.push(&verifier2);
        assert!(
            verify_multiple_encryption_properties(&verifiers_vec, (&partial_proofs, &proofs))
                .is_ok()
        );
    }

    #[test]
    #[wasm_bindgen_test]
    fn detect_trivial_message() {
        let mut dealer = ZKPDealer::new(b"unit test");
        assert!(dealer.dealer_append_validated_point(b"identity", &CompressedRistretto::default()).is_err());
    }
}
