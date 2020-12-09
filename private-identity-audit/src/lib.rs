//! pial is the library that implements the private identity audit protocol
//! of the PIAL, as defined in the section TODO of the whitepaper TODO.
//!

#![cfg_attr(not(feature = "std"), no_std)]
#![feature(iterator_fold_self)]

mod errors;
mod proofs;
mod prover;
mod verifier;
use blake2::{Blake2b, Digest};
use cryptography_core::curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use errors::Fallible;
use proofs::{FinalResponse, InitialMessage, Secrets};
use rand_core::{CryptoRng, RngCore};
//#[cfg(feature = "serde")]
//use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// That `ensure` does not transform into a string representation like `failure::ensure` is doing.
#[allow(unused_macros)]
macro_rules! ensure {
    ($predicate:expr, $context_selector:expr) => {
        if !$predicate {
            return Err($context_selector.into());
        }
    };
}

/// Helper macro to assert that `predicate` is an `Error::from( $err)`.
#[allow(unused_macros)]
macro_rules! assert_err {
    ($predicate:expr, $err:expr) => {
        assert_eq!($predicate.expect_err("Error expected").kind(), &$err);
    };
}

/// This is a security parameter. The larger the value, the higher the security guarantees.
/// This value is used to pad the set of private unique ids set such that the encrypted set,
/// has at least this many element. As a result when a CDD Provider proves that it holds an
/// element of a set, PUIS can guess that element with probability 1/the_size_of_the_padded_set.
pub const SET_SIZE_ANONYMITY_PARAM: usize = 100_000;

pub type PrivateUIDs = Vec<Uuid>;

pub type EncryptedUIDs = Vec<RistrettoPoint>;

pub struct InvestorID {
    did: Scalar,
    uid: Scalar,
}

pub struct Proofs {
    cdd_id_proof: InitialMessage,
    cdd_id_second_half_proof: InitialMessage,
    uid_commitment_proof: InitialMessage,
}

pub struct ProverFinalResponse {
    cdd_id_proof_response: FinalResponse,
    cdd_id_second_half_proof_response: FinalResponse,
    uid_commitment_proof_response: FinalResponse,
}

pub struct ProverSecrets {
    cdd_id_proof_secrets: Secrets,
    cdd_id_second_half_proof_secrets: Secrets,
    uid_commitment_proof_secrets: Secrets,
    rand: Scalar,
}

pub struct VerifierSecrets {
    rand: Scalar,
}

/// Modified version of `slice_to_scalar` of Confidential Identity Library.
/// Creates a scalar from a UUID.
pub fn uuid_to_scalar(uuid: Uuid) -> Scalar {
    let mut hash = [0u8; 64];
    hash.copy_from_slice(Blake2b::digest(uuid.as_bytes()).as_slice());
    Scalar::from_bytes_mod_order_wide(&hash)
}

pub trait PrivateSetGenerator {
    /// This is called by PUIS to create an encrypted version of the set of all unique
    /// identity IDs (uID).
    ///
    /// # Arguments
    /// * `private_unique_identifiers`: A list of UUIDs that represent the private set of
    ///   unique identifiers.
    /// * `min_set_size`: An optional parameter to override the default value of
    /// `SET_SIZE_ANONYMITY_PARAM`.
    fn generate_encrypted_unique_ids<T: RngCore + CryptoRng>(
        &self,
        private_unique_identifiers: PrivateUIDs,
        min_set_size: Option<usize>,
        rng: &mut T,
    ) -> Fallible<(VerifierSecrets, EncryptedUIDs, Scalar)>;
}

pub trait ProofGenerator {
    fn generate_membership_proof<T: RngCore + CryptoRng>(
        investor: InvestorID,
        rng: &mut T,
    ) -> Fallible<(ProverSecrets, Proofs, RistrettoPoint, RistrettoPoint)>;
}
pub trait ChallengeResponder {
    fn generate_challenge_response<T: RngCore + CryptoRng>(
        secrets: ProverSecrets,
        encrypted_uids: EncryptedUIDs,
        challenge: Scalar,
        rng: &mut T,
    ) -> Fallible<(ProverFinalResponse, EncryptedUIDs)>;
}

pub trait ProofVerifier {
    fn verify_membership_proof(
        initial_message: Proofs,
        final_response: ProverFinalResponse,
        challenge: Scalar,
        cdd_id: RistrettoPoint,
        committed_cdd_id: RistrettoPoint,
        committed_cdd_id_second_half: RistrettoPoint,
        verifier_secrets: VerifierSecrets,
        re_encrypted_uids: EncryptedUIDs,
    ) -> Fallible<()>;
}

#[cfg(test)]
mod tests {
    use crate::{
        prover::{generate_bliding_factor, FinalProver, InitialProver},
        uuid_to_scalar,
        verifier::{gen_random_uuids, Verifier, VerifierSetGenerator},
        ChallengeResponder, InvestorID, PrivateSetGenerator, ProofGenerator, ProofVerifier,
    };
    use confidential_identity::pedersen_commitments::PedersenGenerators;
    use cryptography_core::curve25519_dalek::scalar::Scalar;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn test_success_end_to_end() {
        let mut rng = StdRng::from_seed([10u8; 32]);
        let pg = PedersenGenerators::default();

        // Prover generates and sends the initial message.
        let private_uid_set = gen_random_uuids(100, &mut rng);
        let investor = InvestorID {
            uid: uuid_to_scalar(private_uid_set[0]),
            did: Scalar::random(&mut rng),
        };
        let cdd_id = pg.commit(&[
            investor.uid,
            investor.did,
            generate_bliding_factor(investor.uid, investor.did),
        ]);
        let (prover_secrets, proofs, committed_cdd_id, committed_cdd_id_second_half) =
            InitialProver::generate_membership_proof(investor, &mut rng).unwrap();

        // Prover sends `proofs` and Verifier returns a list of 10 uids and the challenge.
        let (verifier_secrets, encrypted_uids, challenge) = VerifierSetGenerator
            .generate_encrypted_unique_ids(private_uid_set, Some(100), &mut rng)
            .unwrap();

        // Verifier sends the encrytped_uids and the challenge to the Prover.
        let (prover_response, re_encrypted_uids) = FinalProver::generate_challenge_response(
            prover_secrets,
            encrypted_uids,
            challenge,
            &mut rng,
        )
        .unwrap();

        // Verifier verifies the proofs and check membership.
        Verifier::verify_membership_proof(
            proofs,
            prover_response,
            challenge,
            cdd_id,
            committed_cdd_id,
            committed_cdd_id_second_half,
            verifier_secrets,
            re_encrypted_uids,
        )
        .unwrap();
    }
}
