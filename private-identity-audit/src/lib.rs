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

/// The initial private set of PUIS.
pub type PrivateUIDs = Vec<Scalar>;

/// The encrypted and padded version of the private set of PUIS.
pub type EncryptedUIDs = Vec<RistrettoPoint>;

/// The Zero-Knowledge challenge.
pub type Challenge = Scalar;

/// Committed CDD ID.
pub type CommittedCDDID = RistrettoPoint;

/// Committed version of the second half CDD ID.
pub type CommittedSecondHalfCDDID = RistrettoPoint;

/// Holds the information about the investor. The DID is public while the uID is private
/// to the CDD Provider.
pub struct InvestorID {
    did: Scalar,
    uid: Scalar,
}

/// Holds the initial messages in the Zero-Knowledge Proofs sent by CDD Provider.
pub struct Proofs {
    cdd_id_proof: InitialMessage,
    cdd_id_second_half_proof: InitialMessage,
    uid_commitment_proof: InitialMessage,
}

/// Holds the CDD Provider's response to the PUIS challenge.
pub struct ProverFinalResponse {
    cdd_id_proof_response: FinalResponse,
    cdd_id_second_half_proof_response: FinalResponse,
    uid_commitment_proof_response: FinalResponse,
}

/// Holds CDD Provider secret data.
pub struct ProverSecrets {
    cdd_id_proof_secrets: Secrets,
    cdd_id_second_half_proof_secrets: Secrets,
    uid_commitment_proof_secrets: Secrets,
    rand: Scalar,
}

/// Holds PUIS secret data.
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

/// Represents the first leg of the protocol from CDD Provider to PUIS.
pub trait ProofGenerator {
    /// This is called by the CDD Provider in the first step of the protocol to generate
    /// initial ZKP proofs that CDD Provider knows a `uID` and a `DID` such that
    ///
    /// `CDD_ID = g^uID * h^DID * f^{hash(uID, DID)}` for some pre-determined `g, h, and f`.
    ///
    /// # Arguments
    /// * `investor`: Holds the uID and DID of the investor.
    /// * `rng`: Cryptographically secure random number generator.
    ///
    /// # Outputs
    /// * `ProverSecrets`: the secret values of PUIS. These are needed in the later steps of
    ///    the protocol and should be stored locally.
    /// * `Proofs`: The initial messages of ZKPs.
    /// * `CommittedCDDID`: committed version of CDD ID.
    /// * `CommittedSecondHalfCDDID`: corresponds to the committed version of
    ///   `h^DID * f^{hash(uID, DID)}`.
    fn generate_initial_proofs<T: RngCore + CryptoRng>(
        investor: InvestorID,
        rng: &mut T,
    ) -> Fallible<(
        ProverSecrets,
        Proofs,
        CommittedCDDID,
        CommittedSecondHalfCDDID,
    )>;
}

/// Represents the second leg of protocol from PUIS to CDD Provider.
pub trait ChallengeGenerator {
    /// This is called by PUIS to create an encrypted version of the set of all unique
    /// identity IDs (uID). Moreover, it generates the random ZKP challenge.
    ///
    /// # Arguments
    /// * `private_unique_identifiers`: A list of Scalars that represent the private set of
    ///   unique identifiers. Call `uuid_to_scalar` to convert uIDs to Scalar properly.
    /// * `min_set_size`: An optional parameter to override the default value of
    /// `SET_SIZE_ANONYMITY_PARAM`.
    /// * `rng`: Cryptographically secure random number generator.
    ///
    /// # Outputs
    /// * `VerifierSecrets`: the secret values of PUIS. These are needed in later steps of
    ///    the protocol and need to be stored locally.
    /// * `EncryptedUIDs`: the padded, encrypted, and shuffled set of uIDs. These should
    ///    be sent to CDD Provider.
    /// * `Challenge`: the ZKP random challenge.
    fn generate_encrypted_set_and_challenge<T: RngCore + CryptoRng>(
        &self,
        private_unique_identifiers: PrivateUIDs,
        min_set_size: Option<usize>,
        rng: &mut T,
    ) -> Fallible<(VerifierSecrets, EncryptedUIDs, Challenge)>;
}

/// Represents the third leg of the protocol from CDD Provider to PUIS.
pub trait ChallengeResponder {
    /// This is called by CDD Provider to generate the ZKP response of the challenge
    /// and provide the proof of membership.
    ///
    /// # Arguments
    /// * `secrets`: CDD Provider secrets that were generated in the first step of the protocol.
    /// * `encrypted_uids`: the list of encrypted uIDs received from PUIS.
    /// * `challenge`: ZKP challenge received from PUIS.
    /// * `rng`: Cryptographically secure random number generator.
    ///
    /// # Outputs
    /// * `ProverFinalResponse`: The ZKP response.
    /// * `EncryptedUIDs`: These re-encrypted uIDs form part of the proof of membership.
    fn generate_challenge_response<T: RngCore + CryptoRng>(
        secrets: ProverSecrets,
        encrypted_uids: EncryptedUIDs,
        challenge: Scalar,
        rng: &mut T,
    ) -> Fallible<(ProverFinalResponse, EncryptedUIDs)>;
}

/// Represents the last step of the protocol were PUIS verifies the proofs.
pub trait ProofVerifier {
    /// PUIS verifies both the ZKP proofs around CDD_ID and the proof of membership.
    ///
    /// # Arguments
    /// * `initial_message`: Initial messages of ZKP proofs of CDD_ID.
    /// * `final_response`: Final responses of ZKP proofs of CDD_ID.
    /// * `challenge`: The ZKP challenge generated by PUIS.
    /// * `cdd_id`: The CDD_ID read from the chain.
    /// * `committed_cdd_id`: The committed CDD_ID received from CDD Provider.
    /// * `committed_cdd_id_second_half`: The committed version of the second half of CDD_ID
    ///    received from CDD Provider.
    /// * `verifier_secrets`: The PUIS secrets generated in the second step of the protocol.
    /// * `rng`: Cryptographically secure random number generator.
    fn verify_proofs(
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
        ChallengeGenerator, ChallengeResponder, InvestorID, ProofGenerator, ProofVerifier,
    };
    use confidential_identity::pedersen_commitments::PedersenGenerators;
    use cryptography_core::curve25519_dalek::scalar::Scalar;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn test_success_end_to_end() {
        let mut rng = StdRng::from_seed([10u8; 32]);
        let pg = PedersenGenerators::default();

        // Private input of the Verifier.
        let private_uid_set: Vec<Scalar> = gen_random_uuids(100, &mut rng)
            .into_iter()
            .map(|uuid| uuid_to_scalar(uuid))
            .collect();

        // Verifier shares one of its uids with the Prover.
        let investor = InvestorID {
            uid: private_uid_set[0],
            did: Scalar::random(&mut rng),
        };

        // Prover generates cdd_id and places it on the chain.
        let cdd_id = pg.commit(&[
            investor.uid,
            investor.did,
            generate_bliding_factor(investor.uid, investor.did),
        ]);

        // P -> V: Prover generates and sends the initial message.
        let (prover_secrets, proofs, committed_cdd_id, committed_cdd_id_second_half) =
            InitialProver::generate_initial_proofs(investor, &mut rng).unwrap();

        // V -> P: Prover sends `proofs` and Verifier returns a list of 10 uids and the challenge.
        let (verifier_secrets, encrypted_uids, challenge) = VerifierSetGenerator
            .generate_encrypted_set_and_challenge(private_uid_set, Some(100), &mut rng)
            .unwrap();

        // P -> V: Verifier sends the encrypted_uids and the challenge to the Prover.
        let (prover_response, re_encrypted_uids) = FinalProver::generate_challenge_response(
            prover_secrets,
            encrypted_uids,
            challenge,
            &mut rng,
        )
        .unwrap();

        // Only V: Verifier verifies the proofs and check membership.
        Verifier::verify_proofs(
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
