//! PIAL is the library that implements the private identity audit protocol
//! of the PIAL, as defined in the section TODO of the whitepaper TODO.
//!

#![cfg_attr(not(feature = "std"), no_std)]
#![feature(iterator_fold_self)]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

use codec::{Decode, Encode};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

mod errors;
#[macro_use]
mod macros;
mod proofs;
mod prover;
mod verifier;
use blake2::{Blake2b, Digest};
use cryptography_core::cdd_claim::{CddClaimData, CddId};
use cryptography_core::curve25519_dalek::scalar::Scalar;
use cryptography_core::dalek_wrapper::{PointData, ScalarData};
use errors::Fallible;
use proofs::{FinalResponse, InitialMessage, Secrets};
use rand_core::{CryptoRng, RngCore};
use sp_std::vec::Vec;
use uuid::Uuid;

/// This is a security parameter. The larger the value, the higher the security guarantees.
/// This value is used to pad the set of private unique ids such that the set,
/// has at least this many element. As a result when a CDD Provider proves that it holds an
/// element of a set, PUIS can guess that element with probability 1/the_size_of_the_padded_set.
pub const SET_SIZE_ANONYMITY_PARAM: usize = 100_000;

pub struct InitialProver;
pub struct FinalProver;

pub struct VerifierSetGenerator;
pub struct Verifier;

/// The initial private set of PUIS.
#[derive(PartialEq, Encode, Decode)]
pub struct PrivateUids(pub Vec<ScalarData>);

/// The committed and padded version of the private set of PUIS.
#[derive(Clone, Debug, PartialEq, Encode, Decode)]
pub struct CommittedUids(pub Vec<PointData>);

/// The Zero-Knowledge challenge.
#[derive(PartialEq, Encode, Decode)]
pub struct Challenge(pub ScalarData);

/// Holds the initial messages in the Zero-Knowledge Proofs sent by CDD Provider.
#[derive(Clone, Debug, PartialEq, Encode, Decode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Proofs {
    cdd_id_proof: InitialMessage,
    cdd_id_second_half_proof: InitialMessage,
    uid_commitment_proof: InitialMessage,
    /// Committed CDD ID. Corresponding to g^uID * h^DID * f^{hash(uID, DID)}`.
    a: PointData,
    /// Committed version of the second half CDD ID. Corresponding to (h^DID*f^{hash(uID, DID)})^r.
    b: PointData,
}

/// Holds the CDD Provider's response to the PUIS challenge.
#[derive(Clone, Encode, Decode, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ProverFinalResponse {
    cdd_id_proof_response: FinalResponse,
    cdd_id_second_half_proof_response: FinalResponse,
    uid_commitment_proof_response: FinalResponse,
}

/// Holds CDD Provider secret data.
#[derive(Clone, Encode, Decode)]
pub struct ProverSecrets {
    cdd_id_proof_secrets: Secrets,
    cdd_id_second_half_proof_secrets: Secrets,
    uid_commitment_proof_secrets: Secrets,
    rand: ScalarData,
}

/// Holds PUIS secret data.
#[derive(Clone, Encode, Decode)]
pub struct VerifierSecrets {
    rand: ScalarData,
}

/// Modified version of `slice_to_scalar` of Confidential Identity Library.
/// Creates a scalar from a UUID.
pub fn uuid_to_scalar(uuid: Uuid) -> ScalarData {
    let mut hash = [0u8; 64];
    hash.copy_from_slice(Blake2b::digest(uuid.as_bytes()).as_slice());
    Scalar::from_bytes_mod_order_wide(&hash).into()
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
    fn generate_initial_proofs<T: RngCore + CryptoRng>(
        investor: CddClaimData,
        rng: &mut T,
    ) -> Fallible<(ProverSecrets, Proofs)>;
}

/// Represents the second leg of the protocol from PUIS to CDD Provider.
pub trait ChallengeGenerator {
    /// This is called by PUIS to create an committed version of the set of all unique
    /// identity IDs (uID). Moreover, it generates the random ZKP challenge.
    ///
    /// # Arguments
    /// * `private_unique_identifiers`: A list of Scalars that represent the private set of
    ///   unique identifiers. Call `uuid_to_scalar` to convert uIDs to Scalar properly.
    /// * `min_set_size`: An optional parameter to override the default value of
    ///   `SET_SIZE_ANONYMITY_PARAM`.
    /// * `rng`: Cryptographically secure random number generator.
    ///
    /// # Outputs
    /// * `VerifierSecrets`: the secret values of PUIS. These are needed in later steps of
    ///    the protocol and need to be stored locally.
    /// * `CommittedUids`: the padded, committed, and shuffled set of uIDs. These should
    ///    be sent to CDD Provider.
    /// * `Challenge`: the ZKP random challenge.
    fn generate_committed_set_and_challenge<T: RngCore + CryptoRng>(
        private_unique_identifiers: PrivateUids,
        min_set_size: Option<usize>,
        rng: &mut T,
    ) -> Fallible<(VerifierSecrets, CommittedUids, Challenge)>;
}

/// Represents the third leg of the protocol from CDD Provider to PUIS.
pub trait ChallengeResponder {
    /// This is called by CDD Provider to generate the ZKP response of the challenge
    /// and provide the proof of membership.
    ///
    /// # Arguments
    /// * `secrets`: CDD Provider secrets that were generated in the first step of the protocol.
    /// * `committed_uids`: the list of committed uIDs received from PUIS.
    /// * `challenge`: ZKP challenge received from PUIS.
    /// * `rng`: Cryptographically secure random number generator.
    ///
    /// # Outputs
    /// * `ProverFinalResponse`: The ZKP response.
    /// * `CommittedUids`: These re-committed uIDs form part of the proof of membership.
    fn generate_challenge_response<T: RngCore + CryptoRng>(
        secrets: &ProverSecrets,
        committed_uids: &CommittedUids,
        challenge: &Challenge,
        rng: &mut T,
    ) -> Fallible<(ProverFinalResponse, CommittedUids)>;
}

/// Represents the last step of the protocol in which PUIS verifies the proofs.
pub trait ProofVerifier {
    /// PUIS verifies both the ZKP proofs around CDD ID and the proof of membership.
    ///
    /// # Arguments
    /// * `initial_message`: Initial messages of ZKP proofs of CDD ID.
    /// * `final_response`: Final responses of ZKP proofs of CDD ID.
    /// * `challenge`: The ZKP challenge generated by PUIS.
    /// * `cdd_id`: The CDD ID read from the chain.
    /// * `verifier_secrets`: The PUIS secrets generated in the second step of the protocol.
    /// * `rng`: Cryptographically secure random number generator.
    fn verify_proofs(
        initial_message: &Proofs,
        final_response: &ProverFinalResponse,
        challenge: &Challenge,
        cdd_id: &CddId,
        verifier_secrets: &VerifierSecrets,
        re_committed_uids: &CommittedUids,
    ) -> Fallible<()>;
}
