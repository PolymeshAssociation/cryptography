//! pial is the library that implements the private identity audit protocol
//! of the PIAL, as defined in the section TODO of the whitepaper TODO.

#![cfg_attr(not(feature = "std"), no_std)]

mod errors;
mod verifier;
use cryptography_core::curve25519_dalek::ristretto::RistrettoPoint;
use errors::Fallible;
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
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
pub struct MultipartCDDId {
    part1: RistrettoPoint,
    part2: RistrettoPoint,
}
pub struct Proof();

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
    ) -> Fallible<EncryptedUIDs>;
}

pub trait ProofGenerator {
    fn generate_membership_proof<T: RngCore + CryptoRng>(
        cdd_id: MultipartCDDId,
        encrypted_uids: EncryptedUIDs,
        rng: T,
    ) -> Fallible<Proof>;
}

pub trait ProofVerifier {
    fn verify_membership_proof(proof: Proof, encrypted_uids: EncryptedUIDs) -> Fallible<()>;
}
