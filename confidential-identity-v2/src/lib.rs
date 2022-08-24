//! The `claim_proofs` library contains API for generating
//! claim proofs and verifying them as part of the
//! Asset Granularity Unique Identity project.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

pub use claim_proofs::{CddClaimData, CddId, ScopeClaimData, ScopeClaimProof, ScopeClaimProofData};
pub use confidential_identity_core;
pub use curve25519_dalek::{
    self,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use errors::Fallible;
use rand_core::{CryptoRng, RngCore};

pub fn random_claim<R: RngCore + CryptoRng>(rng: &mut R) -> (CddClaimData, ScopeClaimData) {
    let investor_unique_id = Scalar::random(rng);
    (
        CddClaimData {
            investor_did: Scalar::random(rng),
            investor_unique_id,
        },
        ScopeClaimData {
            scope_did: Scalar::random(rng),
            investor_unique_id,
        },
    )
}

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

pub trait ProviderTrait {
    /// Compute the CDD_ID. \
    /// CDD_ID = PedersenCommitment(INVESTOR_DID, INVESTOR_UNIQUE_ID, [INVESTOR_DID | INVESTOR_UNIQUE_ID])
    ///
    /// # Arguments
    /// * `cdd_claim` is the CDD claim from which to generate the CDD_ID
    ///
    /// # Output
    /// * The Pedersen commitment result.
    fn create_cdd_id(cdd_claim: &CddClaimData) -> CddId;
}

pub trait InvestorTrait {
    /// Creates a SCOPE_ID and then generates two proofs: \
    /// 1. Prove that the scope id has the following form: INVESTOR_UNIQUE_ID * Hash(SCOPE_DID) \
    /// 2. Prove that the cdd_id and the scope_id share the same INVESTOR_UNIQUE_ID
    ///
    /// # Arguments
    /// * `cdd_claim` is the CDD claim from which the CDD_ID was generated.
    /// * `scope_claim` is the Scope claim from which the SCOPE_ID will be generated.
    ///
    /// # Output
    /// * The proofs.
    fn create_scope_claim_proof<R: RngCore + CryptoRng>(
        cdd_claim: &CddClaimData,
        scope_claim: &ScopeClaimData,
        rng: &mut R,
    ) -> ScopeClaimProof;
}

pub trait VerifierTrait {
    /// Verifies the two proofs and if any of them fail, returns an error.
    ///
    /// # Arguments
    /// * `proof`: the proofs obtained from the call to `create_scope_claim_proof`.
    /// * `investor_did`: the INVESTOR_DID.
    /// * `scope_did`: is the SCOPE_DID.
    /// * `cdd_id`: the CDD_ID.
    ///
    /// # Errors
    /// * `ZkpError`: If the scope id and cdd id do not match.
    /// * `SignatureError`: If the scope id is not wellformed.
    fn verify_scope_claim_proof(
        proof: &ScopeClaimProof,
        investor_did: &Scalar,
        scope_did: &Scalar,
        cdd_id: &CddId,
    ) -> Fallible<()>;
}

pub mod claim_proofs;
pub mod errors;
pub mod mocked;
mod sign;
pub mod uuid;
