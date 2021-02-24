//! The `claim_proofs` library contains API for generating
//! claim proofs and verifying them as part of the
//! Asset Granularity Unique Identity project.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

pub use claim_proofs::{CddClaimData, CddId, ScopeClaimData, ScopeClaimProof, ScopeClaimProofData};
pub use curve25519_dalek::{self, ristretto::CompressedRistretto, scalar::Scalar};
use rand_core::{CryptoRng, RngCore};
pub use schnorrkel;

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
    /// CDD_ID = PedersenCommitment(INVESTOR_DID, INVESTOR_UNIQUE_ID, [INVESTOR_DID | INVESTOR_UNIQUE_ID]) \
    ///
    /// # Inputs
    /// * `cdd_claim` is the CDD claim from which to generate the CDD_ID
    ///
    /// # Output
    /// The Pedersen commitment result.
    fn create_cdd_id(cdd_claim: &CddClaimData) -> CddId;
}

pub trait InvestorTrait {
    fn create_scope_claim_proof<R: RngCore + CryptoRng>(
        cdd_claim: &CddClaimData,
        scope_claim: &ScopeClaimData,
        rng: &mut R,
    ) -> ScopeClaimProof;
}

pub trait VerifierTrait {
    fn verify_scope_claim_proof(
        proof: &ScopeClaimProof,
        scope_claim: &ScopeClaimData,
    ) -> Result<(), ()>;
}

mod claim_proofs;
pub mod mocked;
pub mod uuid;
