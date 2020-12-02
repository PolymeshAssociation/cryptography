//! The `claim_proofs` library contains API for generating
//! claim proofs and verifying them as part of the
//! Asset Granularity Unique Identity project.

pub mod claim_proofs;
pub use claim_proofs::{
    build_scope_claim_proof_data, compute_cdd_id, compute_scope_id, CddClaimData, ProofKeyPair,
    ProofPublicKey, ScopeClaimData, ScopeClaimProofData,
};

pub mod pedersen_commitments;
pub use pedersen_commitments::PedersenGenerators;

use curve25519_dalek::scalar::Scalar;
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

pub mod mocked;
pub mod uuid;
