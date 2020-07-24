//! The `claim_proofs` library contains API for generating
//! claim proofs and verifying them as part of the
//! Asset Granularity Unique Identity project.

pub mod claim_proofs;
pub use claim_proofs::{
    build_scope_claim_proof_data, compute_cdd_id, compute_scope_id, CDDClaimData, ProofKeyPair,
    ProofPublicKey, RawData, ScopeClaimData,
};

pub mod pedersen_commitments;
pub use pedersen_commitments::PedersenGenerators;

use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};

pub fn random_claim<R: RngCore + CryptoRng + ?Sized>(
    rng: &mut R,
) -> (CDDClaimData, ScopeClaimData) {
    let mut investor_did = RawData::default();
    let mut investor_unique_id = RawData::default();
    let mut scope_did = RawData::default();

    rng.fill_bytes(&mut investor_did.0);
    rng.fill_bytes(&mut investor_unique_id.0);
    rng.fill_bytes(&mut scope_did.0);

    let investor_unique_id = Scalar::from_bits(investor_unique_id.0);

    (
        CDDClaimData {
            investor_did: Scalar::from_bits(investor_did.0),
            investor_unique_id,
        },
        ScopeClaimData {
            scope_did: Scalar::from_bits(scope_did.0),
            investor_unique_id,
        },
    )
}
