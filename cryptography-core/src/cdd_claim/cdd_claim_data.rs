use super::pedersen_commitments::{generate_blinding_factor, generate_pedersen_commit};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Create a scalar from a slice of data.
fn slice_to_scalar(data: &[u8]) -> Scalar {
    use blake2::{Blake2b, Digest};
    let mut hash = [0u8; 64];
    hash.copy_from_slice(Blake2b::digest(data).as_slice());
    Scalar::from_bytes_mod_order_wide(&hash)
}

/// The data needed to generate a CDD ID.
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CddClaimData {
    pub investor_did: Scalar,
    pub investor_unique_id: Scalar,
}

impl CddClaimData {
    /// Create a CDD Claim Data object from slices of data.
    pub fn new(investor_did: &[u8], investor_unique_id: &[u8]) -> Self {
        CddClaimData {
            investor_did: slice_to_scalar(investor_did),
            investor_unique_id: slice_to_scalar(investor_unique_id),
        }
    }
}

/// Compute the CDD_ID. \
/// CDD_ID = PedersenCommitment(INVESTOR_DID, INVESTOR_UNIQUE_ID, [INVESTOR_DID | INVESTOR_UNIQUE_ID]) \
///
/// # Inputs
/// * `cdd_claim` is the CDD claim from which to generate the CDD_ID
///
/// # Output
/// The Pedersen commitment result.
pub fn compute_cdd_id(cdd_claim: &CddClaimData) -> RistrettoPoint {
    generate_pedersen_commit(cdd_claim.investor_did, cdd_claim.investor_unique_id)
}

pub fn get_blinding_factor(cdd_claim: &CddClaimData) -> Scalar {
    generate_blinding_factor(cdd_claim.investor_did, cdd_claim.investor_unique_id)
}
