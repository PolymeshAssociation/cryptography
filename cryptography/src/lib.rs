pub mod claim_proofs;
pub mod pedersen_commitments;

use rand::{Rng};
use claim_proofs::{ ScopeClaimData, CDDClaimData, RawData };

pub fn random_claim<R: Rng + ?Sized>(rng: &mut R) -> (CDDClaimData, ScopeClaimData) {
    let mut investor_did = RawData::default();
    let mut investor_unique_id = RawData::default();
    let mut scope_did = RawData::default();

    rng.fill_bytes(&mut investor_did.0);
    rng.fill_bytes(&mut investor_unique_id.0);
    rng.fill_bytes(&mut scope_did.0);

    (
        CDDClaimData {
            investor_did,
            investor_unique_id,
        },
        ScopeClaimData {
            scope_did,
            investor_unique_id,
        },
    )
}
