use cryptography::claim_proofs::{compute_cdd_id, CddClaimData};
use curve25519_dalek::ristretto::RistrettoPoint;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

type InvestorDID = [u8; 32];

// Unique ID is a UUIDv4.
type UniqueID = [u8; 16];

#[derive(Debug, Serialize, Deserialize)]
pub struct CddId {
    pub cdd_id: RistrettoPoint,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RawCddClaimData {
    pub investor_did: InvestorDID,
    pub investor_unique_id: UniqueID,
}

/// Creates a CDD_ID from investor did and investor uid
///
/// # Arguments
/// * `cdd_claim` a stringified json with the following format:
///   { "investor_did": [32_bytes_array], "investor_unique_id": [16_bytes_array] }
///
/// # Errors
/// * `TODO` panicing at the moment.
#[wasm_bindgen]
pub fn process_create_cdd_id(cdd_claim: String) -> String {
    let raw_cdd_data: RawCddClaimData = serde_json::from_str(&cdd_claim)
        .unwrap_or_else(|error| panic!("Failed to deserialize the cdd claim: {}", error));

    let cdd_claim = CddClaimData::new(&raw_cdd_data.investor_did, &raw_cdd_data.investor_unique_id);

    let cdd_id = compute_cdd_id(&cdd_claim);

    let packaged_cdd_id = CddId { cdd_id: cdd_id };
    let cdd_id_str = serde_json::to_string(&packaged_cdd_id)
        .unwrap_or_else(|error| panic!("Failed to serialize the CDD Id: {}", error));

    cdd_id_str
}
