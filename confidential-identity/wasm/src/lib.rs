use blake2::{Blake2s, Digest};
use confidential_identity::{
    claim_proofs::{Investor, Provider},
    mocked, CddClaimData, InvestorTrait, ProviderTrait, ScopeClaimData,
};
use rand::{rngs::StdRng, SeedableRng};
use serde::{Deserialize, Serialize};

use wasm_bindgen::prelude::*;

type InvestorDID = [u8; 32];

// Ticker, a 12 bytes slice, is the scope DID.
pub type ScopeDID = [u8; 12];

// Unique ID is a UUIDv4.
type UniqueID = [u8; 16];

#[derive(Debug, Serialize, Deserialize)]
pub struct RawCddClaimData {
    pub investor_did: InvestorDID,
    pub investor_unique_id: UniqueID,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RawScopeClaimData {
    pub scope_did: ScopeDID,
    pub investor_unique_id: UniqueID,
}

/// Returns the message used for checking the proof.
pub fn make_message(investor_did: &InvestorDID, scope_did: &ScopeDID) -> [u8; 32] {
    Blake2s::default()
        .chain(investor_did)
        .chain(scope_did)
        .finalize()
        .into()
}

/// Creates a CDD_ID from investor did and investor uid
///
/// # Arguments
/// * `cdd_claim` a stringified json with the following format:
///   { "investor_did": [32_bytes_array], "investor_unique_id": [16_bytes_array] }
///
/// # Errors
/// * Failure to deserialize the cdd claim.
/// * Failure to serialize the cdd id.
#[wasm_bindgen]
pub fn create_cdd_id(cdd_claim: String) -> Result<String, JsValue> {
    let raw_cdd_data: RawCddClaimData = serde_json::from_str(&cdd_claim)
        .map_err(|error| format!("Failed to deserialize the cdd claim: {}", error))?;

    let cdd_claim = CddClaimData::new(&raw_cdd_data.investor_did, &raw_cdd_data.investor_unique_id);

    let cdd_id = Provider::create_cdd_id(&cdd_claim);

    let cdd_id_str = serde_json::to_string(&cdd_id)
        .map_err(|error| format!("Failed to serialize the CDD Id: {}", error))?;

    Ok(cdd_id_str)
}

/// Creates a scope claim proof for an investor from investor did, investor uid, and scope did.
///
/// # Arguments
/// * `cdd_claim` a stringified json with the following format:
///   { "investor_did": [32_bytes_array], "investor_unique_id": [16_bytes_array] }
/// * `scoped_claim` a stringified json with the following format:
///   { "scope_did":[12_bytes_array], "investor_unique_id":[16_bytes_array] }
/// * `seed` is the seed used for generating random values. Thes seed MUST be generated using
///   cryptographically secure rng and should be a stringified arry of 32 byets.
///   At the time of writing this doc, the best practice is to use
///   https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/generateKey
///   in a secure context.
///
/// # Errors
/// * Failure to deserialize the cdd claim.
/// * Failure to deserialize the scope claim.
/// * Failure to deserialize the seed.
/// * Failure to serialize the proof.
#[wasm_bindgen]
pub fn create_scope_claim_proof(
    cdd_claim: String,
    scoped_claim: String,
    seed: String,
) -> Result<String, JsValue> {
    let raw_cdd_claim: RawCddClaimData = serde_json::from_str(&cdd_claim)
        .map_err(|error| format!("Failed to deserialize the cdd claim: {}", error))?;

    let raw_scope_claim: RawScopeClaimData = serde_json::from_str(&scoped_claim)
        .map_err(|error| format!("Failed to deserialize the scope claim: {}", error))?;

    let seed: [u8; 32] = serde_json::from_str(&seed)
        .map_err(|error| format!("Failed to deserialize the seed: {}", error))?;
    let mut rng = StdRng::from_seed(seed);

    let cdd_claim = CddClaimData::new(
        &raw_cdd_claim.investor_did,
        &raw_cdd_claim.investor_unique_id,
    );

    let scope_claim = ScopeClaimData::new(
        &raw_scope_claim.scope_did,
        &raw_scope_claim.investor_unique_id,
    );

    let proof = Investor::create_scope_claim_proof(&cdd_claim, &scope_claim, &mut rng);

    let proof_str = serde_json::to_string(&proof)
        .map_err(|error| format!("Failed to serialize the proof: {}", error))?;

    Ok(proof_str)
}

/// This function is for testing. The JS users are not expected to call this function.
#[wasm_bindgen]
pub fn _verify_scope_claim_proof(
    proof: String,
    investor_did: String,
    scope_did: String,
    cdd_id: String,
) -> Result<(), JsValue> {
    use confidential_identity::VerifierTrait;

    let proof: confidential_identity::ScopeClaimProof = serde_json::from_str(&proof)
        .map_err(|error| format!("Failed to deserialize the proof: {}", error))?;

    let investor_did: InvestorDID = serde_json::from_str(&investor_did)
        .map_err(|error| format!("Failed to deserialize the investor_did: {}", error))?;
    let scope_did: ScopeDID = serde_json::from_str(&scope_did)
        .map_err(|error| format!("Failed to deserialize the scope_did: {}", error))?;
    let cdd_id: confidential_identity::CddId = serde_json::from_str(&cdd_id)
        .map_err(|error| format!("Failed to deserialize the cdd_id: {}", error))?;

    confidential_identity::claim_proofs::Verifier::verify_scope_claim_proof(
        &proof,
        &confidential_identity::claim_proofs::slice_to_scalar(&investor_did),
        &confidential_identity::claim_proofs::slice_to_scalar(&scope_did),
        &cdd_id,
    )
    .map_err(|error| format!("Proof verification failed: {}", error).into())
}

#[wasm_bindgen]
pub fn create_mocked_investor_uid(did: String) -> String {
    // Sanitize Did input.
    let did = did.strip_prefix("0x").unwrap_or(&did);
    let did = did.chars().filter(|c| *c != '-').collect::<String>();
    let raw_did = hex::decode(did).expect("Invalid input DID, please use hex format");
    assert!(
        raw_did.len() == 32,
        "Invalid input DID, len should be 64 hex characters"
    );

    // Generate the mocked InvestorUid
    let investor_uid = mocked::make_investor_uid(&raw_did);

    hex::encode(investor_uid)
}
