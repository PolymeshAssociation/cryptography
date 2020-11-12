use cryptography::claim_proofs::{compute_cdd_id, CddClaimData};
use curve25519_dalek::ristretto::RistrettoPoint;
use rand::{rngs::StdRng, SeedableRng};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

pub type InvestorDID = [u8; 32];
pub const INVESTORDID_LEN: usize = 32;

// Ticker, a 12 bytes slice, is the scope DID.
pub type ScopeDID = [u8; 12];
pub const SCOPEDID_LEN: usize = 12;

// Unique ID is a UUIDv4.
pub type UniqueID = [u8; 16];
pub const UNIQUEID_LEN: usize = 16;

#[wasm_bindgen]
extern "C" {
    pub fn alert(s: &str);
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CddId {
    pub cdd_id: RistrettoPoint,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RawCddClaimData {
    pub investor_did: InvestorDID,
    pub investor_unique_id: UniqueID,
}

/// Generate a random `InvestorDID` for experiments.
fn random_investor_did<R: RngCore + CryptoRng>(rng: &mut R) -> InvestorDID {
    let mut investor_did = [0u8; INVESTORDID_LEN];
    rng.fill_bytes(&mut investor_did);
    investor_did
}

/// Generate a random `UniqueID` for experiments.
fn random_unique_id<R: RngCore + CryptoRng>(rng: &mut R) -> UniqueID {
    let mut unique_id = [0u8; UNIQUEID_LEN];
    rng.fill_bytes(&mut unique_id);
    unique_id
}

fn process_create_cdd_id() -> String {
    let mut rng = StdRng::from_seed([42u8; 32]);
    let rand_investor_did = random_investor_did(&mut rng);
    let rand_unique_id = random_unique_id(&mut rng);
    let raw_cdd_data = RawCddClaimData {
        investor_did: rand_investor_did,
        investor_unique_id: rand_unique_id,
    };

    let cdd_claim = CddClaimData::new(&raw_cdd_data.investor_did, &raw_cdd_data.investor_unique_id);

    let cdd_id = compute_cdd_id(&cdd_claim);

    // => CDD provider includes the CDD Id in their claim and submits it to the PolyMesh.
    let packaged_cdd_id = CddId { cdd_id: cdd_id };
    let cdd_id_str = serde_json::to_string(&packaged_cdd_id)
        .unwrap_or_else(|error| panic!("Failed to serialize the CDD Id: {}", error));

    cdd_id_str
}

#[wasm_bindgen]
pub fn greet(name: &str) {
    alert(&format!("Hello, {}!, {}", name, process_create_cdd_id()));
}
