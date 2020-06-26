use cryptography::claim_proofs::RawData;
use curve25519_dalek::ristretto::RistrettoPoint;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Proof {
    pub cdd_id: RistrettoPoint,
    pub investor_did: RawData,
    pub scope_id: RistrettoPoint,
    pub scope_did: RawData,
    #[serde(with = "serde_bytes")]
    pub proof: Vec<u8>,
}
