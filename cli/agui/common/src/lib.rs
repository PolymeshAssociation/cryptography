use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Proof {
    pub cdd_id: RistrettoPoint,
    pub investor_did: Scalar,
    pub scope_id: RistrettoPoint,
    pub scope_did: Scalar,
    #[serde(with = "serde_bytes")]
    pub proof: Vec<u8>,
}
