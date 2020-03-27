use cryptography::claim_proofs::{ ClaimData, RawData};
use curve25519_dalek::ristretto::RistrettoPoint;
use rand::Rng;
use serde::{Deserialize, Serialize};


#[derive(Debug, Serialize, Deserialize)]
pub struct Proof {
    pub claim_label: RistrettoPoint,
    pub inv_id_0: RawData,
    pub did_label: RistrettoPoint,
    pub iss_id: RawData,
    #[serde(with = "serde_bytes")]
    pub proof: Vec<u8>,
}

pub fn random_claim<R: Rng + ?Sized>(rng: &mut R) -> ClaimData {
    let mut inv_id_0 = RawData::default();
    let mut inv_id_1 = RawData::default();
    let mut inv_blind = RawData::default();
    let mut iss_id = RawData::default();

    rng.fill_bytes(&mut inv_id_0.0);
    rng.fill_bytes(&mut inv_id_1.0);
    rng.fill_bytes(&mut inv_blind.0);
    rng.fill_bytes(&mut iss_id.0);

    ClaimData {
        inv_id_0,
        inv_id_1,
        inv_blind,
        iss_id,
    }
}
