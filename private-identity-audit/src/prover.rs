//! Given C = g^x * h^y * f^z
//!
//! The goal is to prove the following statements.
//! - a = C^r -> ZKP(a; C)
//! - b = h^{y*r} * f^{z*r} -> ZKP(b; h, f)
//! - a/b = g^r -> ZKP(a/b; g)

use crate::{
    errors::Fallible, proofs::WellformednessProverAwaitingChallenge, EncryptedUIDs, InvestorID,
    Proof, ProofGenerator,
};
use confidential_identity::pedersen_commitments::PedersenGenerators;
use cryptography_core::{
    asset_proofs::encryption_proofs::single_property_prover,
    curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar},
};
use rand::seq::SliceRandom;
use rand_core::{CryptoRng, RngCore};
use sha3::{Digest, Sha3_512};

pub struct Prover;

/// Modified version of `generate_pedersen_commit` function of Confidential Identity Library.
fn generate_bliding_factor(did: Scalar, uid: Scalar) -> Scalar {
    let hash = Sha3_512::default()
        .chain(did.as_bytes())
        .chain(uid.as_bytes());
    Scalar::from_hash(hash)
}

impl ProofGenerator for Prover {
    fn generate_membership_proof<T: RngCore + CryptoRng>(
        investor: InvestorID,
        encrypted_uids: EncryptedUIDs,
        rng: &mut T,
    ) -> Fallible<Proof> {
        let pg = PedersenGenerators::default();
        let blinding_factor = generate_bliding_factor(investor.did, investor.uid);
        let secrets = [investor.did, investor.uid, blinding_factor];
        let cdd_id = pg.commit(&secrets);
        //let second_half = pg.generators[1] * investor.uid + pg.generators[2] * blinding_factor;

        let r = Scalar::random(rng);
        //let statement1 = cdd_id * r;
        //let statement2 = second_half * r;
        //let statement3 = statement1 - statement2;

        let _proof1 = single_property_prover(
            WellformednessProverAwaitingChallenge {
                secrets: vec![r],
                generators: &vec![cdd_id],
            },
            rng,
        )
        .unwrap();

        let _proof2 = single_property_prover(
            WellformednessProverAwaitingChallenge {
                secrets: [secrets[1] * r, secrets[2] * r].to_vec(),
                generators: &vec![pg.generators[1], pg.generators[2]],
            },
            rng,
        )
        .unwrap();

        let _proof3 = single_property_prover(
            WellformednessProverAwaitingChallenge {
                secrets: vec![r],
                generators: &vec![pg.generators[0]],
            },
            rng,
        )
        .unwrap();

        let mut recommit: Vec<RistrettoPoint> =
            encrypted_uids.into_iter().map(|e_uid| e_uid * r).collect();
        recommit.shuffle(rng);

        Ok(Proof {
            //proof1,
            //proof2,
            //proof3,
            //recommit,
        })
    }
}

// ------------------------------------------------------------------------------------------------
// -                                            Tests                                             -
// ------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    //use crate::{PrivateSetGenerator, SET_SIZE_ANONYMITY_PARAM};
    //use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn test_generate_proof() {
        //let mut rng = StdRng::from_seed([10u8; 32]);
    }
}
