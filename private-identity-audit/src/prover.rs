//! Given C = g^x * h^y * f^z
//!
//! The goal is to prove the following statements.
//! - a = C^r -> ZKP(a; C)
//! - b = h^{y*r} * f^{z*r} -> ZKP(b; h, f)
//! - a/b = g^{x*r} -> ZKP(a/b; g)

use crate::{
    errors::Fallible,
    proofs::{apply_challenge, generate_initial_message},
    ChallengeResponder, EncryptedUIDs, InvestorID, ProofGenerator, Proofs, ProverFinalResponse,
    ProverSecrets,
};
use confidential_identity::pedersen_commitments::PedersenGenerators;
use cryptography_core::curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use rand::seq::SliceRandom;
use rand_core::{CryptoRng, RngCore};
use sha3::{Digest, Sha3_512};

pub struct InitialProver;
pub struct FinalProver;

/// Modified version of `generate_pedersen_commit` function of Confidential Identity Library.
pub fn generate_bliding_factor(did: Scalar, uid: Scalar) -> Scalar {
    let hash = Sha3_512::default()
        .chain(did.as_bytes())
        .chain(uid.as_bytes());
    Scalar::from_hash(hash)
}

impl ProofGenerator for InitialProver {
    fn generate_membership_proof<T: RngCore + CryptoRng>(
        investor: InvestorID,
        rng: &mut T,
    ) -> Fallible<(ProverSecrets, Proofs, RistrettoPoint, RistrettoPoint)> {
        let pg = PedersenGenerators::default();
        let blinding_factor = generate_bliding_factor(investor.did, investor.uid);
        let secrets = [investor.uid, investor.did, blinding_factor];
        let cdd_id = pg.commit(&secrets);

        let r = Scalar::random(rng);

        // Corresponds to proving a = C^r, where C is cdd_id. `a` is represented as
        // `committed_cdd_id`.
        let (cdd_id_proof_secrets, cdd_id_proof) =
            generate_initial_message(vec![r], vec![cdd_id], rng);
        let committed_cdd_id = cdd_id * r;

        // Corresponds to proving b = h^{y*r} * f^{z*r}, b is represented as `commited_cdd_id_second_half`.
        let (cdd_id_second_half_proof_secrets, cdd_id_second_half_proof) = generate_initial_message(
            [investor.did * r, blinding_factor * r].to_vec(),
            vec![pg.generators[1], pg.generators[2]],
            rng,
        );
        let commited_cdd_id_second_half =
            (pg.generators[1] * investor.did + pg.generators[2] * blinding_factor) * r;

        // Corresponds to proving a/b = g^{x*r}.
        let (uid_commitment_proof_secrets, uid_commitment_proof) =
            generate_initial_message(vec![investor.uid * r], vec![pg.generators[0]], rng);

        Ok((
            ProverSecrets {
                cdd_id_proof_secrets,
                cdd_id_second_half_proof_secrets,
                uid_commitment_proof_secrets,
                rand: r,
            },
            Proofs {
                cdd_id_proof,
                cdd_id_second_half_proof,
                uid_commitment_proof,
            },
            committed_cdd_id,
            commited_cdd_id_second_half,
        ))
    }
}

impl ChallengeResponder for FinalProver {
    fn generate_challenge_response<T: RngCore + CryptoRng>(
        secrets: ProverSecrets,
        encrypted_uids: EncryptedUIDs,
        challenge: Scalar,
        rng: &mut T,
    ) -> Fallible<(ProverFinalResponse, EncryptedUIDs)> {
        let r = secrets.rand;
        let mut recommitted_uids: Vec<RistrettoPoint> =
            encrypted_uids.into_iter().map(|e_uid| e_uid * r).collect();
        recommitted_uids.shuffle(rng);

        let cdd_id_proof_response = apply_challenge(secrets.cdd_id_proof_secrets, challenge);
        let cdd_id_second_half_proof_response =
            apply_challenge(secrets.cdd_id_second_half_proof_secrets, challenge);
        let uid_commitment_proof_response =
            apply_challenge(secrets.uid_commitment_proof_secrets, challenge);

        Ok((
            ProverFinalResponse {
                cdd_id_proof_response,
                cdd_id_second_half_proof_response,
                uid_commitment_proof_response,
            },
            recommitted_uids,
        ))
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
