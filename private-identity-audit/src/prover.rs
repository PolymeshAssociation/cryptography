//! Given C = g^x * h^y * f^z
//!
//! The goal is to prove the following statements.
//! - a = C^r -> ZKP(a; C)
//! - b = h^{y*r} * f^{z*r} -> ZKP(b; h, f)
//! - a/b = g^{x*r} -> ZKP(a/b; g)

use crate::{
    errors::Fallible, proofs::non_interactive_prove, CommittedUids, ProofGenerator, Prover,
    ZKPFinalResponse, ZKPInitialmessage,
};
use cryptography_core::{
    cdd_claim::{
        compute_cdd_id, get_blinding_factor, pedersen_commitments::PedersenGenerators, CddClaimData,
    },
    curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar},
};
use rand::seq::SliceRandom;
use rand_core::{CryptoRng, RngCore};

impl ProofGenerator for Prover {
    fn generate_proofs<T: RngCore + CryptoRng>(
        claims: &[CddClaimData],
        committed_uids: &CommittedUids,
        rng: &mut T,
    ) -> Fallible<(Vec<ZKPInitialmessage>, Vec<ZKPFinalResponse>, CommittedUids)> {
        let r = Scalar::random(rng);

        let vec_of_tuples = claims
            .iter()
            .map(|claim| {
                let blinding_factor = get_blinding_factor(&claim);
                let cdd_id = compute_cdd_id(&claim);

                let pg = PedersenGenerators::default();

                // Corresponds to proving a = C^r, where C is cdd_id.
                let (cdd_id_proof, cdd_id_proof_response) =
                    non_interactive_prove(vec![r], vec![cdd_id.0], rng)?;
                let a = cdd_id.0 * r;

                // Corresponds to proving b = h^{y*r} * f^{z*r}.
                let (cdd_id_second_half_proof, cdd_id_second_half_proof_response) =
                    non_interactive_prove(
                        [claim.investor_did * r, blinding_factor * r].to_vec(),
                        vec![pg.generators[0], pg.generators[2]],
                        rng,
                    )?;
                let b = (pg.generators[0] * claim.investor_did
                    + pg.generators[2] * blinding_factor)
                    * r;

                // Corresponds to proving a/b = g^{x*r}.
                let (uid_commitment_proof, uid_commitment_proof_response) = non_interactive_prove(
                    vec![claim.investor_unique_id * r],
                    vec![pg.generators[1]],
                    rng,
                )?;

                Ok((
                    ZKPInitialmessage {
                        cdd_id_proof,
                        cdd_id_second_half_proof,
                        uid_commitment_proof,
                        a: a.into(),
                        b: b.into(),
                    },
                    ZKPFinalResponse {
                        cdd_id_proof_response,
                        cdd_id_second_half_proof_response,
                        uid_commitment_proof_response,
                    },
                ))
            })
            .collect::<Fallible<Vec<(ZKPInitialmessage, ZKPFinalResponse)>>>()?;

        let (initial_messages, final_responses) = vec_of_tuples.into_iter().unzip();

        let mut recommitted_uids: Vec<RistrettoPoint> =
            committed_uids.0.iter().map(|e_uid| e_uid * r).collect();

        // The prover reshuffles the set. Otherwise, once the verifiers searches for the element
        // and finds it, the verifier can tell which element it was based on the position in the
        // set.
        recommitted_uids.shuffle(rng);
        let recommitted_uids = CommittedUids(recommitted_uids);

        Ok((initial_messages, final_responses, recommitted_uids))
    }
}

// ------------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        uuid_to_scalar, verifier::gen_random_uuids, CommittedSetGenerator, PrivateUids,
        ProofGenerator, ProofVerifier, Prover, Verifier, VerifierSetGenerator,
    };
    use cryptography_core::cdd_claim::{compute_cdd_id, CddClaimData};
    use rand::{rngs::StdRng, SeedableRng};
    use rand_core::RngCore;
    use uuid::Uuid;

    #[test]
    fn test_success_end_to_end() {
        let mut rng = StdRng::from_seed([10u8; 32]);

        // set the max uID set size to 100 for faster test
        let uid_set_max = 100;
        // Private input of the Verifier.
        let private_uid_set: Vec<Uuid> = gen_random_uuids(uid_set_max, &mut rng);

        // Make a random did for the investor.
        let mut investor_dids = [[0u8; 32], [0u8; 32]];
        rng.fill_bytes(&mut investor_dids[0]);
        rng.fill_bytes(&mut investor_dids[1]);

        // Verifier shares one of its uids with the Prover.
        let claims = investor_dids
            .iter()
            .map(|did| CddClaimData::new(did, private_uid_set[0].as_bytes()))
            .collect::<Vec<_>>();

        // Prover generates cdd_id and places it on the chain.
        let cdd_ids = claims
            .iter()
            .map(|claim| compute_cdd_id(claim))
            .collect::<Vec<_>>();

        let private_uid_scalar_set: Vec<Scalar> =
            private_uid_set.into_iter().map(uuid_to_scalar).collect();

        // V -> P: Prover sends `proofs` and Verifier returns a list of 10 uids and the challenge.
        let (verifier_secrets, committed_uids) = VerifierSetGenerator::generate_committed_set(
            PrivateUids(private_uid_scalar_set),
            Some(uid_set_max),
            &mut rng,
        )
        .unwrap();

        // P -> V: Prover generates and sends the initial message.
        let (initial_message, final_response, re_committed_uids) =
            Prover::generate_proofs(&claims, &committed_uids, &mut rng).unwrap();

        // Only V: Verifier verifies the proofs and check membership.
        Verifier::verify_proofs(
            &initial_message,
            &final_response,
            &cdd_ids,
            &verifier_secrets,
            &re_committed_uids,
        )
        .iter()
        .for_each(|res| assert!(res.is_ok()));
    }
}
