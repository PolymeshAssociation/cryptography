//! Given C = g^x * h^y * f^z
//!
//! The goal is to prove the following statements.
//! - a = C^r -> ZKP(a; C)
//! - b = h^{y*r} * f^{z*r} -> ZKP(b; h, f)
//! - a/b = g^{x*r} -> ZKP(a/b; g)

use crate::{
    errors::Fallible,
    proofs::{apply_challenge, generate_initial_message},
    ChallengeResponder, CommittedUids, InvestorID, ProofGenerator, Proofs, ProverFinalResponse,
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
pub fn generate_blinding_factor(uid: Scalar, did: Scalar) -> Scalar {
    let hash = Sha3_512::default()
        .chain(uid.as_bytes())
        .chain(did.as_bytes());
    Scalar::from_hash(hash)
}

impl ProofGenerator for InitialProver {
    fn generate_initial_proofs<T: RngCore + CryptoRng>(
        investor: InvestorID,
        rng: &mut T,
    ) -> Fallible<(ProverSecrets, Proofs)> {
        let pg = PedersenGenerators::default();
        let blinding_factor = generate_blinding_factor(investor.uid, investor.did);
        let secrets = [investor.uid, investor.did, blinding_factor];
        let cdd_id = pg.commit(&secrets);

        let r = Scalar::random(rng);

        // Corresponds to proving a = C^r, where C is cdd_id.
        let (cdd_id_proof_secrets, cdd_id_proof) =
            generate_initial_message(vec![r], vec![cdd_id], rng)?;
        let a = cdd_id * r;

        // Corresponds to proving b = h^{y*r} * f^{z*r}.
        let (cdd_id_second_half_proof_secrets, cdd_id_second_half_proof) =
            generate_initial_message(
                [investor.did * r, blinding_factor * r].to_vec(),
                vec![pg.generators[1], pg.generators[2]],
                rng,
            )?;
        let b = (pg.generators[1] * investor.did + pg.generators[2] * blinding_factor) * r;

        // Corresponds to proving a/b = g^{x*r}.
        let (uid_commitment_proof_secrets, uid_commitment_proof) =
            generate_initial_message(vec![investor.uid * r], vec![pg.generators[0]], rng)?;

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
                a,
                b,
            },
        ))
    }
}

impl ChallengeResponder for FinalProver {
    fn generate_challenge_response<T: RngCore + CryptoRng>(
        secrets: ProverSecrets,
        committed_uids: CommittedUids,
        challenge: Scalar,
        rng: &mut T,
    ) -> Fallible<(ProverFinalResponse, CommittedUids)> {
        let r = secrets.rand;
        let mut recommitted_uids: Vec<RistrettoPoint> =
            committed_uids.into_iter().map(|e_uid| e_uid * r).collect();
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

#[cfg(test)]
mod tests {
    use crate::{
        prover::{generate_blinding_factor, FinalProver, InitialProver},
        uuid_to_scalar,
        verifier::{gen_random_uuids, Verifier, VerifierSetGenerator},
        ChallengeGenerator, ChallengeResponder, InvestorID, ProofGenerator, ProofVerifier,
    };
    use confidential_identity::pedersen_commitments::PedersenGenerators;
    use cryptography_core::curve25519_dalek::scalar::Scalar;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn test_success_end_to_end() {
        let mut rng = StdRng::from_seed([10u8; 32]);
        let pg = PedersenGenerators::default();

        // Private input of the Verifier.
        let private_uid_set: Vec<Scalar> = gen_random_uuids(100, &mut rng)
            .into_iter()
            .map(|uuid| uuid_to_scalar(uuid))
            .collect();

        // Verifier shares one of its uids with the Prover.
        let investor = InvestorID {
            uid: private_uid_set[0],
            did: Scalar::random(&mut rng),
        };

        // Prover generates cdd_id and places it on the chain.
        let cdd_id = pg.commit(&[
            investor.uid,
            investor.did,
            generate_blinding_factor(investor.uid, investor.did),
        ]);

        // P -> V: Prover generates and sends the initial message.
        let (prover_secrets, proofs) =
            InitialProver::generate_initial_proofs(investor, &mut rng).unwrap();

        // V -> P: Prover sends `proofs` and Verifier returns a list of 10 uids and the challenge.
        let (verifier_secrets, committed_uids, challenge) = VerifierSetGenerator
            .generate_committed_set_and_challenge(private_uid_set, Some(100), &mut rng)
            .unwrap();

        // P -> V: Verifier sends the committed_uids and the challenge to the Prover.
        let (prover_response, re_committed_uids) = FinalProver::generate_challenge_response(
            prover_secrets,
            committed_uids,
            challenge,
            &mut rng,
        )
        .unwrap();

        // Only V: Verifier verifies the proofs and check membership.
        Verifier::verify_proofs(
            proofs,
            prover_response,
            challenge,
            cdd_id,
            verifier_secrets,
            re_committed_uids,
        )
        .unwrap();
    }
}
