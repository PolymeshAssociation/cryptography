use crate::{
    errors::Fallible, proofs::verify, uuid_to_scalar, EncryptedUIDs, PrivateSetGenerator,
    PrivateUIDs, ProofVerifier, Proofs, ProverFinalResponse, VerifierSecrets,
    SET_SIZE_ANONYMITY_PARAM,
};
use confidential_identity::pedersen_commitments::PedersenGenerators;
use cryptography_core::curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use rand::seq::SliceRandom;
use rand_core::{CryptoRng, RngCore};
use uuid::{Builder, Uuid, Variant, Version};

pub struct VerifierSetGenerator;
pub struct Verifier;

impl PrivateSetGenerator for VerifierSetGenerator {
    fn generate_encrypted_unique_ids<T: RngCore + CryptoRng>(
        &self,
        private_unique_identifiers: PrivateUIDs,
        min_set_size: Option<usize>,
        rng: &mut T,
    ) -> Fallible<(VerifierSecrets, EncryptedUIDs, Scalar)> {
        // Pad the input vector with randomly generated uuids.
        let min_size = if let Some(overriden_size) = min_set_size {
            overriden_size
        } else {
            SET_SIZE_ANONYMITY_PARAM
        };
        let padded_vec = if private_unique_identifiers.len() >= min_size {
            private_unique_identifiers
        } else {
            let padding = gen_random_uuids(min_size - private_unique_identifiers.len(), rng);
            [&private_unique_identifiers[..], &padding[..]].concat()
        };

        // Commit to each element.
        let pg = PedersenGenerators::default();
        let r = Scalar::random(rng);
        let mut commitments = padded_vec
            .into_iter()
            .map(|uid| uuid_to_scalar(uid))
            .map(|scalar_uid| pg.generators[0] * scalar_uid * r)
            .collect::<EncryptedUIDs>();
        commitments.shuffle(rng);

        let challenge = Scalar::random(rng);

        Ok((VerifierSecrets { rand: r }, commitments, challenge))
    }
}

impl ProofVerifier for Verifier {
    fn verify_membership_proof(
        initial_message: Proofs,
        final_response: ProverFinalResponse,
        challenge: Scalar,
        cdd_id: RistrettoPoint, // TODO: need to find a way of using this.
        committed_cdd_id: RistrettoPoint,
        committed_cdd_id_second_half: RistrettoPoint,
        verifier_secrets: VerifierSecrets,
        re_encrypted_uids: EncryptedUIDs,
    ) -> Fallible<()> {
        let uid_commitment = committed_cdd_id - committed_cdd_id_second_half;
        assert_eq!(initial_message.cdd_id_proof.generators[0], cdd_id);

        assert!(verify(
            initial_message.cdd_id_proof,
            final_response.cdd_id_proof_response,
            committed_cdd_id,
            challenge,
        )); // TODO
        assert!(verify(
            initial_message.cdd_id_second_half_proof,
            final_response.cdd_id_second_half_proof_response,
            committed_cdd_id_second_half,
            challenge,
        )); // TODO
        assert!(verify(
            initial_message.uid_commitment_proof,
            final_response.uid_commitment_proof_response,
            uid_commitment,
            challenge,
        )); // TODO

        let looking_for = uid_commitment * verifier_secrets.rand;

        let found = re_encrypted_uids
            .into_iter()
            .any(|element| element == looking_for);
        assert!(found); // TODO
        Ok(())
    }
}

pub fn gen_random_uuids<T: RngCore + CryptoRng>(count: usize, rng: &mut T) -> Vec<Uuid> {
    vec![0; count]
        .into_iter()
        .map(|_| {
            let mut random_bytes: [u8; 16] = [0; 16];
            rng.fill_bytes(&mut random_bytes);
            let rand_uuid = Builder::from_bytes(random_bytes)
                .set_variant(Variant::RFC4122)
                .set_version(Version::Random)
                .build();
            rand_uuid
        })
        .collect()
}

// ------------------------------------------------------------------------------------------------
// -                                            Tests                                             -
// ------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::{
        verifier::{gen_random_uuids, VerifierSetGenerator},
        PrivateSetGenerator, SET_SIZE_ANONYMITY_PARAM,
    };
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn test_verifier_set_gen_length() {
        let mut rng = StdRng::from_seed([10u8; 32]);
        let input_len = 10;

        // Test original anonoymity param.
        let (_, encrytped_uids, _) = VerifierSetGenerator
            .generate_encrypted_unique_ids(gen_random_uuids(input_len, &mut rng), None, &mut rng)
            .expect("Success");

        assert_eq!(encrytped_uids.len(), SET_SIZE_ANONYMITY_PARAM);

        // Test overridden anonoymity param.
        let different_annonymity_size = 20;
        let (_, encrytped_uids, _) = VerifierSetGenerator
            .generate_encrypted_unique_ids(
                gen_random_uuids(input_len, &mut rng),
                Some(different_annonymity_size),
                &mut rng,
            )
            .expect("Success");

        assert_eq!(encrytped_uids.len(), different_annonymity_size);

        // Test no padding.
        let different_annonymity_size = 5;
        let (_, encrytped_uids, _) = VerifierSetGenerator
            .generate_encrypted_unique_ids(
                gen_random_uuids(input_len, &mut rng),
                Some(different_annonymity_size),
                &mut rng,
            )
            .expect("Success");

        assert_eq!(encrytped_uids.len(), input_len);
    }
}
