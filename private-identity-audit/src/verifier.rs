use crate::{
    errors::{ErrorKind, Fallible},
    EncryptedUIDs, PrivateSetGenerator, PrivateUIDs, SET_SIZE_ANONYMITY_PARAM,
};
use blake2::{Blake2b, Digest};
use confidential_identity::pedersen_commitments::PedersenGenerators;
use cryptography_core::curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use uuid::{Builder, Uuid, Variant, Version};

pub struct VerifierSetGenerator;

impl PrivateSetGenerator for VerifierSetGenerator {
    fn generate_encrypted_unique_ids<T: RngCore + CryptoRng>(
        &self,
        private_unique_identifiers: PrivateUIDs,
        min_set_size: Option<usize>,
        rng: &mut T,
    ) -> Fallible<EncryptedUIDs> {
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
        Ok(padded_vec
            .into_iter()
            .map(|uid| uuid_to_scalar(uid))
            .map(|scalar_uid| Scalar::random(rng) * scalar_uid)
            .map(|blinded_uid| pg.generators[0] * blinded_uid)
            .collect())
    }
}

/// Modified version of `slice_to_scalar` of Confidential Identity Library.
/// Creates a scalar from a UUID.
fn uuid_to_scalar(uuid: Uuid) -> Scalar {
    let mut hash = [0u8; 64];
    hash.copy_from_slice(Blake2b::digest(uuid.as_bytes()).as_slice());
    Scalar::from_bytes_mod_order_wide(&hash)
}

fn gen_random_uuids<T: RngCore + CryptoRng>(count: usize, rng: &mut T) -> Vec<Uuid> {
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
        let encrytped_uids = VerifierSetGenerator
            .generate_encrypted_unique_ids(gen_random_uuids(input_len, &mut rng), None, &mut rng)
            .expect("Success");

        assert_eq!(encrytped_uids.len(), SET_SIZE_ANONYMITY_PARAM);

        // Test overridden anonoymity param.
        let different_annonymity_size = 20;
        let encrytped_uids = VerifierSetGenerator
            .generate_encrypted_unique_ids(
                gen_random_uuids(input_len, &mut rng),
                Some(different_annonymity_size),
                &mut rng,
            )
            .expect("Success");

        assert_eq!(encrytped_uids.len(), different_annonymity_size);

        // Test no padding.
        let different_annonymity_size = 5;
        let encrytped_uids = VerifierSetGenerator
            .generate_encrypted_unique_ids(
                gen_random_uuids(input_len, &mut rng),
                Some(different_annonymity_size),
                &mut rng,
            )
            .expect("Success");

        assert_eq!(encrytped_uids.len(), input_len);
    }
}
