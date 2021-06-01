//! This modules is used for creating and verifying SCOPE Claims.
//!
//! TODO: describe the usecase for asset clamis: e.g. ensuring one vote per real-world person.
//! TODO: double check the `rng`s in the tests and make sure that they are passed mutable.

use crate::{cdd_claim::CddClaim, get_g, get_g1, get_g2, UserKeys};
use cryptography_core::{RistrettoPoint, Scalar};
use rand_core::{CryptoRng, RngCore};
use sha3::{Digest, Sha3_512};

pub struct ScopeClaim {
    scope_did: Scalar,
    claim: RistrettoPoint,
    proof_a: Scalar,
    proof_b: Scalar,
    proof_ss: RistrettoPoint,
    proof_tt: RistrettoPoint,
}

impl ScopeClaim {
    pub fn new<R: RngCore + CryptoRng>(
        cdd_claim: &CddClaim,
        scope_did: Scalar,
        user_keypair: &UserKeys,
        rng: &mut R,
    ) -> Self {
        let hashed_asset =
            RistrettoPoint::from_hash(Sha3_512::default().chain(scope_did.as_bytes()));
        let claim = hashed_asset * user_keypair.private;
        // Prove that statement_1 and statement_2 share the same private key.

        let s = Scalar::random(rng);
        let t = Scalar::random(rng);
        let ss = hashed_asset * s;
        let tt = get_g() * s + get_g1() * t;

        // TODO: compute challenge c using fiat-shamir
        let c = Scalar::random(rng);
        let a = s * c + user_keypair.private;
        let b = t * c + cdd_claim.claim_o_1_hat;

        Self {
            scope_did,
            claim,
            proof_a: a,
            proof_b: b,
            proof_ss: ss,
            proof_tt: tt,
        }
    }

    pub fn verify(&self, cdd_claim: &CddClaim, user_did: Scalar) -> Result<(), String> {
        let statement_1 = self.claim;
        let statement_2 = cdd_claim.claim_c_1_hat - (get_g2() * user_did);
        let hashed_asset =
            RistrettoPoint::from_hash(Sha3_512::default().chain(self.scope_did.as_bytes()));

        // TODO: compute challenge c using fiat-shamir
        let c = Scalar::default();
        if statement_1 + self.proof_ss * c != hashed_asset * self.proof_a {
            return Err("First check failed!".into());
        }

        if statement_2 + self.proof_tt * c == get_g() * self.proof_a + get_g1() * self.proof_b {
            return Err("Second check failed!".into());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        cdd_claim::CddClaim,
        scope_claim::ScopeClaim,
        sign::{step1, step2, step3, step4},
        IssuerKeys, UserKeys,
    };
    use cryptography_core::Scalar;
    use rand::{rngs::StdRng, SeedableRng};

    const SEED: [u8; 32] = [42u8; 32];

    fn setup(rng: &mut StdRng) -> (CddClaim, Scalar, UserKeys) {
        // TODO: instead of copy-pasting this test from sign.rs and cdd_claim.rs,
        // hard-code a hand-crafted signature struct and a CddClaim struct.
        //
        // ---------------- Done by the User.
        // In the real implementation each party will have its own rng.
        let user_keypair = UserKeys::new(rng);
        let user_public_key = user_keypair.public;

        // ---------------- Done by the Issuer.
        let issuer_keypair = IssuerKeys::new(rng);
        let issuer_public_key = issuer_keypair.public;

        let (step1_public, step1_secret) = step1(user_public_key, &issuer_keypair, rng);
        let (step2_public, step2_secret) =
            step2(user_public_key, issuer_public_key, step1_public, rng);
        let step3_public = step3(step2_public, step1_secret, &issuer_keypair.private);
        let (identity_signature, identity_signature_private_key) =
            step4(step3_public, step2_secret, &issuer_public_key).expect("Verification failed!");

        assert!(
            identity_signature.verify(&issuer_public_key),
            "Signature verification failed!"
        );
        let user_did = Scalar::random(rng);

        let cdd_claim = CddClaim::new(
            &identity_signature,
            &identity_signature_private_key,
            &user_keypair,
            user_did,
            rng,
        );

        cdd_claim
            .verify(&identity_signature, user_did, issuer_public_key)
            .expect("CDD Claim verification failed!");

        (cdd_claim, user_did, user_keypair)
    }

    #[test]
    fn test_scope_claim() {
        // ---------------- Done by the User.
        // In the real implementation each party will have its own rng.
        let mut rng = StdRng::from_seed(SEED);
        let (cdd_claim, user_did, user_keypair) = setup(&mut rng);
        let scope_did = Scalar::random(&mut rng);

        let scope_claim = ScopeClaim::new(&cdd_claim, scope_did, &user_keypair, &mut rng);

        scope_claim
            .verify(&cdd_claim, user_did)
            .expect("SCOPE Claim verification failed!");
    }
}
