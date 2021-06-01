//! This modules is used for creating and verifying CDD Claims
//!
//! The user can create a CDD Claim after she has verified her identity and has received
//! a certificate from PUIS. The user may create many CDD Claims for each of her public keys.
//!
//! TODO: Compress ALL the RistrettoPoints that are send over the wire and the decompress them
//! during the verification to save bandwidth.
//!
//! TODO: since this will be used in the PIAL as well, the base types should be moved to a new
//! folder under `cryptography_core`. The same way that the current types are located at
//! `cryptography-core/src/cdd_claim/`

use cryptography_core::{RistrettoPoint, Scalar};
use rand_core::{CryptoRng, RngCore};
use sha3::{Digest, Sha3_512};

use crate::{
    get_g, get_g1, get_g2,
    sign::{IdentitySignature, IdentitySignaturePrivateKey},
    UserKeys,
};

pub struct CddClaim {
    claim_c_1_hat: RistrettoPoint,
    claim_a_1_hat: Scalar,
    claim_r_1_hat: Scalar,
    proof_a: Scalar,
    proof_r0: Scalar,
    proof_r1: Scalar,
}

impl CddClaim {
    pub fn new<R: RngCore + CryptoRng>(
        identity_signature: &IdentitySignature,
        identity_signature_private_key: &IdentitySignaturePrivateKey,
        user_keypair: UserKeys,
        user_did: Scalar,
        rng: &mut R,
    ) -> Self {
        let w0 = Scalar::random(rng);
        let w1 = Scalar::random(rng);
        let o_1_hat = Scalar::random(rng);
        let w_1_hat = Scalar::random(rng);

        let h = identity_signature.h;
        let g = get_g();
        let g1 = get_g1();
        let g2 = get_g2();

        let a =
            Scalar::from_hash(Sha3_512::default().chain((h * w0 + g1 * w1).compress().as_bytes()));
        let c_1_hat = g2 * user_did + g * user_keypair.private + g1 * o_1_hat;
        let a_1_hat = Scalar::from_hash(
            Sha3_512::default().chain((g * w1 + g1 * w_1_hat).compress().as_bytes()),
        );
        let c = Scalar::from_hash(
            Sha3_512::default()
                .chain(a.as_bytes())
                .chain(c_1_hat.compress().as_bytes())
                .chain(a_1_hat.as_bytes())
                .chain(user_did.as_bytes()),
        );
        let r0 = identity_signature_private_key.0 * c + w0;
        let r1 = w1 - c * user_keypair.private;
        let r_1_hat = w_1_hat - c * o_1_hat;
        Self {
            claim_c_1_hat: c_1_hat,
            claim_a_1_hat: a_1_hat,
            claim_r_1_hat: r_1_hat,
            proof_a: a,
            proof_r0: r0,
            proof_r1: r1,
        }
    }

    pub fn verify(
        &self,
        identity_signature: &IdentitySignature,
        user_did: Scalar,
        issuer_public_key: RistrettoPoint,
    ) -> Result<(), String> {
        let c = Scalar::from_hash(
            Sha3_512::default()
                .chain(self.proof_a.as_bytes())
                .chain(self.claim_c_1_hat.compress().as_bytes())
                .chain(self.claim_a_1_hat.as_bytes())
                .chain(user_did.as_bytes()),
        );

        let a = Scalar::from_hash(
            Sha3_512::default().chain(
                (get_g1() * self.proof_r1 + identity_signature.h * self.proof_r0
                    - issuer_public_key * c)
                    .compress()
                    .as_bytes(),
            ),
        );

        // TODO: use `ensure!` with proper Error names.
        if a != self.proof_a {
            return Err("Failed to prove the knowlegde of user's private key.".into());
        }

        let a_1_hat = Scalar::from_hash(
            Sha3_512::default().chain(
                (get_g() * self.proof_r1
                    + get_g1() * self.claim_r_1_hat
                    + (self.claim_c_1_hat - (get_g2() * user_did)) * c)
                    .compress()
                    .as_bytes(),
            ),
        );

        // TODO: use `ensure!` with proper Error names.
        if a_1_hat != self.claim_a_1_hat {
            return Err(
                "Failed to prove that the CDD Claim and the certificate use the same private key."
                    .into(),
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        cdd_claim::CddClaim,
        sign::{step1, step2, step3, step4, IdentitySignature, IdentitySignaturePrivateKey},
        IssuerKeys, UserKeys,
    };
    use cryptography_core::{RistrettoPoint, Scalar};
    use rand::{rngs::StdRng, SeedableRng};

    const SEED: [u8; 32] = [42u8; 32];

    fn setup(
        rng: &mut StdRng,
    ) -> (
        IdentitySignature,
        IdentitySignaturePrivateKey,
        UserKeys,
        RistrettoPoint,
    ) {
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
        let (signature, signature_private_key) =
            step4(step3_public, step2_secret, &issuer_public_key).expect("Verification failed!");

        assert!(
            signature.verify(&issuer_public_key),
            "Signature verification failed!"
        );

        (
            signature,
            signature_private_key,
            user_keypair,
            issuer_public_key,
        )
    }
    #[test]
    fn test_cdd_claim() {
        // ---------------- Done by the User.
        // In the real implementation each party will have its own rng.
        let mut rng = StdRng::from_seed(SEED);

        let (identity_signature, identity_signature_private_key, user_keypair, issuer_public_key) =
            setup(&mut rng);
        let user_did = Scalar::random(&mut rng);

        let cdd_claim = CddClaim::new(
            &identity_signature,
            &identity_signature_private_key,
            user_keypair,
            user_did,
            &mut rng,
        );

        cdd_claim
            .verify(&identity_signature, user_did, issuer_public_key)
            .expect("CDD Claim verification failed!");
    }
}
