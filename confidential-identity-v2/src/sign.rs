//! This modules is used for handling the identity signature creation. The identity signature
//! creation is a 5 step interactive protocol between the User and the Issuer.
//! At each step, a party runs one of the functions in this module and sends the results to the
//! other party.
//!
//! Step 0: Not part of this module.
//!         - The Issuer creates a keypair.
//!         - The User creates a keypair.
//!         - The Issuer and the User exchange their public keys.
//!

use crate::{get_g, IssuerKeys};
use cryptography_core::{RistrettoPoint, Scalar};
use rand_core::{CryptoRng, RngCore};
use sha3::{Digest, Sha3_512};

/// TODO: needs better name
/// Created by the Issuer and sent over the wire to the User.
pub struct Step1PublicData {
    sigma_a: RistrettoPoint,
    sigma_b: RistrettoPoint,
    sigma_z: RistrettoPoint,
}

/// TODO: needs better name
pub struct Step1SecretData(Scalar);

/// TODO: needs better name
/// Created by the Issuer and sent over the wire to the User.
pub struct Step2PublicData(Scalar);

/// TODO: needs better name
pub struct Step2SecretData {
    alpha: Scalar,
    beta2: Scalar,
    h: RistrettoPoint,
    sigma_a_prime: RistrettoPoint,
    sigma_b_prime: RistrettoPoint,
    sigma_z_prime: RistrettoPoint,
    sigma_c_prime: Scalar,
}

pub struct IdentitySignature {
    pub h: RistrettoPoint,
    pub sigma_z_prime: RistrettoPoint,
    pub sigma_c_prime: Scalar,
    pub sigma_r_prime: Scalar,
}

pub struct IdentitySignaturePrivateKey(pub(crate) Scalar);

/// TODO: needs better name
/// Given the `user_public_key` and the `issuer_keypair`, the Issuer computes and returns
/// `Step1PublicData` to be shared with the User. The function also returns a secret Scalar value that
/// should be kept private by the issuer. This value will be used in `step3`.
pub fn step1<R: RngCore + CryptoRng>(
    user_public_key: RistrettoPoint,
    issuer_keypair: &IssuerKeys,
    rng: &mut R,
) -> (Step1PublicData, Step1SecretData) {
    let gamma = user_public_key + issuer_keypair.public;
    let w = Scalar::random(rng);
    let sigma_a = get_g() * w;
    let sigma_b = gamma * w;
    let sigma_z = gamma * issuer_keypair.private;
    (
        Step1PublicData {
            sigma_a,
            sigma_b,
            sigma_z,
        },
        Step1SecretData(w),
    )
}

/// TODO: needs better name
/// Given the result of step1, and the public keys of the User and the Issuer, the User computes
/// and returns `sigma_c` to be shared with the Issuer. The function also returns the internal data
/// that should be private by the User. These internal data will be used in `step4`.
pub fn step2<R: RngCore + CryptoRng>(
    user_public_key: RistrettoPoint,
    issuer_public_key: RistrettoPoint,
    step1_data: Step1PublicData,
    rng: &mut R,
) -> (Step2PublicData, Step2SecretData) {
    let alpha = Scalar::random(rng);
    let beta1 = Scalar::random(rng);
    let beta2 = Scalar::random(rng);
    let gamma = user_public_key + issuer_public_key;
    let h = gamma * alpha;
    let t1 = issuer_public_key * beta1 + get_g() * beta2;
    let t2 = h * beta2;
    let sigma_z_prime = step1_data.sigma_z * alpha;
    let sigma_a_prime = t1 + step1_data.sigma_a;
    let sigma_b_prime = sigma_z_prime * beta1 + t2 + step1_data.sigma_b * alpha;
    let sigma_c_prime = Scalar::from_hash(
        Sha3_512::default()
            .chain(h.compress().as_bytes())
            .chain(sigma_z_prime.compress().as_bytes())
            .chain(sigma_a_prime.compress().as_bytes())
            .chain(sigma_b_prime.compress().as_bytes()),
    );
    let sigma_c = sigma_c_prime + beta1;
    (
        Step2PublicData(sigma_c),
        Step2SecretData {
            alpha,
            beta2,
            h,
            sigma_a_prime,
            sigma_b_prime,
            sigma_z_prime,
            sigma_c_prime,
        },
    )
}

/// TODO: needs better name
/// Given the results of step2 (`sigma_c`), the `issuer_secret_key`, and the `step1_secret`, the
/// issuer blinds `sigma_c` and returns `sigma_r`. The `step1_secret` can be safely deleted after
/// this step.
pub fn step3(
    step2_public: Step2PublicData,
    step1_secret: Step1SecretData,
    issuer_private_key: &Scalar,
) -> Scalar {
    step2_public.0 * issuer_private_key + step1_secret.0
}

/// TODO: needs better name
/// Given the result of the step3 (`sigma_r`), issuer_public_key, and `step2_secret_data`, the User
/// verifies that the data received from the Issuer matches the data created internally. If the
/// checks pass, the function returns the certificate and its corresponding private key.
/// TODO: return proper errors.
pub fn step4(
    step3_public: Scalar,
    step2_secret_data: Step2SecretData,
    issuer_public_key: &RistrettoPoint,
) -> Result<(IdentitySignature, IdentitySignaturePrivateKey), String> {
    let Step2SecretData {
        alpha,
        beta2,
        h,
        sigma_a_prime,
        sigma_b_prime,
        sigma_z_prime,
        sigma_c_prime,
    } = step2_secret_data;
    let sigma_r_prime = step3_public + beta2;

    let lhs = sigma_a_prime + sigma_b_prime;
    let rhs = (get_g() + h) * sigma_r_prime - (issuer_public_key + sigma_z_prime) * sigma_c_prime;

    ensure!(lhs == rhs, "LHS neq RHS");

    Ok((
        IdentitySignature {
            h,
            sigma_z_prime,
            sigma_c_prime,
            sigma_r_prime,
        },
        IdentitySignaturePrivateKey(Scalar::invert(&alpha)),
    ))
}

impl IdentitySignature {
    /// This method is used by the chain to verify the signature.
    pub fn verify(&self, issuer_public_key: &RistrettoPoint) -> bool {
        let sigma_a_prime = get_g() * self.sigma_r_prime - issuer_public_key * self.sigma_c_prime;
        let sigma_b_prime = self.h * self.sigma_r_prime - self.sigma_z_prime * self.sigma_c_prime;
        let sigma_c_prime = Scalar::from_hash(
            Sha3_512::default()
                .chain(self.h.compress().as_bytes())
                .chain(self.sigma_z_prime.compress().as_bytes())
                .chain(sigma_a_prime.compress().as_bytes())
                .chain(sigma_b_prime.compress().as_bytes()),
        );

        sigma_c_prime == self.sigma_c_prime
    }
}

// TODO: Make sure to add asserts and handles the cases were random numbers end up being zero.
// TODO: Make sure to Zeroize secrets.

#[cfg(test)]
mod tests {
    use crate::{
        sign::{step1, step2, step3, step4},
        IssuerKeys, UserKeys,
    };
    use rand::{rngs::StdRng, SeedableRng};

    const SEED: [u8; 32] = [42u8; 32];

    #[test]
    fn test_happy_path_end_to_end() {
        // ---------------- Done by the User.
        // In the real implementation each party will have its own rng.
        let mut rng = StdRng::from_seed(SEED);
        let user_keypair = UserKeys::new(&mut rng);
        let user_public_key = user_keypair.public;

        // ---------------- Done by the Issuer.
        let issuer_keypair = IssuerKeys::new(&mut rng);
        let issuer_public_key = issuer_keypair.public;

        let (step1_public, step1_secret) = step1(user_public_key, &issuer_keypair, &mut rng);
        let (step2_public, step2_secret) =
            step2(user_public_key, issuer_public_key, step1_public, &mut rng);
        let step3_public = step3(step2_public, step1_secret, &issuer_keypair.private);
        let (signature, _signature_private_key) =
            step4(step3_public, step2_secret, &issuer_public_key).expect("Verification failed!");

        assert!(
            signature.verify(&issuer_public_key),
            "Signature verification failed!"
        );
    }
}
