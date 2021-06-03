//! This library is the implementation of the 2nd iteration of the confidential identity system.
//! The goal of this version is to enable users to create claim with minimal interaction with the
//! PUIS and CDD providers. Moreover, in this version PUIS and CDD providers will store the least
//! amount of information about a user which preserves the privacy of the users even further.
//!
//!
//! The confidential identity libary v2 (CIL2) has the following actors.
//! 1. User
//! 2. Issuer: The PUIS system
//! 3. Identity verifier: The CDD Provider
//! 4. Claim verifier: PolyMesh chain
//!
//!
//! The CIL2 has three main phases:
//! 1. The user communicates with an external identity verifier and obtains a
//!    fingerprint. This is done outside of this library.
//! 2. The user creates a private/public key pair using the APIs provided by the is library and
//!    registers the public key with the issuer along with the fingerprint.
//! 2. [TODO: this should probably be merged into the above] The user then sends the fingerprint
//!    to the issuer and obtains a certificate, which is an attestation of the the identity of the
//!    user. This library provides an API for creating this certificate. The following apis are
//!    related to this phase:
//!    
//!    - TODO: list the APIs
//! 3. The uer creates a CDD Claim and submits it to the chain for verification.
//!    This library provides an API for creating this certificate. The following apis are
//!    related to this phase:
//!    
//!    - TODO: list the APIs
//! 4. The user creates a SCOPE claim and submits it to the chain for verification.
//!    This library provides an API for creating this certificate. The following apis are
//!    related to this phase:
//!    
//!    - TODO: list the APIs
//!
//! Example workflow:
//!
//! ```
//! use confidential_identity_v2::{
//!     UserKeys, IssuerKeys, verify_user_public_key_zkp_sig,
//!     cdd_claim::CddClaim,
//!     scope_claim::ScopeClaim,
//!     sign::{IdentitySignature, step1, step2, step3, step4}
//! };
//! use cryptography_core::{RistrettoPoint, Scalar};
//! use rand::{thread_rng, Rng};
//!
//! // ---------------- Done by the user
//! let mut rng = thread_rng();
//! let keys = UserKeys::new(&mut rng);
//! let identity_proof = keys.generate_identity_proof();
//! // Send `identity_proof` to issuer (PUIS)
//!
//! // ---------------- Done by issuer (PUIS)
//! verify_user_public_key_zkp_sig(keys.public, &identity_proof).expect("Identity verification failed");
//!
//! let user_keypair = UserKeys::new(&mut rng);
//! let user_public_key = user_keypair.public;
//!
//! // ---------------- Done by the Issuer.
//! let issuer_keypair = IssuerKeys::new(&mut rng);
//! let issuer_public_key = issuer_keypair.public;
//!
//! let (step1_public, step1_secret) = step1(user_public_key, &issuer_keypair, &mut rng);
//! let (step2_public, step2_secret) =
//!     step2(user_public_key, issuer_public_key, step1_public, &mut rng);
//! let step3_public = step3(step2_public, step1_secret, &issuer_keypair.private);
//! let (identity_signature, identity_signature_private_key) =
//!     step4(step3_public, step2_secret, &issuer_public_key).expect("Verification failed!");
//!
//! assert!(
//!     identity_signature.verify(&issuer_public_key),
//!     "Signature verification failed!"
//! );
//! // Send the `identity_signature` back to the user.
//!
//! // ---------------- Done by the user
//! let user_did = Scalar::random(&mut rng);
//!
//! let cdd_claim = CddClaim::new(
//!     &identity_signature,
//!     &identity_signature_private_key,
//!     &user_keypair,
//!     user_did,
//!     &mut rng,
//! );
//!
//! // send `cdd_claim` to PolMesh
//!
//! // ---------------- Done by the PolyMesh
//! cdd_claim
//!     .verify(&identity_signature, user_did, issuer_public_key)
//!     .expect("CDD Claim verification failed!");
//!
//! //// ---------------- Done by the user
//! let scope_did = Scalar::random(&mut rng);
//!
//! //// send `scope_claim` to PolyMesh
//! let scope_claim = ScopeClaim::new(&cdd_claim, scope_did, &user_keypair, &mut rng);
//!
//! //// ---------------- Done by the PolyMesh
//! scope_claim
//!     .verify(&cdd_claim, user_did)
//!     .expect("SCOPE Claim verification failed!");
//!
//! ```

use cryptography_core::{
    cdd_claim::PedersenGenerators, CompressedRistretto, RistrettoPoint, Scalar,
};
use rand_core::{CryptoRng, RngCore};
use sha3::{digest::FixedOutput, Digest, Sha3_512};
use zeroize::Zeroize;

/// That `ensure` does not transform into a string representation like `failure::ensure` is doing.
#[allow(unused_macros)]
macro_rules! ensure {
    ($predicate:expr, $context_selector:expr) => {
        if !$predicate {
            return Err($context_selector.into());
        }
    };
}

pub mod cdd_claim;
pub mod errors;
pub mod scope_claim;
pub mod sign;

const PUBLIC_KEY_ZKP_SIG_MSG: &str = "Polymath ZKP Fixed Message Proof";

pub struct UserKeys {
    pub public: RistrettoPoint,
    private: PrivateKey,
}

#[derive(Zeroize)]
#[zeroize(drop)] // Overwrite secret key material with null bytes when it goes out of scope.
pub struct PrivateKey {
    pub(crate) key: Scalar,
    pub(crate) nonce: [u8; 32],
}

pub struct IssuerKeys {
    pub public: RistrettoPoint,
    pub private: Scalar,
}

#[derive(Clone)]
#[allow(non_snake_case)]
pub struct IdentityZkProof {
    R: CompressedRistretto,
    s: Scalar,
}

impl UserKeys {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let key = Scalar::random(rng);
        let public = key * get_g1();
        let nonce_from_secret = Sha3_512::default().chain(&key.as_bytes()).fixed_result();
        let mut nonce = [0u8; 32];
        nonce[..].copy_from_slice(&nonce_from_secret[32..]);

        let private = PrivateKey { key, nonce };
        Self { private, public }
    }

    /// Hook desc.
    ///
    /// Detailed aoesuthaoesh `arg1` aontseuhonsetahus `arg2`. `out1`
    ///
    /// # Arguments
    /// If not redundant
    ///
    /// # Examples
    /// executable examples, edge cases, etc
    ///
    /// # Errors
    /// * if there is any or they can be added to desc
    ///
    /// # Panics
    /// * if there is any
    #[allow(non_snake_case)]
    pub fn generate_identity_proof(&self) -> IdentityZkProof {
        // generate zkp prove
        let mut h = Sha3_512::new();
        let R: CompressedRistretto;
        let r: Scalar;
        let s: Scalar;
        let k: Scalar;

        h.input(&self.private.nonce);
        h.input(PUBLIC_KEY_ZKP_SIG_MSG);

        r = Scalar::from_hash(h);
        R = (r * get_g1()).compress();

        h = Sha3_512::new();
        h.input(R.as_bytes());
        h.input(self.public.compress().as_bytes());
        h.input(PUBLIC_KEY_ZKP_SIG_MSG);

        k = Scalar::from_hash(h);
        s = (k * self.private.key) + r;

        IdentityZkProof { R, s }
    }
}

#[allow(non_snake_case)]
pub fn verify_user_public_key_zkp_sig(
    user_public_key: RistrettoPoint,
    signature: &IdentityZkProof,
) -> Result<(), String> {
    let mut h = Sha3_512::new();
    let R: RistrettoPoint;
    let k: Scalar;
    let minus_A = -user_public_key;

    h.input(signature.R.as_bytes());
    h.input(user_public_key.compress().as_bytes());
    h.input(PUBLIC_KEY_ZKP_SIG_MSG);

    k = Scalar::from_hash(h);
    R = k * minus_A + signature.s * get_g1();

    ensure!(R.compress() == signature.R, "ZKP verification error");

    Ok(())
}

impl IssuerKeys {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let private = Scalar::random(rng);
        // The only difference between this and UserKey is the base generator.
        let public = private * get_g();
        Self { private, public }
    }
}

pub fn get_g() -> RistrettoPoint {
    PedersenGenerators::default().generators[0]
}

pub fn get_g1() -> RistrettoPoint {
    PedersenGenerators::default().generators[1]
}

pub fn get_g2() -> RistrettoPoint {
    PedersenGenerators::default().generators[2]
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    const SEED: [u8; 32] = [42u8; 32];

    #[test]
    fn test_signature_scheme() {
        let mut rng = StdRng::from_seed(SEED);
        let user_keypair = UserKeys::new(&mut rng);

        let identity_zkp_proof = user_keypair.generate_identity_proof();

        assert!(verify_user_public_key_zkp_sig(user_keypair.public, &identity_zkp_proof).is_ok());
    }
}
