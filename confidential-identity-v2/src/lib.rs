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
//! use confidential_identity_v2::{UserKeys, cdd_claim::CddClaim, ScopeClaim, sign::IdentitySignature};
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
//! let verified_identity = identity_proof.verify().expect("Identity verification must pass");
//! // TODO: Run the identity signature protocol.
//! let identity_signature = IdentitySignature{
//!   h: RistrettoPoint::default(),
//!   sigma_z_prime: RistrettoPoint::default(),
//!   sigma_c_prime: Scalar::default(),
//!   sigma_r_prime: Scalar::default(),
//! };
//! // Send the `identity_signature` back to the user.
//!
//! // ---------------- Done by the user
//! let cdd_claim = CddClaim::new(&identity_signature);
//! // send `cdd_claim` to PolMesh
//!
//! // ---------------- Done by the PolyMesh
//! cdd_claim.verify().expect("CDD claim verification must pass");
//!
//! // ---------------- Done by the user
//! let scope_claim = ScopeClaim::new(&identity_signature, &cdd_claim);
//! // send `scope_claim` to PolyMesh
//!
//! // ---------------- Done by the PolyMesh
//! scope_claim.verify().expect("SCOPE claim verification must pass");
//! ```

use cdd_claim::CddClaim;
use cryptography_core::{cdd_claim::PedersenGenerators, RistrettoPoint, Scalar};
use rand_core::{CryptoRng, RngCore};
use sign::IdentitySignature;

pub mod cdd_claim;
pub mod errors;
pub mod sign;

pub struct UserKeys {
    public: RistrettoPoint,
    private: Scalar,
}

pub struct IssuerKeys {
    public: RistrettoPoint,
    private: Scalar,
}

#[derive(Clone)]
pub struct IdentityZkClaim {}

pub struct IdentityZkVerifiedClaim {}

pub struct IdentityZkProof {
    claim: IdentityZkClaim,
}

pub struct ScopeClaim {}

impl UserKeys {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let private = Scalar::random(rng);
        let public = private * get_g1();
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
    pub fn generate_identity_proof(&self) -> IdentityZkProof {
        // generate zkp prove
        IdentityZkProof::new()
    }
}

impl IssuerKeys {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let private = Scalar::random(rng);
        // The only difference between this and UserKey is the base generator.
        let public = private * get_g();
        Self { private, public }
    }
}

impl IdentityZkProof {
    pub fn new() -> Self {
        // Create the non-interactive proof
        Self {
            claim: IdentityZkClaim {},
        }
    }

    pub fn verify(&self) -> Result<IdentityZkVerifiedClaim, ()> {
        // Verify the proov
        Ok(IdentityZkVerifiedClaim::from(self.claim.clone()))
    }
}

impl From<IdentityZkClaim> for IdentityZkVerifiedClaim {
    fn from(claim: IdentityZkClaim) -> Self {
        Self {}
    }
}

impl ScopeClaim {
    pub fn new(identity_signature: &IdentitySignature, cdd_claim: &CddClaim) -> Self {
        Self {}
    }
    pub fn verify(&self) -> Result<(), ()> {
        Ok(())
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
