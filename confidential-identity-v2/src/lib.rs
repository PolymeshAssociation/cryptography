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
//! use confidential_identity_v2::{UserKeys, IdentitySignature, CddClaim, ScopeClaim};
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
//! let identity_signature = IdentitySignature::new(verified_identity);
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

use cryptography_core::{
    asset_proofs::{ElgamalPublicKey, ElgamalSecretKey},
    Scalar,
};
use rand_core::{CryptoRng, RngCore};

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

pub struct UserKeys {
    public: ElgamalPublicKey,
    secret: ElgamalSecretKey,
}

#[derive(Clone)]
pub struct IdentityZkClaim {}

pub struct IdentityZkVerifiedClaim {}

pub struct IdentityZkProof {
    claim: IdentityZkClaim,
}

pub struct IdentitySignature {}

pub struct CddClaim {}

pub struct ScopeClaim {}

impl UserKeys {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let key = Scalar::random(rng);
        let secret = ElgamalSecretKey::new(key);
        let public = secret.get_public_key();
        Self { secret, public }
    }
    pub fn generate_identity_proof(&self) -> IdentityZkProof {
        // generate zkp prove
        IdentityZkProof::new()
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

impl IdentitySignature {
    pub fn new(verified_identity: IdentityZkVerifiedClaim) -> Self {
        // Creates a signature for a verified identity
        Self {}
    }
}

impl CddClaim {
    pub fn new(identity_signature: &IdentitySignature) -> Self {
        Self {}
    }
    pub fn verify(&self) -> Result<(), ()> {
        Ok(())
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

pub mod errors;
