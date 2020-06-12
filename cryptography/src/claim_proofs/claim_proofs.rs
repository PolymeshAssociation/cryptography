//! The `claim_proofs` library contains API for generating
//! claim proofs and verifying them as part of the
//! Asset Granularity Unique Identity project.
//!
//! The investor would use the `ProofKeyPair` API to generate
//! the proofs.
//!
//! The verifier would use the `ProofPublicKey` API to verify
//! the proofs, and conclude that an investor's identity matches
//! its claims.
//!
//! ```
//! use cryptography::claim_proofs::{compute_cdd_id, compute_scope_id, build_scope_claim_proof_data,
//!     CDDClaimData, ScopeClaimData, ProofKeyPair, RawData};
//!
//! // Investor side:
//! let message = b"some asset ownership claims!";
//!
//! let investor_did = RawData([1u8; 32]);
//! let investor_unique_id = RawData([2u8; 32]);
//! let cdd_claim = CDDClaimData {investor_did, investor_unique_id};
//!
//! let scope_did = RawData([4u8; 32]);
//! let scope_claim = ScopeClaimData {scope_did, investor_unique_id};
//!
//! let scope_claim_proof_data = build_scope_claim_proof_data(&cdd_claim, &scope_claim);
//! let pair = ProofKeyPair::from(scope_claim_proof_data);
//!
//! let proof = pair.generate_id_match_proof(message);
//! let cdd_id = compute_cdd_id(&cdd_claim);
//! let scope_id = compute_scope_id(&scope_claim);
//!
//! // Verifier side:
//! use cryptography::claim_proofs::ProofPublicKey;
//!
//! let verifier_pub = ProofPublicKey::new(cdd_id, &investor_did, scope_id, &scope_did);
//! let result = verifier_pub.verify_id_match_proof(message, &proof);
//!
//! assert!(result);
//! ```
//!

use super::pedersen_commitments::PedersenGenerators;
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use lazy_static::lazy_static;
use schnorrkel::{context::SigningContext, signing_context, Keypair, PublicKey, Signature};
use serde::{Deserialize, Serialize};
use sha3::{
    digest::{FixedOutput, Input},
    Sha3_256, Sha3_512,
};

use sp_std::prelude::*;

/// Signing context.
const SIGNING_CTX: &[u8] = b"PolymathClaimProofs";

lazy_static! {
    static ref SIG_CTXT: SigningContext = signing_context(SIGNING_CTX);
}

#[derive(Debug, Copy, Clone, Default, Serialize, Deserialize)]
pub struct RawData(pub [u8; 32]);

impl AsRef<[u8; 32]> for RawData {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

fn concat(a: RawData, b: RawData) -> Vec<u8> {
    let mut t = Vec::with_capacity(a.0.len() + b.0.len());
    t.extend_from_slice(a.as_ref());
    t.extend_from_slice(b.as_ref());
    t
}

/// The data needed to generate a CDD ID
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct CDDClaimData {
    pub investor_did: RawData,
    pub investor_unique_id: RawData,
}

/// The data needed to generate a SCOPE ID
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct ScopeClaimData {
    pub scope_did: RawData,
    pub investor_unique_id: RawData,
}

/// The data needed to generate a proof that a SCOPE ID matches a CDD ID
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct ScopeClaimProofData {
    pub scope_did: RawData,
    pub investor_did: RawData,
    pub investor_unique_id: RawData,
}

/// An Schnorrkel/Ristretto x25519 ("sr25519") key pair.
/// This is the construct that the investors will use to generate
/// claim proofs.
#[derive(Debug)]
pub struct ProofKeyPair {
    keypair: Keypair,
}

/// An Schnorrkel/Ristretto x25519 ("sr25519") public key.
/// This is the construct that the blockchain validator will use for
/// claim proof validation.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProofPublicKey {
    pub_key: PublicKey,
}

/// Compute the CDD_ID. \
/// CDD_ID = PedersenCommitment(INVESTOR_DID, INVESTOR_UNIQUE_ID, [INVESTOR_DID | INVESTOR_UNIQUE_ID]) \
///
/// # Inputs
/// * `cdd_claim` is the CDD claim from which to generate the CDD_ID
///
/// # Output
/// The Pedersen commitment result.
pub fn compute_cdd_id(cdd_claim: &CDDClaimData) -> RistrettoPoint {
    let pg = PedersenGenerators::default();
    pg.commit(&[
        Scalar::hash_from_bytes::<Sha3_512>(cdd_claim.investor_did.as_ref()),
        Scalar::hash_from_bytes::<Sha3_512>(cdd_claim.investor_unique_id.as_ref()),
        Scalar::hash_from_bytes::<Sha3_512>(
            concat(cdd_claim.investor_did, cdd_claim.investor_unique_id).as_ref(),
        ),
    ])
}

/// Compute the SCOPE_ID \
/// SCOPE_ID = PedersenCommitment(SCOPE_DID, INVESTOR_UNIQUE_ID, [SCOPE_DID | INVESTOR_UNIQUE_ID])
///
/// # Inputs
/// * `scope_claim` is the scope claim from which to generate the SCOPE_ID
/// * `id1` is the second value to commit.
///
/// # Output
/// The Pedersen commitment result.
pub fn compute_scope_id(scope_claim: &ScopeClaimData) -> RistrettoPoint {
    let pg = PedersenGenerators::default();
    pg.commit(&[
        Scalar::hash_from_bytes::<Sha3_512>(scope_claim.scope_did.as_ref()),
        Scalar::hash_from_bytes::<Sha3_512>(scope_claim.investor_unique_id.as_ref()),
        Scalar::hash_from_bytes::<Sha3_512>(
            concat(scope_claim.scope_did, scope_claim.investor_unique_id).as_ref(),
        ),
    ])
}

pub fn build_scope_claim_proof_data(
    cdd_claim: &CDDClaimData,
    scope_claim: &ScopeClaimData,
) -> ScopeClaimProofData {
    ScopeClaimProofData {
        scope_did: scope_claim.scope_did,
        investor_unique_id: cdd_claim.investor_unique_id,
        investor_did: cdd_claim.investor_did,
    }
}

pub type Seed = [u8; 32];

impl From<ScopeClaimProofData> for ProofKeyPair {
    /// Create a key pair object for the investor from a claim data.
    ///
    /// # Input:
    /// `d`: the data required to prove that a SCOPE_ID matches a CDD_ID.
    fn from(d: ScopeClaimProofData) -> Self {
        // Investor's secret key is:
        // Hash([INVESTOR_DID | INVESTOR_UNIQUE_ID]) - Hash([SCOPE_DID | INVESTOR_UNIQUE_ID])
        let first_term = concat(d.investor_did, d.investor_unique_id);
        let second_term = concat(d.scope_did, d.investor_unique_id);
        let secret_key_scalar = Scalar::hash_from_bytes::<Sha3_512>(first_term.as_ref())
            - Scalar::hash_from_bytes::<Sha3_512>(&second_term);

        // Set the secret key's nonce to : ["nonce" | secret_key]
        let mut h = Sha3_256::default();
        h.input("nonce");
        h.input(&secret_key_scalar.as_bytes());
        let nonce = h.fixed_result();

        let mut exported_private_key = Vec::with_capacity(64);
        exported_private_key.extend_from_slice(secret_key_scalar.as_bytes());
        exported_private_key.extend_from_slice(&nonce);

        let secret = schnorrkel::SecretKey::from_bytes(&exported_private_key)
            .expect("key is always the correct size");
        let public = secret.to_public();

        ProofKeyPair {
            keypair: schnorrkel::Keypair { public, secret },
        }
    }
}

impl ProofKeyPair {
    /// Generate an Id match proof.
    ///
    /// # Input
    /// * `message`: the message to generate a proof for.
    ///
    /// # Output
    /// A proof in the form of an Schnorrkel/Ristretto x25519 signature.
    pub fn generate_id_match_proof(&self, message: &[u8]) -> Signature {
        self.keypair.sign(SIG_CTXT.bytes(message))
    }
}

impl ProofPublicKey {
    /// Create a public key object for the blockchain validator.
    ///
    /// # Inputs
    /// * `cdd_id`: the investor's CDD_ID.
    /// * `investor_did`: the investor's DID.
    /// * `scope_id`: the investor's SCOPE_ID.
    /// * `scope_did`: the scope DID
    pub fn new(
        cdd_id: RistrettoPoint,
        investor_did: &RawData,
        scope_id: RistrettoPoint,
        scope_did: &RawData,
    ) -> Self {
        let pg = PedersenGenerators::default();
        let cdd_label_prime = pg.label_prime(
            cdd_id,
            Scalar::hash_from_bytes::<Sha3_512>(investor_did.as_ref()),
        );
        let scope_label_prime = pg.label_prime(
            scope_id,
            Scalar::hash_from_bytes::<Sha3_512>(scope_did.as_ref()),
        );

        let pub_key = PublicKey::from_point(cdd_label_prime - scope_label_prime);
        ProofPublicKey { pub_key }
    }

    /// Verify an Id match proof.
    ///
    /// # Inputs
    /// * `message`: the message to verify the proof for.
    /// * `sig`: the proof.
    ///
    /// # Output
    /// `true` on a successful verification, `false` otherwise.
    pub fn verify_id_match_proof(&self, message: &[u8], sig: &Signature) -> bool {
        self.pub_key
            .verify_simple(SIGNING_CTX, message, sig)
            .is_ok()
    }
}

// ------------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claim_proofs::random_claim;
    use rand::{rngs::StdRng, SeedableRng};

    const SEED_1: [u8; 32] = [42u8; 32];
    const SEED_2: [u8; 32] = [43u8; 32];

    #[test]
    fn match_pub_key_both_sides() {
        let expected_public_key = [
            48, 37, 28, 128, 48, 60, 182, 218, 99, 119, 36, 30, 184, 242, 122, 224, 253, 90, 103,
            203, 187, 234, 53, 49, 45, 116, 56, 211, 135, 72, 214, 68,
        ];

        let mut rng = StdRng::from_seed(SEED_1);
        let (cdd_claim, scope_claim) = random_claim(&mut rng);
        let scope_claim_proof_data = build_scope_claim_proof_data(&cdd_claim, &scope_claim);

        // Investor side.
        let pair = ProofKeyPair::from(scope_claim_proof_data);
        let cdd_id = compute_cdd_id(&cdd_claim);
        let scope_id = compute_scope_id(&scope_claim);

        // Verifier side.
        let verifier_pub = ProofPublicKey::new(
            cdd_id,
            &cdd_claim.investor_did,
            scope_id,
            &scope_claim.scope_did,
        );

        // Make sure both sides get the same public key.
        assert_eq!(pair.keypair.public, verifier_pub.pub_key);

        assert_eq!(verifier_pub.pub_key.to_bytes(), expected_public_key);
    }

    #[test]
    fn verify_proofs() {
        let message = &b"I didn't claim anything!".to_vec();
        let bad_message = &b"I claim everything!".to_vec();

        // Investor side.
        let mut rng = StdRng::from_seed(SEED_2);
        let (cdd_claim, scope_claim) = random_claim(&mut rng);
        let scope_claim_proof_data = build_scope_claim_proof_data(&cdd_claim, &scope_claim);

        let pair = ProofKeyPair::from(scope_claim_proof_data);
        let proof = pair.generate_id_match_proof(message);

        // Note: the SR 255-19 randomizes the signing process, therefore
        // we can't check the `proof` against a  test vector here.

        let cdd_id = compute_cdd_id(&cdd_claim);
        let scope_id = compute_scope_id(&scope_claim);

        // => Investor makes {cdd_id, scope_id, investor_did, scope_did, message, proof} public knowledge.

        // Verifier side.
        let verifier_pub = ProofPublicKey::new(
            cdd_id,
            &cdd_claim.investor_did,
            scope_id,
            &scope_claim.scope_did,
        );

        // Positive tests.
        let result = verifier_pub.verify_id_match_proof(message, &proof);
        assert!(result);

        // Negative tests.
        let bad_result = verifier_pub.verify_id_match_proof(bad_message, &proof);
        assert!(!bad_result);
    }
}
