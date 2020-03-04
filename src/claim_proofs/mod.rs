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
//! use cryptography::claim_proofs::{ClaimData, ProofKeyPair, compute_label};
//!
//! // Investor side:
//! let inv_id_0 = [28, 186, 16, 209, 13, 185, 38, 241, 102, 195, 194, 151, 237, 105, 92, 179, 59, 12, 150, 197, 149, 8, 75, 81, 2, 141, 69, 94, 132, 8, 97, 239];
//! let inv_id_1 = [0, 220, 83, 102, 85, 220, 195, 179, 141, 72, 48, 1, 215, 62, 99, 206, 119, 116, 200, 133, 206, 210, 169, 179, 160, 111, 120, 204, 103, 50, 18, 100];
//! let inv_blind = [191, 16, 112, 187, 85, 110, 121, 158, 222, 186, 137, 10, 187, 115, 84, 52, 93, 109, 158, 117, 6, 143, 214, 207, 233, 98, 45, 163, 42, 212, 58, 168];
//! let iss_id = [248, 224, 196, 2, 197, 199, 222, 98, 104, 117, 148, 27, 119, 163, 26, 136, 163, 142, 155, 1, 253, 86, 172, 198, 138, 163, 27, 116, 121, 124, 163, 164];
//!
//! let message = &[73, 32, 100, 105, 100, 110, 39, 116, 32, 99, 108, 97, 105, 109, 32, 97, 110, 121, 116, 104, 105, 110, 103, 33];
//!
//! let d = ClaimData::new(inv_id_0, inv_id_1, inv_blind, iss_id);
//! let pair = ProofKeyPair::new(d);
//!
//! let proof = pair.generate_id_match_proof(message);
//! let did_label = compute_label(inv_id_0, inv_id_1, Some(inv_blind));
//! let claim_label = compute_label(iss_id, inv_id_1, None);
//!
//! // Verifier side:
//! use cryptography::claim_proofs::{ProofPublicKey};
//!
//! let verifier_pub = ProofPublicKey::new(did_label, inv_id_0, claim_label, iss_id);
//! let result = verifier_pub.verify_id_match_proof(message, &proof);
//!
//! assert!(result);
//! ```
//!

use curve25519_dalek::{scalar::Scalar, ristretto::RistrettoPoint};
use sha3::Sha3_512;
use schnorrkel::{Keypair, signing_context, Signature, PublicKey};
use crate::pedersen_commitments::{PedersenGenerators};

/// Signing context.
const SIGNING_CTX: &[u8] = b"PolymathClaimProofs";

/// The 4 claims attributes that are used to calculate the claim proofs.
/// 1. `inv_id_0` corresponds to the `INVESTOR_DID`.
/// 2. `inv_id_1` corresponds to the `INVESTOR_UNIQUE_ID`.
/// 3. `inv_blind` corresponds to the `RANDOM_BLIND`.
/// 4. `iss_id` corresponds to the `TARGET_ASSET_ISSUER`.
#[derive(Debug, Copy, Clone)]
pub struct ClaimData {
    inv_id_0: [u8; 32],
    inv_id_1: [u8; 32],
    inv_blind: [u8; 32],
    iss_id: [u8; 32],
}

impl ClaimData {
    pub fn new(inv_id_0: [u8; 32], inv_id_1: [u8; 32], inv_blind: [u8; 32], iss_id: [u8; 32]) -> Self {
        ClaimData {
            inv_id_0,
            inv_id_1,
            inv_blind,
            iss_id,
        }
    }
}

/// An Schnorrkel/Ristretto x25519 ("sr25519") key pair.
/// This is the construct that the investors will use to generate
/// claim proofs.
#[derive(Default, Debug)]
pub struct ProofKeyPair {
    keypair: Keypair,
}

/// An Schnorrkel/Ristretto x25519 ("sr25519") public key.
/// This is the construct that the blockchain validator will use for
/// claim proof validation.
#[derive(Copy, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProofPublicKey {
    pub_key: PublicKey,
}

/// Compute DID or claim labels. \
/// DID_LABEL = PedersenCommitment(INVESTOR_DID, INVESTOR_UNIQUE_ID, RANDOM_BLIND) \
/// CLAIM_LABEL = PedersenCommitment(TARGET_ASSET_ISSUER, INVESTOR_UNIQUE_ID, [TARGET_ASSET_ISSUER | INVESTOR_UNIQUE_ID])
///
/// # Inputs
/// * `id0` is the first value to commit.
/// * `id1` is the second value to commit.
/// * `blind` is the third value to commit. If this term is not provided, `[id0|id1]` will be used as the third value.
///
/// # Output
/// The Pedersen commitment result.
pub fn compute_label(id0:[u8; 32], id1: [u8; 32], blind: Option<[u8; 32]>) -> RistrettoPoint {
    let third_term: Vec<u8> = match blind {
        Some(t) => t.to_vec(),
        None => {
            let mut t = Vec::with_capacity(id0.len() + id1.len());
            t.extend_from_slice(&id0.to_vec());
            t.extend_from_slice(&id1.to_vec());
            t
        },
    };

    let pg = PedersenGenerators::default();
    pg.commit(&[
        Scalar::hash_from_bytes::<Sha3_512>(&id0),
        Scalar::hash_from_bytes::<Sha3_512>(&id1),
        Scalar::hash_from_bytes::<Sha3_512>(&third_term)])
}

impl ProofKeyPair {
    /// Create a key pair object for the investor from the investor id,
    /// and the claim attributes.
    ///
    /// # Input:
    /// `d`: the claim data.
    pub fn new(d: ClaimData) -> Self {
        // Investor's secret key is:
        // Hash(RANDOM_BLIND) - Hash([TARGET_ASSET_ISSUER | INVESTOR_UNIQUE_ID])
        let mut second_term = Vec::with_capacity(d.iss_id.len() + d.inv_id_1.len());
        second_term.extend_from_slice(&d.iss_id.to_vec());
        second_term.extend_from_slice(&d.inv_id_1.to_vec());

        let secret_key_scalar = Scalar::hash_from_bytes::<Sha3_512>(&d.inv_blind) -
            Scalar::hash_from_bytes::<Sha3_512>(&second_term);

        // Note: This will generate a new nondeterministic nonce everytime this constructor is called.
        // A potential problem is that the investor will get a different claim proof for the
        // same claim everytime they run this process. It may or may not be an issue.
        // Alternatively this constructor could take in a seed and use a deterministic RNG.
        let nonce: [u8; 32] = rand::random();
        let mut exported_private_key = Vec::with_capacity(64);
        exported_private_key.extend_from_slice(&secret_key_scalar.to_bytes());
        exported_private_key.extend_from_slice(&nonce);

        let secret = schnorrkel::SecretKey::from_bytes(&exported_private_key)
            .expect("key is always the correct size; qed");
        let public_key = secret.to_public();

        ProofKeyPair {
            keypair: schnorrkel::Keypair { public: public_key, secret: secret },
        }
    }

    /// Generate an Id match proof.
    ///
    /// # Input
    /// * `message`: the message to generate a proof for.
    ///
    /// # Output
    /// A proof in the form of an Schnorrkel/Ristretto x25519 signature.
    pub fn generate_id_match_proof(&self, message: &[u8]) -> Signature {
        let context = signing_context(SIGNING_CTX);
        self.keypair.sign(context.bytes(message)).into()
    }
}

impl ProofPublicKey {
    /// Create a public key object for the blockchain validator.
    ///
    /// # Inputs
    /// * `did_label`: the investor's DID label.
    /// * `investor_public_value`: the investor's DID.
    /// * `claim_label`: the claim's label.
    /// * `issuer_public_value`: the asset issuer's Id.
    pub fn new(did_label: RistrettoPoint, investor_public_value: [u8; 32], claim_label: RistrettoPoint, issuer_public_value: [u8; 32]) -> Self {
        let pg = PedersenGenerators::default();
        let did_label_prime = pg.label_prime(did_label, Scalar::hash_from_bytes::<Sha3_512>(&investor_public_value));
        let claim_label_prime = pg.label_prime(claim_label, Scalar::hash_from_bytes::<Sha3_512>(&issuer_public_value));

        let pub_key = PublicKey::from_point(did_label_prime - claim_label_prime);
        ProofPublicKey {
            pub_key: pub_key,
        }
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
        self.pub_key.verify_simple(SIGNING_CTX, message, sig).is_ok()
    }
}

// ------------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn match_pub_key_both_sides() {
        // Note that generally testing with random numbers isn't desirable, since
        // when/if it fails in production, and you don't have access to the trace
        // it is not helpful.
        let inv_id_0: [u8; 32] = rand::random();
        let inv_id_1: [u8; 32] = rand::random();
        let inv_blind: [u8; 32] = rand::random();
        let iss_id: [u8; 32] = rand::random();

        // Investor side.
        let d = ClaimData::new(inv_id_0, inv_id_1, inv_blind, iss_id);
        let pair = ProofKeyPair::new(d);
        let did_label = compute_label(inv_id_0, inv_id_1, Some(inv_blind));
        let claim_label = compute_label(iss_id, inv_id_1, None);

        // Verifier side.
        let verifier_pub = ProofPublicKey::new(did_label, inv_id_0, claim_label, iss_id);

        // Make sure both sides get the same public key.
        assert_eq!(pair.keypair.public, verifier_pub.pub_key);
    }

    #[test]
    fn verify_proofs() {
        let message = &b"I didn't claim anything!".to_vec();
        let bad_message = &b"I claim everything!".to_vec();

        // Investor side.
        let inv_id_0: [u8; 32] = rand::random();
        let inv_id_1: [u8; 32] = rand::random();
        let inv_blind: [u8; 32] = rand::random();
        let iss_id: [u8; 32] = rand::random();
        let d = ClaimData::new(inv_id_0, inv_id_1, inv_blind, iss_id);
        let pair = ProofKeyPair::new(d);
        let proof = pair.generate_id_match_proof(message);

        let did_label = compute_label(inv_id_0, inv_id_1, Some(inv_blind));
        let claim_label = compute_label(iss_id, inv_id_1, None);

        // => Investor makes {did_label, claim_label, inv_id_0, iss_id, message, proof} public knowledge.

        // Verifier side.
        let verifier_pub = ProofPublicKey::new(did_label, inv_id_0, claim_label, iss_id);

        // Positive tests.
        let result = verifier_pub.verify_id_match_proof(message, &proof);
        assert!(result);

        // Negative tests.
        let bad_result = verifier_pub.verify_id_match_proof(bad_message, &proof);
        assert!(!bad_result);
    }
}
