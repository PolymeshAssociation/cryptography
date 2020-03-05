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
//! use cryptography::claim_proofs::{RawData, ClaimData, ProofKeyPair, compute_label};
//!
//! // Investor side:
//! let message = b"some asset ownership claims!";
//!
//! let inv_id_0 = RawData([1u8; 32]);
//! let inv_id_1 = RawData([2u8; 32]);
//! let inv_blind = RawData([3u8; 32]);
//! let iss_id = RawData([4u8; 32]);
//!
//! let d = ClaimData {inv_id_0, inv_id_1, inv_blind, iss_id};
//! let pair = ProofKeyPair::from(d);
//!
//! let proof = pair.generate_id_match_proof(message);
//! let did_label = compute_label(&inv_id_0, &inv_id_1, Some(&inv_blind));
//! let claim_label = compute_label(&iss_id, &inv_id_1, None);
//!
//! // Verifier side:
//! use cryptography::claim_proofs::ProofPublicKey;
//!
//! let verifier_pub = ProofPublicKey::new(did_label, &inv_id_0, claim_label, &iss_id);
//! let result = verifier_pub.verify_id_match_proof(message, &proof);
//!
//! assert!(result);
//! ```
//!

use curve25519_dalek::{scalar::Scalar, ristretto::RistrettoPoint};
use sha3::{Sha3_512, Sha3_256, digest::{Input,FixedOutput}};
use schnorrkel::{Keypair, signing_context, Signature, PublicKey};
use crate::pedersen_commitments::PedersenGenerators;

#[cfg(test)]
use rand::RngCore;

/// Signing context.
const SIGNING_CTX: &[u8] = b"PolymathClaimProofs";

#[derive(Debug, Copy, Clone, Default)]
pub struct RawData(pub [u8; 32]);

impl AsRef<[u8; 32]> for RawData {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The 4 claims attributes that are used to calculate the claim proofs.
/// 1. `inv_id_0` corresponds to the `INVESTOR_DID`.
/// 2. `inv_id_1` corresponds to the `INVESTOR_UNIQUE_ID`.
/// 3. `inv_blind` corresponds to the `RANDOM_BLIND`.
/// 4. `iss_id` corresponds to the `TARGET_ASSET_ISSUER`.
#[derive(Debug, Copy, Clone)]
pub struct ClaimData {
    pub inv_id_0: RawData,
    pub inv_id_1: RawData,
    pub inv_blind: RawData,
    pub iss_id: RawData,
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
pub fn compute_label(id0: &RawData, id1: &RawData, blind: Option<&RawData>) -> RistrettoPoint {
    let third_term: Vec<u8> = match blind {
        Some(t) => t.0.to_vec(),
        None => {
            let mut t = Vec::with_capacity(id0.0.len() + id1.0.len());
            t.extend_from_slice(id0.as_ref());
            t.extend_from_slice(id1.as_ref());
            t
        },
    };

    let pg = PedersenGenerators::default();
    pg.commit(&[
        Scalar::hash_from_bytes::<Sha3_512>(id0.as_ref()),
        Scalar::hash_from_bytes::<Sha3_512>(id1.as_ref()),
        Scalar::hash_from_bytes::<Sha3_512>(third_term.as_ref())])
}

pub type Seed = [u8; 32];

impl ProofKeyPair {
    pub fn from(d: ClaimData) -> Self {
        // Investor's secret key is:
        // Hash(RANDOM_BLIND) - Hash([TARGET_ASSET_ISSUER | INVESTOR_UNIQUE_ID])
        let mut second_term = Vec::with_capacity(d.iss_id.0.len() + d.inv_id_1.0.len());
        second_term.extend_from_slice(d.iss_id.as_ref());
        second_term.extend_from_slice(d.inv_id_1.as_ref());

        let secret_key_scalar = Scalar::hash_from_bytes::<Sha3_512>(d.inv_blind.as_ref()) -
            Scalar::hash_from_bytes::<Sha3_512>(&second_term);

        // Set the secret key's nonce to : ["nonce" | secret_key]
        let mut h = Sha3_256::default();
        h.input("nonce");
        h.input(&secret_key_scalar.to_bytes());
        let nonce =  h.fixed_result();

        let mut exported_private_key = Vec::with_capacity(64);
        exported_private_key.extend_from_slice(&secret_key_scalar.to_bytes());
        exported_private_key.extend_from_slice(&nonce);

        let secret = schnorrkel::SecretKey::from_bytes(&exported_private_key)
            .expect("key is always the correct size");
        let public = secret.to_public();

        ProofKeyPair {
            keypair: schnorrkel::Keypair { public, secret },
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
        self.keypair.sign(context.bytes(message))
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
    pub fn new(did_label: RistrettoPoint, investor_public_value: &RawData, claim_label: RistrettoPoint, issuer_public_value: &RawData) -> Self {
        let pg = PedersenGenerators::default();
        let did_label_prime = pg.label_prime(did_label, Scalar::hash_from_bytes::<Sha3_512>(investor_public_value.as_ref()));
        let claim_label_prime = pg.label_prime(claim_label, Scalar::hash_from_bytes::<Sha3_512>(issuer_public_value.as_ref()));

        let pub_key = PublicKey::from_point(did_label_prime - claim_label_prime);
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
        self.pub_key.verify_simple(SIGNING_CTX, message, sig).is_ok()
    }
}

// ------------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{ SeedableRng, rngs::StdRng };

    const SEED_1 : [u8; 32] = [42u8; 32];
    const SEED_2 : [u8; 32] = [43u8; 32];

    fn random_claim<R: RngCore + Sized>(mut rng: R) -> ClaimData {
        let mut inv_id_0 = RawData::default();
        let mut inv_id_1 = RawData::default();
        let mut inv_blind = RawData::default();
        let mut iss_id = RawData::default();

        rng.fill_bytes(&mut inv_id_0.0);
        rng.fill_bytes(&mut inv_id_1.0);
        rng.fill_bytes(&mut inv_blind.0);
        rng.fill_bytes(&mut iss_id.0);

        ClaimData {inv_id_0, inv_id_1, inv_blind, iss_id}
    }

    #[test]
    fn match_pub_key_both_sides() {
        let expected_public_key =
            [234, 60, 137, 157, 161, 149, 69, 12,
             3, 160, 245, 107, 89, 180, 152, 149,
             227, 128, 37, 233, 161, 36, 95, 205,
             193, 35, 163, 204, 60, 154, 231, 111];

        let rng = StdRng::from_seed(SEED_1);
        let d = random_claim(rng);

        // Investor side.
        let pair = ProofKeyPair::from(d);
        let did_label = compute_label(&d.inv_id_0, &d.inv_id_1, Some(&d.inv_blind));
        let claim_label = compute_label(&d.iss_id, &d.inv_id_1, None);

        // Verifier side.
        let verifier_pub = ProofPublicKey::new(did_label, &d.inv_id_0, claim_label, &d.iss_id);

        // Make sure both sides get the same public key.
        assert_eq!(pair.keypair.public, verifier_pub.pub_key);

        assert_eq!(verifier_pub.pub_key.to_bytes(), expected_public_key);
    }

    #[test]
    fn verify_proofs() {
        // let expected_proof =
        //     Signature::from_bytes(&[124, 109, 74, 164, 74, 0, 60, 128,
        //      214, 67, 247, 194, 100, 178, 109, 56,
        //      173, 100, 246, 239, 122, 230, 148, 163,
        //      34, 194, 217, 203, 100, 120, 209, 81,
        //      28, 41, 226, 183, 18, 35, 172, 239,
        //      42, 240, 76, 213, 160, 111, 145, 126,
        //      61, 83, 92, 102, 14, 7, 254, 13,
        //      110, 211, 244, 182, 99, 54, 81, 128 ]).unwrap();
        let message = &b"I didn't claim anything!".to_vec();
        let bad_message = &b"I claim everything!".to_vec();

        // Investor side.
        let rng = StdRng::from_seed(SEED_2);
        let d = random_claim(rng);
        let pair = ProofKeyPair::from(d);
        let proof = pair.generate_id_match_proof(message);

        // todo: turns out even when we fix the nonce we get a different proof everytime.
        // assert_eq!(proof, expected_proof);

        let did_label = compute_label(&d.inv_id_0, &d.inv_id_1, Some(&d.inv_blind));
        let claim_label = compute_label(&d.iss_id, &d.inv_id_1, None);

        // => Investor makes {did_label, claim_label, inv_id_0, iss_id, message, proof} public knowledge.

        // Verifier side.
        let verifier_pub = ProofPublicKey::new(did_label, &d.inv_id_0, claim_label, &d.iss_id);

        // Positive tests.
        let result = verifier_pub.verify_id_match_proof(message, &proof);
        assert!(result);

        // Negative tests.
        let bad_result = verifier_pub.verify_id_match_proof(bad_message, &proof);
        assert!(!bad_result);
    }
}
