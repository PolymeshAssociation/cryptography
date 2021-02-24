//! The `claim_proofs` library contains API for generating
//! claim proofs and verifying them as part of the
//! Asset Granularity Unique Identity project.
//!
//! The investor would use the `Proof` API to generate
//! the proofs.
//!
//! The verifier would use the `ProofPublicKey` API to verify
//! the proofs, and conclude that an investor's identity matches
//! its claims.
//!
//! ```
//! //use confidential_identity::{Provider, compute_scope_id, build_scope_claim_proof_data,
//! //    CddClaimData, ScopeClaimData, ScopeClaimProof};
//! //use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
//!
//! //// Investor side:
//! //let message = b"some asset ownership claims!";
//!
//! //let investor_did = [1u8; 32];
//! //let investor_unique_id = [2u8; 32];
//! //let cdd_claim = CddClaimData::new(&investor_did, &investor_unique_id);
//!
//! //let scope_did = [4u8; 32];
//! //let scope_claim = ScopeClaimData::new(&scope_did, &investor_unique_id);
//!
//! //let scope_claim_proof_data = build_scope_claim_proof_data(&cdd_claim, &scope_claim);
//! //let pair = ScopeClaimProof::from(scope_claim_proof_data);
//!
//! //let proof = pair.generate_id_match_proof(message);
//! //let cdd_id = Provider.create_cdd_id(&cdd_claim);
//! //let scope_id = compute_scope_id(&scope_claim);
//!
//! //// Verifier side:
//! //use confidential_identity::ProofPublicKey;
//!
//! //let verifier_pub = ProofPublicKey::new(cdd_id, &investor_did, scope_id, &scope_did);
//! //let result = verifier_pub.verify_id_match_proof(message, &proof);
//!
//! //assert!(result);
//! ```
//!

use crate::{InvestorTrait, ProviderTrait, VerifierTrait};
use blake2::{Blake2b, Blake2s, Digest};
use cryptography_core::cdd_claim::pedersen_commitments::PedersenGenerators;
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
//use lazy_static::lazy_static;
use rand_core::{CryptoRng, RngCore};
//use schnorrkel::{context::SigningContext, signing_context, Keypair, PublicKey};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use sp_std::prelude::*;

///// Signing context.
//const SIGNING_CTX: &[u8] = b"PolymathClaimProofs";

//lazy_static! {
//    static ref SIG_CTXT: SigningContext = signing_context(SIGNING_CTX);
//}

/// Create a scalar from a slice of data.
fn slice_to_scalar(data: &[u8]) -> Scalar {
    let mut hash = [0u8; 64];
    hash.copy_from_slice(Blake2b::digest(data).as_slice());
    Scalar::from_bytes_mod_order_wide(&hash)
}

pub fn slice_to_ristretto_point(data: &[u8]) -> RistrettoPoint {
    let mut hash = [0u8; 64];
    hash.copy_from_slice(Blake2b::digest(data).as_slice());
    RistrettoPoint::from_uniform_bytes(&hash)
}

/// The data needed to generate a CDD ID.
pub type CddClaimData = cryptography_core::cdd_claim::CddClaimData;

/// The CDD ID type.
pub type CddId = cryptography_core::cdd_claim::CddId;

/// The data needed to generate a SCOPE ID.
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ScopeClaimData {
    pub scope_did: Scalar,
    pub investor_unique_id: Scalar,
}

impl ScopeClaimData {
    /// Create a Scope Claim Data object from slices of data.
    pub fn new(scope_did: &[u8], investor_unique_id: &[u8]) -> Self {
        ScopeClaimData {
            scope_did: slice_to_scalar(scope_did),
            investor_unique_id: slice_to_scalar(investor_unique_id),
        }
    }
}

/// The data needed to generate a proof that a SCOPE ID matches a CDD ID
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ScopeClaimProofData {
    pub scope_did: Scalar,
    pub scope_did_hash: RistrettoPoint,
    pub investor_did: Scalar,
    pub investor_unique_id: Scalar,
}

/// Contains the Zero Knowledge proof and the proof of wellformedness.
/// This is the construct that the investors will use to generate
/// claim proofs.
#[derive(Debug)]
pub struct ScopeClaimProof {
    proof_scope_id_wellfromed: Signature,
    public: RistrettoPoint,
}

///// An Schnorrkel/Ristretto x25519 ("sr25519") public key.
///// This is the construct that the blockchain validator will use for
///// claim proof validation.
//#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
//pub struct ProofPublicKey {
//    pub_key: PublicKey,
//}

#[derive(Debug)]
struct Signature {
    s: Scalar,
    e: Scalar,
}

// -------------------------------------------------------------------------------------------
// -                                Trait Implementations                                    -
// -------------------------------------------------------------------------------------------

pub struct Provider;

impl ProviderTrait for Provider {
    fn create_cdd_id(cdd_claim: &CddClaimData) -> CddId {
        cryptography_core::cdd_claim::compute_cdd_id(cdd_claim)
    }
}

pub struct Investor;

impl InvestorTrait for Investor {
    fn create_scope_claim_proof<R: RngCore + CryptoRng>(
        cdd_claim: &CddClaimData,
        scope_claim: &ScopeClaimData,
        rng: &mut R,
    ) -> ScopeClaimProof {
        let scope_did_hash = slice_to_ristretto_point(scope_claim.scope_did.as_bytes());
        let scope_id = scope_claim.investor_unique_id * scope_did_hash;

        let (proof_scope_id_wellfromed, public) = sign(
            &scope_claim.investor_unique_id,
            &scope_did_hash,
            "TODO: Sign(SCOPE_ID, Hash(SCOPE_ID))".to_string(),
            rng,
        );

        return ScopeClaimProof {
            proof_scope_id_wellfromed,
            public,
        };
        //let proof_scope_id_cdd_id_match = zkp_scope_id_cdd_id();

        //ScopeClaimProof {
        //    cdd_id,
        //    investor_did,
        //    scope_id,
        //    scope_did,
        //    scope_did_hash,
        //    proof_scope_id_wellfromed,
        //    proof_scope_id_cdd_id_match,
        //}
    }
}

pub struct Verifier;

impl VerifierTrait for Verifier {
    fn verify_scope_claim_proof(
        proof: &ScopeClaimProof,
        scope_claim: &ScopeClaimData,
    ) -> Result<(), ()> {
        let scope_did_hash = slice_to_ristretto_point(scope_claim.scope_did.as_bytes());
        let is_sig_valid = verify(
            &proof.proof_scope_id_wellfromed,
            &scope_did_hash,
            &proof.public,
            "TODO: Sign(SCOPE_ID, Hash(SCOPE_ID))".to_string(),
        );

        if is_sig_valid {
            return Ok(());
        } else {
            return Err(());
        }
    }
}

// -------------------------------------------------------------------------------------------
// -                                  Internal Functions                                     -
// -------------------------------------------------------------------------------------------

fn generate_keypair(
    scope_did_hash: RistrettoPoint,
    inverstor_unique_id: Scalar,
) -> schnorrkel::Keypair {
    use sha3::{digest::FixedOutput, Digest, Sha3_256};
    let nonce = Sha3_256::default()
        .chain("nonce")
        .chain(&inverstor_unique_id.as_bytes())
        .fixed_result();

    let mut exported_private_key = [0u8; 64];
    exported_private_key[..32].copy_from_slice(inverstor_unique_id.as_bytes());
    exported_private_key[32..].copy_from_slice(&nonce);

    let secret = schnorrkel::SecretKey::from_bytes(&exported_private_key)
        .expect("key is always the correct size");

    let public = schnorrkel::keys::PublicKey::from_point(scope_did_hash);
    schnorrkel::Keypair { public, secret }
}

fn sign<R: RngCore + CryptoRng>(
    secret: &Scalar,
    base: &RistrettoPoint,
    message: String,
    rng: &mut R,
) -> (Signature, RistrettoPoint) {
    let public = secret * base;

    let k = Scalar::random(rng);
    let r = k * base;
    let e: [u8; 32] = Blake2s::default()
        .chain(r.compress().to_bytes())
        .chain(message.as_bytes())
        .finalize()
        .into();
    let e = slice_to_scalar(&e);
    let s = k - secret * e;

    (Signature { s, e }, public)
}

fn verify(
    sig: &Signature,
    base: &RistrettoPoint,
    public: &RistrettoPoint,
    message: String,
) -> bool {
    let r_verif = sig.s * base + sig.e * public;
    let e_verif: [u8; 32] = Blake2s::default()
        .chain(r_verif.compress().to_bytes())
        .chain(message.as_bytes())
        .finalize()
        .into();
    let e_verif = slice_to_scalar(&e_verif);

    sig.e == e_verif
}

/// Compute the SCOPE_ID \
/// SCOPE_ID = PedersenCommitment(SCOPE_DID, INVESTOR_UNIQUE_ID, [SCOPE_DID | INVESTOR_UNIQUE_ID])
///
/// # Inputs
/// * `scope_claim` is the scope claim from which to generate the SCOPE_ID
///
/// # Output
/// The Pedersen commitment result.
fn compute_scope_id(scope_claim: &ScopeClaimData) -> RistrettoPoint {
    scope_claim.investor_unique_id * slice_to_ristretto_point(scope_claim.scope_did.as_bytes())
}

//impl ScopeClaimProof {
//    /// Generate an Id match proof.
//    ///
//    /// # Input
//    /// * `message`: the message to generate a proof for.
//    ///
//    /// # Output
//    /// A proof in the form of an Schnorrkel/Ristretto x25519 signature.
//    pub fn generate_id_match_proof(&self, message: &[u8]) -> Signature {
//        self.keypair.sign(SIG_CTXT.bytes(message))
//    }
//}

//impl ProofPublicKey {
//    /// Create a public key object for the blockchain validator.
//    ///
//    /// # Inputs
//    /// * `cdd_id`: the investor's CDD_ID.
//    /// * `investor_did`: the investor's DID.
//    /// * `scope_id`: the investor's SCOPE_ID.
//    /// * `scope_did`: the scope DID
//    pub fn new(
//        cdd_id: CddId,
//        investor_did: &[u8],
//        scope_id: RistrettoPoint,
//        scope_did: &[u8],
//    ) -> Self {
//        let investor_did = slice_to_scalar(investor_did);
//        let scope_did = slice_to_scalar(scope_did);
//        let pg = PedersenGenerators::default();
//
//        let cdd_label_prime = pg.label_prime(cdd_id.0, investor_did);
//        let scope_label_prime = pg.label_prime(scope_id, scope_did);
//        let diff = cdd_label_prime - scope_label_prime;
//
//        let pub_key = PublicKey::from_point(diff);
//        ProofPublicKey { pub_key }
//    }
//
//    /// Verify an Id match proof.
//    ///
//    /// # Inputs
//    /// * `message`: the message to verify the proof for.
//    /// * `sig`: the proof.
//    ///
//    /// # Output
//    /// `true` on a successful verification, `false` otherwise.
//    pub fn verify_id_match_proof(&self, message: &[u8], sig: &Signature) -> bool {
//        self.pub_key
//            .verify_simple(SIGNING_CTX, message, sig)
//            .is_ok()
//    }
//}

// ------------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    const SEED_1: [u8; 32] = [42u8; 32];
    const SEED_2: [u8; 32] = [43u8; 32];

    //#[test]
    //fn match_pub_key_both_sides() {
    //    let expected_public_key = [
    //        102, 132, 8, 112, 82, 12, 133, 155, 7, 47, 56, 166, 4, 178, 144, 27, 78, 252, 169, 28,
    //        30, 215, 62, 126, 248, 158, 208, 35, 9, 210, 148, 49,
    //    ];

    //    let mut rng = StdRng::from_seed(SEED_1);

    //    // Generate random IDs.
    //    // Use random slices to make claims.
    //    // Don't make any assumptions about these slices' sizes.
    //    let mut unique_id_bytes = [0u8; 256];
    //    rng.fill_bytes(&mut unique_id_bytes);
    //    let mut did_bytes = [0u8; 32];
    //    rng.fill_bytes(&mut did_bytes);
    //    let mut scope_id_bytes = [0u8; 128];
    //    rng.fill_bytes(&mut scope_id_bytes);
    //    let cdd_claim = CddClaimData::new(&did_bytes, &unique_id_bytes);
    //    let scope_claim = ScopeClaimData::new(&scope_id_bytes, &unique_id_bytes);

    //    let scope_claim_proof_data = build_scope_claim_proof_data(&cdd_claim, &scope_claim);

    //    // Investor side.
    //    let pair = ScopeClaimProof::from(scope_claim_proof_data);
    //    let cdd_id = Provider.create_cdd_id(&cdd_claim);
    //    let scope_id = compute_scope_id(&scope_claim);

    //    // Verifier side.
    //    let verifier_pub = ProofPublicKey::new(cdd_id, &did_bytes, scope_id, &scope_id_bytes);

    //    // Make sure both sides get the same public key.
    //    assert_eq!(pair.keypair.public, verifier_pub.pub_key);

    //    assert_eq!(verifier_pub.pub_key.to_bytes(), expected_public_key);
    //}

    //#[test]
    //fn verify_proofs() {
    //    let mut rng = StdRng::from_seed(SEED_2);

    //    // Use random slices to make claims.
    //    // Don't make any assumptions about these slices' sizes.
    //    let mut unique_id_bytes = [0u8; 72];
    //    rng.fill_bytes(&mut unique_id_bytes);
    //    let mut did_bytes = [0u8; 32];
    //    rng.fill_bytes(&mut did_bytes);
    //    let mut scope_id_bytes = [0u8; 128];
    //    rng.fill_bytes(&mut scope_id_bytes);
    //    let cdd_claim = CddClaimData::new(&did_bytes, &unique_id_bytes);
    //    let scope_claim = ScopeClaimData::new(&scope_id_bytes, &unique_id_bytes);

    //    let message = &b"I didn't claim anything!".to_vec();
    //    let bad_message = &b"I claim everything!".to_vec();

    //    // Investor side.
    //    let scope_claim_proof_data = build_scope_claim_proof_data(&cdd_claim, &scope_claim);

    //    let pair = ScopeClaimProof::from(scope_claim_proof_data);
    //    let proof = pair.generate_id_match_proof(message);

    //    // Note: the SR 255-19 randomizes the signing process, therefore
    //    // we can't check the `proof` against a  test vector here.

    //    let cdd_id = Provider.create_cdd_id(&cdd_claim);
    //    let scope_id = compute_scope_id(&scope_claim);

    //    // => Investor makes {cdd_id, scope_id, investor_did, scope_did, message, proof} public knowledge.

    //    // Verifier side.
    //    let verifier_pub = ProofPublicKey::new(cdd_id, &did_bytes, scope_id, &scope_id_bytes);

    //    // Positive tests.
    //    let result = verifier_pub.verify_id_match_proof(message, &proof);
    //    assert!(result);

    //    // Negative tests.
    //    let bad_result = verifier_pub.verify_id_match_proof(bad_message, &proof);
    //    assert!(!bad_result);
    //}

    #[test]
    fn test_signature_scheme() {
        let mut rng = StdRng::from_seed(SEED_1);

        let secret = Scalar::random(&mut rng);
        let base = RistrettoPoint::random(&mut rng);
        let (sig, public) = sign(&secret, &base, "message".to_string(), &mut rng);

        let res = verify(&sig, &base, &public, "message".to_string());
        assert!(res);
    }

    fn gen_zkp<R: RngCore + CryptoRng>(
        scope_did_hash: RistrettoPoint,
        scope_id: RistrettoPoint,
        cdd_id: RistrettoPoint,
        cdd_id_random_blind: Scalar,
        investor_did: Scalar,
        investor_unique_id: Scalar,
        rng: &mut R,
    ) -> (Scalar, Scalar, RistrettoPoint, RistrettoPoint) {
        let g = PedersenGenerators::default().generators;
        let expr2 = cdd_id - investor_did * g[0];

        let T = expr2 - scope_id;
        let t = Scalar::random(rng);
        let s = Scalar::random(rng);
        let f = t * (g[1] - scope_did_hash) + s * g[2];

        let c: [u8; 32] = Blake2s::default()
            .chain(f.compress().to_bytes())
            .chain(scope_id.compress().to_bytes())
            .chain(expr2.compress().to_bytes())
            .finalize()
            .into();
        let c = slice_to_scalar(&c);

        let a = investor_unique_id * c + t;
        let b = cdd_id_random_blind * c + s;

        (a, b, T, f)
    }

    fn verify_zkp(
        f: RistrettoPoint,
        scope_id: RistrettoPoint,
        cdd_id: RistrettoPoint,
        investor_did: Scalar,
        a: Scalar,
        b: Scalar,
        scope_did_hash: RistrettoPoint,
        T: RistrettoPoint,
    ) -> bool {
        let g = PedersenGenerators::default().generators;
        let expr2 = cdd_id - investor_did * g[0];

        let c: [u8; 32] = Blake2s::default()
            .chain(f.compress().to_bytes())
            .chain(scope_id.compress().to_bytes())
            .chain(expr2.compress().to_bytes())
            .finalize()
            .into();
        let c = slice_to_scalar(&c);
        let lhs = a * (g[1] - scope_did_hash) + b * g[2];
        let rhs = (c * T) + f;

        lhs == rhs
    }

    #[test]
    fn test_zkp_proof() {
        let mut rng = StdRng::from_seed(SEED_1);

        let secret = Scalar::random(&mut rng);
        let base = RistrettoPoint::random(&mut rng);
        let investor_did = Scalar::random(&mut rng);

        let pg = PedersenGenerators::default();
        let g = pg.generators;
        let rb = Scalar::random(&mut rng);
        let scope_id = secret * base;
        let cdd_id = investor_did * g[0] + secret * g[1] + rb * g[2];

        // proof
        let (a, b, T, f) = gen_zkp(base, scope_id, cdd_id, rb, investor_did, secret, &mut rng);

        // verify
        let res = verify_zkp(f, scope_id, cdd_id, investor_did, a, b, base, T);

        assert!(res);
    }
}
