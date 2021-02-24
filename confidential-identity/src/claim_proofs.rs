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
//! use confidential_identity::{claim_proofs::{Provider, Investor, Verifier},
//!     CddClaimData, ScopeClaimData, ScopeClaimProof, ProviderTrait, InvestorTrait, VerifierTrait};
//! use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
//! use rand::{thread_rng, Rng};
//!
//! let investor_did = [1u8; 32];
//! let investor_unique_id = [2u8; 32];
//! let cdd_claim = CddClaimData::new(&investor_did, &investor_unique_id);
//!
//! let scope_did = [4u8; 32];
//! let scope_claim = ScopeClaimData::new(&scope_did, &investor_unique_id);
//!
//! let mut rng = thread_rng();
//!
//! // CDD Provider side.
//! let cdd_id = Provider::create_cdd_id(&cdd_claim);
//! // => cdd_id is now public knowlegde.
//!
//! // Investor side.
//! let proof = Investor::create_scope_claim_proof(&cdd_claim, &scope_claim, &mut rng);
//! // => proof is now public knowlegde.
//!
//! // Verifier side.
//! let result = Verifier::verify_scope_claim_proof(&proof, &cdd_claim.investor_did, &cdd_id);
//!
//! result.expect("Proofs did not pass!");
//! ```

use crate::{
    errors::{ErrorKind, Fallible},
    InvestorTrait, ProviderTrait, VerifierTrait,
};
use blake2::{Blake2b, Blake2s, Digest};
use cryptography_core::cdd_claim::pedersen_commitments::{
    generate_blinding_factor, PedersenGenerators,
};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use sp_std::prelude::*;

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
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ScopeClaimProof {
    pub proof_scope_id_wellfromed: Signature,
    pub proof_scope_id_cdd_id_match: ZkProofData,
    pub scope_claim: ScopeClaimData,
    pub cdd_claim: CddClaimData,
    pub scope_id: RistrettoPoint,
    pub cdd_id: CddId,
    pub public: RistrettoPoint,
}

/// Stores the Schnorr signature for verifying the wellformedness of scope_id.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Signature {
    sig: Scalar,
    blinded_message: Scalar,
}

/// Stores the zero knowlegde proof data for scope_id and cdd_id matching.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ZkProofData {
    challenge_responses: [Scalar; 2],
    subtract_expressions_res: RistrettoPoint,
    blinded_scope_did_hash: RistrettoPoint,
}

const SIGNATURE_MESSAGE: &str = "SCOPE_ID is Wellformed";

// -------------------------------------------------------------------------------------------
// -                                Trait Implementations                                    -
// -------------------------------------------------------------------------------------------

/// Implements the APIs of the CDD provider.
pub struct Provider;

impl ProviderTrait for Provider {
    fn create_cdd_id(cdd_claim: &CddClaimData) -> CddId {
        cryptography_core::cdd_claim::compute_cdd_id(cdd_claim)
    }
}

/// Implements the APIs of the Investor.
pub struct Investor;

impl InvestorTrait for Investor {
    fn create_scope_claim_proof<R: RngCore + CryptoRng>(
        cdd_claim: &CddClaimData,
        scope_claim: &ScopeClaimData,
        rng: &mut R,
    ) -> ScopeClaimProof {
        let scope_did_hash = slice_to_ristretto_point(scope_claim.scope_did.as_bytes());
        let scope_id = scope_claim.investor_unique_id * scope_did_hash;
        let cdd_id = cryptography_core::cdd_claim::compute_cdd_id(cdd_claim);

        let (proof_scope_id_wellfromed, public) = sign(
            &scope_claim.investor_unique_id,
            &scope_did_hash,
            SIGNATURE_MESSAGE.to_string(),
            rng,
        );

        let proof_scope_id_cdd_id_match =
            gen_zkp(&scope_did_hash, &scope_id, &cdd_id.0, &cdd_claim, rng);

        ScopeClaimProof {
            proof_scope_id_wellfromed,
            proof_scope_id_cdd_id_match,
            scope_claim: *scope_claim,
            cdd_claim: *cdd_claim,
            scope_id,
            cdd_id,
            public,
        }
    }
}

/// Implements the APIs of the Verifier.
pub struct Verifier;

impl VerifierTrait for Verifier {
    fn verify_scope_claim_proof(
        proof: &ScopeClaimProof,
        investor_did: &Scalar,
        cdd_id: &CddId,
    ) -> Fallible<()> {
        let scope_did_hash = slice_to_ristretto_point(proof.scope_claim.scope_did.as_bytes());

        ensure! {cdd_id.0 == proof.cdd_id.0, ErrorKind::SignatureError};

        ensure! {
        verify_signature(
            &proof.proof_scope_id_wellfromed,
            &scope_did_hash,
            &proof.public,
            SIGNATURE_MESSAGE.to_string(),
        ), ErrorKind::SignatureError};

        ensure! {
        verify_zkp(
            &proof.proof_scope_id_cdd_id_match,
            &proof.scope_id,
            &cdd_id.0,
            investor_did,
            &scope_did_hash,
        ), ErrorKind::ZkpError};

        Ok(())
    }
}

// -------------------------------------------------------------------------------------------
// -                                  Internal Functions                                     -
// -------------------------------------------------------------------------------------------

/// Perform a schnorr signature using a custom base point.
fn sign<R: RngCore + CryptoRng>(
    secret: &Scalar,
    base: &RistrettoPoint,
    message: String,
    rng: &mut R,
) -> (Signature, RistrettoPoint) {
    let public = secret * base;

    let k = Scalar::random(rng);
    let r = k * base;
    let blinded_message: [u8; 32] = Blake2s::default()
        .chain(r.compress().to_bytes())
        .chain(message.as_bytes())
        .finalize()
        .into();
    let blinded_message = slice_to_scalar(&blinded_message);
    let sig = k - secret * blinded_message;

    (
        Signature {
            sig,
            blinded_message,
        },
        public,
    )
}

/// Verifies a schnorr signature using a custom base point.
fn verify_signature(
    sig: &Signature,
    base: &RistrettoPoint,
    public: &RistrettoPoint,
    message: String,
) -> bool {
    let r_verif = sig.sig * base + sig.blinded_message * public;
    let blinded_message_verif: [u8; 32] = Blake2s::default()
        .chain(r_verif.compress().to_bytes())
        .chain(message.as_bytes())
        .finalize()
        .into();
    let blinded_message_verif = slice_to_scalar(&blinded_message_verif);

    sig.blinded_message == blinded_message_verif
}

/// ZKP that two points have the same scalar. Uses Fiat-Shamir to generate the challenge.
fn gen_zkp<R: RngCore + CryptoRng>(
    scope_did_hash: &RistrettoPoint,
    scope_id: &RistrettoPoint,
    cdd_id: &RistrettoPoint,
    cdd_claim: &CddClaimData,
    rng: &mut R,
) -> ZkProofData {
    let g = PedersenGenerators::default().generators;
    let expr2 = cdd_id - cdd_claim.investor_did * g[0];
    let cdd_id_random_blind =
        generate_blinding_factor(cdd_claim.investor_did, cdd_claim.investor_unique_id);

    let subtract_expressions_res = expr2 - scope_id;
    let rands: [Scalar; 2] = [Scalar::random(rng), Scalar::random(rng)];
    let blinded_scope_did_hash = rands[0] * (g[1] - scope_did_hash) + rands[1] * g[2];

    let challenge: [u8; 32] = Blake2s::default()
        .chain(blinded_scope_did_hash.compress().to_bytes())
        .chain(scope_id.compress().to_bytes())
        .chain(expr2.compress().to_bytes())
        .finalize()
        .into();
    let challenge = slice_to_scalar(&challenge);

    let challenge_responses = [
        cdd_claim.investor_unique_id * challenge + rands[0],
        cdd_id_random_blind * challenge + rands[1],
    ];

    ZkProofData {
        challenge_responses,
        subtract_expressions_res,
        blinded_scope_did_hash,
    }
}

/// Verify the ZKP.
fn verify_zkp(
    proof: &ZkProofData,
    scope_id: &RistrettoPoint,
    cdd_id: &RistrettoPoint,
    investor_did: &Scalar,
    scope_did_hash: &RistrettoPoint,
) -> bool {
    let g = PedersenGenerators::default().generators;
    let expr2 = cdd_id - investor_did * g[0];

    let challenge: [u8; 32] = Blake2s::default()
        .chain(proof.blinded_scope_did_hash.compress().to_bytes())
        .chain(scope_id.compress().to_bytes())
        .chain(expr2.compress().to_bytes())
        .finalize()
        .into();
    let challenge = slice_to_scalar(&challenge);
    let lhs = proof.challenge_responses[0] * (g[1] - scope_did_hash)
        + proof.challenge_responses[1] * g[2];
    let rhs = (challenge * proof.subtract_expressions_res) + proof.blinded_scope_did_hash;

    lhs == rhs
}

// ------------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    const SEED: [u8; 32] = [42u8; 32];

    #[test]
    fn verify_proofs() {
        let mut rng = StdRng::from_seed(SEED);

        // Use random slices to make claims.
        // Don't make any assumptions about these slices' sizes.
        let mut unique_id_bytes = [0u8; 72];
        rng.fill_bytes(&mut unique_id_bytes);
        let mut did_bytes = [0u8; 32];
        rng.fill_bytes(&mut did_bytes);
        let mut scope_id_bytes = [0u8; 128];
        rng.fill_bytes(&mut scope_id_bytes);
        let cdd_claim = CddClaimData::new(&did_bytes, &unique_id_bytes);
        let scope_claim = ScopeClaimData::new(&scope_id_bytes, &unique_id_bytes);

        // CDD Provider side.
        let cdd_id = Provider::create_cdd_id(&cdd_claim);
        // => cdd_id is now public knowlegde.

        // Investor side.
        let proof = Investor::create_scope_claim_proof(&cdd_claim, &scope_claim, &mut rng);
        // => proof is now public knowlegde.

        // Verifier side.
        let result = Verifier::verify_scope_claim_proof(&proof, &cdd_claim.investor_did, &cdd_id);

        result.unwrap();
    }

    #[test]
    fn test_signature_scheme() {
        let mut rng = StdRng::from_seed(SEED);

        let secret = Scalar::random(&mut rng);
        let base = RistrettoPoint::random(&mut rng);
        let (sig, public) = sign(&secret, &base, "message".to_string(), &mut rng);

        // Positive test.
        let res = verify_signature(&sig, &base, &public, "message".to_string());
        assert!(res);

        // Negative test.
        let res = verify_signature(&sig, &base, &public, "invalid message".to_string());
        assert!(!res);
    }

    #[test]
    fn test_zkp_proof() {
        let mut rng = StdRng::from_seed(SEED);

        let secret = Scalar::random(&mut rng);
        let base = RistrettoPoint::random(&mut rng);
        let investor_did = Scalar::random(&mut rng);

        let pg = PedersenGenerators::default();
        let g = pg.generators;
        let scope_id = secret * base;
        let rb = generate_blinding_factor(investor_did, secret);
        let cdd_id = investor_did * g[0] + secret * g[1] + rb * g[2];
        let cdd_claim = CddClaimData {
            investor_did,
            investor_unique_id: secret,
        };

        let proof = gen_zkp(&base, &scope_id, &cdd_id, &cdd_claim, &mut rng);
        let res = verify_zkp(&proof, &scope_id, &cdd_id, &investor_did, &base);
        assert!(res);
    }
}
