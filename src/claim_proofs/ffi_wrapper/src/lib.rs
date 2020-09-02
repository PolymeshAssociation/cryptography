//! The `claim_proofs_ffi` is the Foreign Function Interface (FFI)
//! for the `claim_proofs` library. It contains API for generating
//! claim proofs and verifying them as part of the
//! Asset Granularity Unique Identity project.

extern crate libc;
use libc::size_t;
use std::slice;

use cryptography::claim_proofs::{build_scope_claim_proof_data, compute_cdd_id, compute_scope_id};

pub type ScopeClaimData = cryptography::claim_proofs::ScopeClaimData;
pub type ScopeClaimProofData = cryptography::claim_proofs::ScopeClaimProofData;
pub type ProofPublicKey = cryptography::claim_proofs::ProofPublicKey;
pub type ProofKeyPair = cryptography::claim_proofs::ProofKeyPair;
pub type CDDClaimData = cryptography::claim_proofs::CDDClaimData;
pub type Signature = schnorrkel::Signature;
pub type Scalar = curve25519_dalek::scalar::Scalar;
pub type RistrettoPoint = curve25519_dalek::ristretto::RistrettoPoint;

// ------------------------------------------------------------------------
// Data Structures
// ------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn scalar_new(scalar_bits: *const u8, len: size_t) -> *mut Scalar {
    assert!(!scalar_bits.is_null() && len == 32);

    let mut scalar_slice = [0u8; 32];
    scalar_slice
        .copy_from_slice(unsafe { &slice::from_raw_parts(scalar_bits, len as usize)[..32] });

    let scalar = Scalar::from_bits(scalar_slice);
    Box::into_raw(Box::new(scalar))
}

#[no_mangle]
pub extern "C" fn scalar_free(ptr: *mut Scalar) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        Box::from_raw(ptr);
    }
}

#[no_mangle]
pub extern "C" fn cdd_claim_data_new(
    investor_did: *mut Scalar,
    investor_unique_id: *mut Scalar,
) -> *mut CDDClaimData {
    assert!(!investor_did.is_null());
    assert!(!investor_unique_id.is_null());

    let investor_did: Scalar = unsafe { *investor_did };
    let investor_unique_id: Scalar = unsafe { *investor_unique_id };
    Box::into_raw(Box::new(CDDClaimData {
        investor_did,
        investor_unique_id,
    }))
}

#[no_mangle]
pub extern "C" fn cdd_claim_data_free(ptr: *mut CDDClaimData) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        Box::from_raw(ptr);
    }
}

#[no_mangle]
pub extern "C" fn scope_claim_data_new(
    scope_did: *mut Scalar,
    investor_unique_id: *mut Scalar,
) -> *mut ScopeClaimData {
    assert!(!scope_did.is_null());
    assert!(!investor_unique_id.is_null());

    let scope_did: Scalar = unsafe { *scope_did };
    let investor_unique_id: Scalar = unsafe { *investor_unique_id };
    Box::into_raw(Box::new(ScopeClaimData {
        scope_did,
        investor_unique_id,
    }))
}

#[no_mangle]
pub extern "C" fn scope_claim_data_free(ptr: *mut ScopeClaimData) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        Box::from_raw(ptr);
    }
}

#[no_mangle]
pub extern "C" fn scope_claim_proof_data_free(ptr: *mut ScopeClaimProofData) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        Box::from_raw(ptr);
    }
}

#[no_mangle]
pub extern "C" fn proof_public_key_new(
    cdd_id: *mut RistrettoPoint,
    investor_did: *mut Scalar,
    scope_id: *mut RistrettoPoint,
    scope_did: *mut Scalar,
) -> *mut ProofPublicKey {
    assert!(!cdd_id.is_null());
    assert!(!investor_did.is_null());
    assert!(!scope_id.is_null());
    assert!(!scope_did.is_null());

    let cdd_id: RistrettoPoint = unsafe { *cdd_id };
    let investor_did: Scalar = unsafe { *investor_did };
    let scope_id: RistrettoPoint = unsafe { *scope_id };
    let scope_did: Scalar = unsafe { *scope_did };

    let proof_public_key = ProofPublicKey::new(cdd_id, investor_did, scope_id, scope_did);

    Box::into_raw(Box::new(proof_public_key))
}

#[no_mangle]
pub extern "C" fn proof_public_key_free(ptr: *mut ProofPublicKey) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        Box::from_raw(ptr);
    }
}

#[no_mangle]
pub extern "C" fn signature_free(ptr: *mut Signature) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        Box::from_raw(ptr);
    }
}

// ------------------------------------------------------------------------
// Prover API
// ------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn build_scope_claim_proof_data_wrapper(
    cdd_claim: *const CDDClaimData,
    scope_claim: *const ScopeClaimData,
) -> *mut ScopeClaimProofData {
    assert!(!cdd_claim.is_null());
    assert!(!scope_claim.is_null());

    let cdd_claim: CDDClaimData = unsafe { *cdd_claim };
    let scope_claim: ScopeClaimData = unsafe { *scope_claim };
    Box::into_raw(Box::new(build_scope_claim_proof_data(
        &cdd_claim,
        &scope_claim,
    )))
}

#[no_mangle]
pub extern "C" fn compute_cdd_id_wrapper(cdd_claim: *const CDDClaimData) -> *mut RistrettoPoint {
    assert!(!cdd_claim.is_null());

    let cdd_claim: CDDClaimData = unsafe { *cdd_claim };
    Box::into_raw(Box::new(compute_cdd_id(&cdd_claim)))
}

#[no_mangle]
pub extern "C" fn compute_scope_id_wrapper(
    scope_claim: *const ScopeClaimData,
) -> *mut RistrettoPoint {
    assert!(!scope_claim.is_null());

    let scope_claim: ScopeClaimData = unsafe { *scope_claim };
    Box::into_raw(Box::new(compute_scope_id(&scope_claim)))
}

#[no_mangle]
pub extern "C" fn generate_id_match_proof_wrapper(
    scope_claim_proof_data: *mut ScopeClaimProofData,
    message: *const u8,
    message_size: size_t,
) -> *mut Signature {
    assert!(!scope_claim_proof_data.is_null());
    assert!(!message.is_null());
    // We allow zero size messages.

    let message_slice = unsafe { slice::from_raw_parts(message, message_size as usize) };
    let scope_claim_proof_data: ScopeClaimProofData = unsafe { *scope_claim_proof_data };
    let pair = ProofKeyPair::from(scope_claim_proof_data);
    let proof = pair.generate_id_match_proof(message_slice);

    Box::into_raw(Box::new(proof))
}

// ------------------------------------------------------------------------
// Verifier API
// ------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn verify_id_match_proof_wrapper(
    proof_public_key: *const ProofPublicKey,
    message: *const u8,
    message_size: size_t,
    signature: *const Signature,
) -> bool {
    assert!(!proof_public_key.is_null());
    assert!(!message.is_null());
    // We allow zero size messages.

    let message_slice = unsafe { slice::from_raw_parts(message, message_size as usize) };
    let proof_public_key: ProofPublicKey = unsafe { *proof_public_key };
    let signature: Signature = unsafe { *signature };

    proof_public_key.verify_id_match_proof(message_slice, &signature)
}
