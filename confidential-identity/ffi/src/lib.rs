//! The `confidential_identity_ffi` is the Foreign Function Interface (FFI)
//! for the `confidential_identity` library. It contains API for generating
//! claim proofs and verifying them as part of the
//! Asset Granularity Unique Identity project.

extern crate libc;
use confidential_identity::{
    claim_proofs::{Investor, Provider, Verifier},
    cryptography_core::cdd_claim::cdd_claim_data::slice_to_scalar,
    InvestorTrait, ProviderTrait, ScopeClaimProof, VerifierTrait,
};
use libc::size_t;
use rand_core::OsRng;
use std::slice;

pub type ScopeClaimData = confidential_identity::ScopeClaimData;
pub type CddClaimData = confidential_identity::CddClaimData;
pub type CddId = confidential_identity::CddId;
pub type RistrettoPoint = curve25519_dalek::ristretto::RistrettoPoint;

fn box_alloc<T>(x: T) -> *mut T {
    Box::into_raw(Box::new(x))
}

// ------------------------------------------------------------------------
// Data Structures
// ------------------------------------------------------------------------

/// Create a new `CddClaimData` object.
///
/// Caller is responsible for calling `cdd_claim_data_free()` to deallocate this object.
///
/// # Safety
///
/// Caller is also responsible for making sure `investor_did` and
/// `investor_unique_id` point to allocated blocks of memory of `investor_did_size`
/// and `investor_unique_id_size` bytes respectively.
#[no_mangle]
pub unsafe extern "C" fn cdd_claim_data_new(
    investor_did: *const u8,
    investor_did_size: size_t,
    investor_unique_id: *const u8,
    investor_unique_id_size: size_t,
) -> *mut CddClaimData {
    assert!(!investor_did.is_null());
    assert!(!investor_unique_id.is_null());
    let investor_did = slice::from_raw_parts(investor_did, investor_did_size as usize);

    let investor_unique_id =
        slice::from_raw_parts(investor_unique_id, investor_unique_id_size as usize);

    box_alloc(CddClaimData::new(investor_did, investor_unique_id))
}

/// Deallocates a `CddClaimData` object's memory.
///
/// # Safety
///
/// Should only be called on a still-valid pointer to an object returned by
/// `cdd_claim_data_new()`.
#[no_mangle]
pub unsafe extern "C" fn cdd_claim_data_free(ptr: *mut CddClaimData) {
    if ptr.is_null() {
        return;
    }
    Box::from_raw(ptr);
}

/// Create a new `ScopeClaimData` object.
///
/// Caller is responsible for calling `scope_claim_data_free()` to deallocate this object.
///
/// # Safety
///
/// Caller is also responsible for making sure `scope_did` and
/// `investor_unique_id` point to allocated blocks of memory of `scope_did_size`
/// and `investor_unique_id_size` bytes respectively.
#[no_mangle]
pub unsafe extern "C" fn scope_claim_data_new(
    scope_did: *const u8,
    scope_did_size: size_t,
    investor_unique_id: *const u8,
    investor_unique_id_size: size_t,
) -> *mut ScopeClaimData {
    assert!(!scope_did.is_null());
    assert!(!investor_unique_id.is_null());

    let scope_did = slice::from_raw_parts(scope_did, scope_did_size as usize);
    let investor_unique_id =
        slice::from_raw_parts(investor_unique_id, investor_unique_id_size as usize);

    box_alloc(ScopeClaimData::new(scope_did, investor_unique_id))
}

/// Deallocates a `ScopeClaimData` object's memory.
///
/// # Safety
///
/// Should only be called on a still-valid pointer to an object returned by
/// `scope_claim_data_new()`.
#[no_mangle]
pub unsafe extern "C" fn scope_claim_data_free(ptr: *mut ScopeClaimData) {
    if ptr.is_null() {
        return;
    }
    Box::from_raw(ptr);
}

// ------------------------------------------------------------------------
// Provider API
// ------------------------------------------------------------------------

/// Creates a CDD ID from a CDD claim.
///
/// # Safety
///
/// Caller is responsible to make sure `cdd_claim` pointer is a valid
/// `CddClaimData` object, created by this API.
/// Caller is responsible for deallocating memory after use.
#[no_mangle]
pub unsafe extern "C" fn create_cdd_id(cdd_claim: *const CddClaimData) -> *mut CddId {
    assert!(!cdd_claim.is_null());

    let cdd_claim: CddClaimData = *cdd_claim;
    box_alloc(Provider::create_cdd_id(&cdd_claim))
}

// ------------------------------------------------------------------------
// Verifier API
// ------------------------------------------------------------------------

/// Creates a `Signature` from a scope claim proof data and a message.
///
/// # Safety
///
/// Caller is responsible to make sure `scope_claim_proof_data` and `message`
/// pointers are valid objects, created by this API, and `message` points to
/// a block of memory that has at least `message_size` bytes.
/// Caller is responsible for deallocating memory after use.
#[no_mangle]
pub unsafe extern "C" fn create_scope_claim_proof(
    cdd_claim: *const CddClaimData,
    scope_claim: *const ScopeClaimData,
) -> *mut ScopeClaimProof {
    assert!(!cdd_claim.is_null());
    assert!(!scope_claim.is_null());

    let mut rng = OsRng;
    let cdd_claim: CddClaimData = *cdd_claim;
    let scope_claim: ScopeClaimData = *scope_claim;
    let proof = Investor::create_scope_claim_proof(&cdd_claim, &scope_claim, &mut rng);

    box_alloc(proof)
}

/// Deallocates a `ScopeClaimProof` object's memory.
///
/// # Safety
///
/// Should only be called on a still-valid pointer to an object returned by
/// `create_scope_claim_proof()`.
#[no_mangle]
pub unsafe extern "C" fn scope_claim_proof_free(ptr: *mut ScopeClaimProof) {
    if ptr.is_null() {
        return;
    }
    Box::from_raw(ptr);
}

// ------------------------------------------------------------------------
// Verifier API
// ------------------------------------------------------------------------

/// Verifies the signature on a message.
///
/// # Safety
///
/// Caller is responsible to make sure `proof_public_key`, `message`, and `signature`
/// pointers are valid objects, created by this API, and `message` points to a block
/// of memory that has at least `message_size` bytes.
/// Caller is responsible for deallocating memory after use.
#[no_mangle]
pub unsafe extern "C" fn verify_scope_claim_proof(
    proof: *const ScopeClaimProof,
    investor_did: *const u8,
    investor_did_size: size_t,
    scope_did: *const u8,
    scope_did_size: size_t,
    cdd_id: *const CddId,
) -> bool {
    assert!(!proof.is_null());
    assert!(!investor_did.is_null());
    assert!(!cdd_id.is_null());

    let proof: &ScopeClaimProof = &*proof;
    let investor_did = slice::from_raw_parts(investor_did, investor_did_size as usize);
    let investor_did = slice_to_scalar(investor_did);
    let scope_did = slice::from_raw_parts(scope_did, scope_did_size as usize);
    let scope_did = slice_to_scalar(scope_did);
    let cdd_id: CddId = *cdd_id;
    Verifier::verify_scope_claim_proof(proof, &investor_did, &scope_did, &cdd_id).is_ok()
}
