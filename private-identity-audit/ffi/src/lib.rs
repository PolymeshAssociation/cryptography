//! The `private_identity_audit_ffi` is the Foreign Function Interface (FFI)
//! for the `private_identity_audit` library. It contains API for generating
//! unique identity membership proofs and verifying them as part of the
//! PIAL project.

extern crate libc;
use cryptography_core::curve25519_dalek::scalar::Scalar;
use libc::size_t;
use macros::ArrBuilder;
use private_identity_audit::{
    uuid_to_scalar, CommittedSetGenerator, ProofGenerator, ProofVerifier, Prover, Verifier,
    VerifierSetGenerator,
};
use rand::{rngs::StdRng, SeedableRng};
use std::{ptr::null_mut, slice};
use uuid::{Builder, Variant, Version};

pub type CddId = cryptography_core::cdd_claim::CddId;
pub type PrivateUids = private_identity_audit::PrivateUids;
pub type CommittedUids = private_identity_audit::CommittedUids;
pub type Challenge = private_identity_audit::Challenge;
pub type VerifierSecrets = private_identity_audit::VerifierSecrets;
pub type ZKPInitialmessage = private_identity_audit::ZKPInitialmessage;
pub type ZKPFinalResponse = private_identity_audit::ZKPFinalResponse;
pub type CddClaimData = cryptography_core::cdd_claim::CddClaimData;

#[repr(C)]
#[derive(ArrBuilder)]
pub struct ArrZKPInitialmessage {
    arr: *mut ZKPInitialmessage,
    n: usize,
    cap: usize,
}

#[repr(C)]
#[derive(ArrBuilder)]
pub struct ArrZKPFinalResponse {
    arr: *mut ZKPFinalResponse,
    n: usize,
    cap: usize,
}

#[repr(C)]
#[derive(ArrBuilder)]
pub struct ArrCddClaimData {
    arr: *mut CddClaimData,
    n: usize,
    cap: usize,
}

#[repr(C)]
#[derive(ArrBuilder)]
pub struct ArrCddId {
    arr: *mut CddId,
    n: usize,
    cap: usize,
}

#[repr(C)]
pub struct VerifierSetGeneratorResults {
    pub verifier_secrets: *mut VerifierSecrets,
    pub committed_uids: *mut CommittedUids,
}

#[repr(C)]
pub struct ProverResults {
    pub prover_initial_messages: *mut ArrZKPInitialmessage,
    pub prover_final_responses: *mut ArrZKPFinalResponse,
    pub committed_uids: *mut CommittedUids,
}

fn box_alloc<T>(x: T) -> *mut T {
    Box::into_raw(Box::new(x))
}

// ------------------------------------------------------------------------
// Data Structures
// ------------------------------------------------------------------------

/// Convert a Uuid byte array into a scalar object.
///
/// Caller is responsible for calling `cdd_claim_data_free()` to deallocate this object.
///
/// # Safety
/// Caller is also responsible for making sure `investor_did` and
/// `investor_unique_id` point to allocated blocks of memory of `investor_did_size`
/// and `investor_unique_id_size` bytes respectively.
#[no_mangle]
pub unsafe extern "C" fn uuid_new(unique_id: *const u8, unique_id_size: size_t) -> *mut Scalar {
    assert!(!unique_id.is_null());
    assert!(unique_id_size == 16);

    let mut uuid_bytes = [0u8; 16];
    uuid_bytes.copy_from_slice(slice::from_raw_parts(unique_id, unique_id_size as usize));

    let uuid = Builder::from_bytes(uuid_bytes)
        .set_variant(Variant::RFC4122)
        .set_version(Version::Random)
        .build();

    box_alloc(uuid_to_scalar(uuid))
}

#[no_mangle]
pub unsafe extern "C" fn uuid_new2(unique_id: *const u8, unique_id_size: size_t) -> *mut Scalar {
    assert!(!unique_id.is_null());
    assert!(unique_id_size == 16);

    let mut uuid_bytes = [0u8; 16];
    uuid_bytes.copy_from_slice(slice::from_raw_parts(unique_id, unique_id_size as usize));

    let uuid = Builder::from_bytes(uuid_bytes)
        .set_variant(Variant::RFC4122)
        .set_version(Version::Random)
        .build();

    box_alloc(uuid_to_scalar(uuid))
}

/// Deallocates a `Scalar` object's memory.
///
/// Should only be called on a still-valid pointer to an object returned by
/// `uuid_new()`.
#[no_mangle]
pub unsafe extern "C" fn scalar_free(ptr: *mut Scalar) {
    if ptr.is_null() {
        return;
    }
    Box::from_raw(ptr);
}

/// Create a new `CddClaimData` object.
///
/// Caller is responsible for calling `cdd_claim_data_free()` to deallocate this object.
///
/// # Safety
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
/// Should only be called on a still-valid pointer to an object returned by
/// `cdd_claim_data_new()`.
#[no_mangle]
pub unsafe extern "C" fn cdd_claim_data_free(ptr: *mut CddClaimData) {
    if ptr.is_null() {
        return;
    }
    Box::from_raw(ptr);
}

/// Deallocates a `VerifierSetGeneratorResults` object's memory.
///
/// Should only be called on a still-valid pointer to an object returned by
/// `generate_committed_set()`.
#[no_mangle]
pub unsafe extern "C" fn verifier_set_generator_results_free(
    ptr: *mut VerifierSetGeneratorResults,
) {
    if ptr.is_null() {
        return;
    }
    Box::from_raw(ptr);
}

/// Deallocates a `ProverResults` object's memory.
///
/// Should only be called on a still-valid pointer to an object returned by
/// `generate_proofs()`.
#[no_mangle]
pub unsafe extern "C" fn prover_results_free(ptr: *mut ProverResults) {
    if ptr.is_null() {
        return;
    }
    Box::from_raw(ptr);
}

/// Deallocates a `TODO` object's memory.
///
/// Should only be called on a still-valid pointer to an object returned by
/// `TODO()`.
/// TODO: Do the same for the other arrays as well.
#[no_mangle]
pub unsafe extern "C" fn todo(ptr: *mut ArrZKPInitialmessage) {
    if ptr.is_null() {
        return;
    }
    // TODO std::mem::forget()
    Box::from_raw(ptr);
}

// ------------------------------------------------------------------------
// Prover API
// ------------------------------------------------------------------------

/// Creates a `InitialProverResults` object from a CDD claim and a seed.
///
///
/// # Safety
/// Caller is responsible to make sure `cdd_claim` is a valid
/// pointer to a `CddClaimData` object, and `seed` is a random
/// 32-byte array.
/// Caller is responsible for deallocating memory after use.
#[no_mangle]
pub unsafe extern "C" fn generate_proofs(
    cdd_claims: *const ArrCddClaimData,
    committed_uids: *const CommittedUids,
    seed: *const u8,
    seed_size: size_t,
) -> *mut ProverResults {
    assert!(!cdd_claims.is_null());
    assert!(!seed.is_null());
    assert!(seed_size == 32);

    let cdd_claims: &[CddClaimData] = &(*cdd_claims).to_vec();
    let committed_uids_vec: &CommittedUids = &*committed_uids;

    let mut rng_seed = [0u8; 32];
    rng_seed.copy_from_slice(slice::from_raw_parts(seed, seed_size as usize));
    let mut rng = StdRng::from_seed(rng_seed);

    let result = Prover::generate_proofs::<StdRng>(cdd_claims, committed_uids_vec, &mut rng);

    // Log the error and return.
    if result.is_err() {
        println!("Step 2) Prover -> Verifier error: {:?}", result.is_err());
        return null_mut();
    }

    let (initial_message_vec, final_responses_vec, re_committed_uids) = result.unwrap();

    box_alloc(ProverResults {
        prover_initial_messages: box_alloc(ArrZKPInitialmessage::new(initial_message_vec)),
        prover_final_responses: box_alloc(ArrZKPFinalResponse::new(final_responses_vec)),
        committed_uids: box_alloc(re_committed_uids),
    })
}

// ------------------------------------------------------------------------
// VerifierSetGenerator API
// ------------------------------------------------------------------------

/// Creates a `VerifierSetGeneratorResults` object from a private Uuid (as
/// a Scalar object), a minimum set size, and a seed.
///
/// # Safety
/// Caller is responsible to make sure `private_unique_identifiers`
/// is a valid pointer to a `Scalar` object, and `seed` is a random
/// 32-byte array.
/// Caller is responsible for deallocating memory after use.
#[no_mangle]
pub unsafe extern "C" fn generate_committed_set(
    private_unique_identifiers: *mut Scalar,
    private_unique_identifiers_size: size_t,
    min_set_size: *const size_t,
    seed: *const u8,
    seed_size: size_t,
) -> *mut VerifierSetGeneratorResults {
    assert!(!private_unique_identifiers.is_null());
    assert!(private_unique_identifiers_size != 0);
    assert!(!seed.is_null());
    assert!(seed_size == 32);

    let unique_identifiers = private_identity_audit::PrivateUids(
        slice::from_raw_parts_mut(private_unique_identifiers, private_unique_identifiers_size)
            .into(),
    );

    let min_set_size: Option<usize> = match min_set_size.is_null() {
        true => None,
        false => Some(*min_set_size as usize),
    };

    let mut rng_seed = [0u8; 32];
    rng_seed.copy_from_slice(slice::from_raw_parts(seed, seed_size as usize));
    let mut rng = StdRng::from_seed(rng_seed);

    let result =
        VerifierSetGenerator::generate_committed_set(unique_identifiers, min_set_size, &mut rng);

    // Log the error and return.
    if result.is_err() {
        println!("Step 1) Verifier -> Prover error: {:?}", result.is_err());
        return null_mut();
    }

    let (verifier_secrets, committed_uids) = result.unwrap();

    box_alloc(VerifierSetGeneratorResults {
        verifier_secrets: box_alloc(verifier_secrets),
        committed_uids: box_alloc(committed_uids),
    })
}

// ------------------------------------------------------------------------
// Verifier API
// ------------------------------------------------------------------------

/// Verifies the proof of a Uuid's membership in a set of Uuids.
///
/// # Safety
/// Caller is responsible to make sure `initial_message`,
/// `final_response`, `challenge`, `cdd_id`, `verifier_secrets`,
/// and `re_committed_uids` pointers are valid objects, created by
/// this API.
/// Caller is responsible for deallocating memory after use.
#[no_mangle]
pub unsafe extern "C" fn verify_proofs(
    initial_messages: *const ArrZKPInitialmessage,
    final_responses: *const ArrZKPFinalResponse,
    cdd_ids: *const ArrCddId,
    verifier_secrets: *const VerifierSecrets,
    re_committed_uids: *const CommittedUids,
) -> bool {
    assert!(!initial_messages.is_null());
    assert!(!final_responses.is_null());
    assert!(!cdd_ids.is_null());
    assert!(!verifier_secrets.is_null());
    assert!(!re_committed_uids.is_null());

    let initial_messages: &[ZKPInitialmessage] = &(*initial_messages).to_vec();
    let final_responses: &[ZKPFinalResponse] = &(*final_responses).to_vec();

    let cdd_ids: &[CddId] = &(*cdd_ids).to_vec();
    let verifier_secrets: &VerifierSecrets = &*verifier_secrets;
    let re_committed_uids: &CommittedUids = &*re_committed_uids;

    let results = Verifier::verify_proofs(
        initial_messages,
        final_responses,
        cdd_ids,
        verifier_secrets,
        re_committed_uids,
    );

    // Log the error.
    for (i, result) in results.iter().enumerate() {
        if result.is_err() {
            println!(
                "Step 4) Verifier error is statement #{}: {:?}",
                i,
                result.is_err()
            );
            return false;
        }
    }

    true
}
