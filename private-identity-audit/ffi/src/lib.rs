//! The `private_identity_audit_ffi` is the Foreign Function Interface (FFI)
//! for the `private_identity_audit` library. It contains API for generating
//! unique identity membership proofs and verifying them as part of the
//! PIAL project.

#![feature(vec_into_raw_parts)]

extern crate libc;
use codec::{Decode, Encode};
use cryptography_core::{
    cdd_claim::{CddClaimData, CddId},
    curve25519_dalek::scalar::Scalar,
};
use libc::size_t;
use private_identity_audit::{
    uuid_to_scalar, CommittedSetGenerator, CommittedUids, PrivateUids, ProofGenerator,
    ProofVerifier, Prover, Verifier, VerifierSecrets, VerifierSetGenerator, ZKPFinalResponse,
    ZKPInitialmessage,
};
use rand::{rngs::StdRng, SeedableRng};
use std::{ptr::null_mut, slice};
use uuid::{Builder, Variant, Version};

#[repr(C)]
#[derive(Debug, Clone)]
pub struct VecEncoding {
    arr: *mut u8,
    n: usize,
}

impl VecEncoding {
    pub fn new(vec: Vec<u8>) -> Self {
        let (ptr, len, _cap) = vec.into_raw_parts();
        Self { arr: ptr, n: len }
    }
}

#[repr(C)]
#[derive(Clone, Debug)]
pub struct MatrixEncoding {
    arr: *mut u8,
    rows: usize,
    cols: usize,
}

impl MatrixEncoding {
    pub fn new<T: Encode>(vec: Vec<T>) -> Self {
        let vec = vec
            .iter()
            .map(|item| item.encode())
            .collect::<Vec<Vec<u8>>>();
        let rows = vec.len();
        let cols = vec.first().unwrap().len(); // TODO remove unwrap

        let vec: Vec<u8> = vec.into_iter().flatten().collect();
        let (ptr, _len, _cap) = vec.into_raw_parts();
        Self {
            arr: ptr,
            rows,
            cols,
        }
    }

    unsafe fn to_vec(&self) -> Vec<Vec<u8>> {
        let slice: &mut [u8] = slice::from_raw_parts_mut(self.arr, self.rows * self.cols);

        slice
            .chunks_exact(self.cols)
            .map(<[_]>::to_vec)
            .collect::<Vec<Vec<u8>>>()
    }
}

#[repr(C)]
pub struct ArrCddClaimData {
    arr: *mut CddClaimData,
    n: usize,
}

impl ArrCddClaimData {
    unsafe fn to_vec(&self) -> Vec<CddClaimData> {
        Vec::from_raw_parts(self.arr, self.n, self.n)
    }
}

#[repr(C)]
pub struct ArrCddId {
    arr: *mut CddId,
    n: usize,
}

impl ArrCddId {
    unsafe fn to_vec(&self) -> Vec<CddId> {
        Vec::from_raw_parts(self.arr, self.n, self.n)
    }
}

#[repr(C)]
pub struct VerifierSetGeneratorResults {
    pub verifier_secrets: VecEncoding,
    pub committed_uids: VecEncoding,
}

#[repr(C)]
pub struct ProverResults {
    pub prover_initial_messages: MatrixEncoding,
    pub prover_final_responses: MatrixEncoding,
    pub committed_uids: VecEncoding,
}

fn box_alloc<T>(x: T) -> *mut T {
    Box::into_raw(Box::new(x))
}

//// ------------------------------------------------------------------------
//// Data Structures
//// ------------------------------------------------------------------------
//
///// Convert a Uuid byte array into a scalar object.
/////
///// Caller is responsible for calling `cdd_claim_data_free()` to deallocate this object.
/////
///// # Safety
///// Caller is also responsible for making sure `investor_did` and
///// `investor_unique_id` point to allocated blocks of memory of `investor_did_size`
///// and `investor_unique_id_size` bytes respectively.
//#[no_mangle]
//pub unsafe extern "C" fn uuid_new(unique_id: *const u8, unique_id_size: size_t) -> *mut Scalar {
unsafe fn to_uuid(raw: Vec<u8>) -> Scalar {
    assert!(raw.len() == 16, "Expected 16, got {}", raw.len());

    let mut uuid_bytes = [0u8; 16];
    uuid_bytes.copy_from_slice(raw.as_slice());

    let uuid = Builder::from_bytes(uuid_bytes)
        .set_variant(Variant::RFC4122)
        .set_version(Version::Random)
        .build();

    uuid_to_scalar(uuid)
}

///// Deallocates a `Scalar` object's memory.
/////
///// Should only be called on a still-valid pointer to an object returned by
///// `uuid_new()`.
//#[no_mangle]
//pub unsafe extern "C" fn scalar_free(ptr: *mut Scalar) {
//    if ptr.is_null() {
//        return;
//    }
//    Box::from_raw(ptr);
//}
//
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

///// Deallocates a `CddClaimData` object's memory.
/////
///// Should only be called on a still-valid pointer to an object returned by
///// `cdd_claim_data_new()`.
//#[no_mangle]
//pub unsafe extern "C" fn cdd_claim_data_free(ptr: *mut CddClaimData) {
//    if ptr.is_null() {
//        return;
//    }
//    Box::from_raw(ptr);
//}
//
///// Deallocates a `VerifierSetGeneratorResults` object's memory.
/////
///// Should only be called on a still-valid pointer to an object returned by
///// `generate_committed_set()`.
//#[no_mangle]
//pub unsafe extern "C" fn verifier_set_generator_results_free(
//    ptr: *mut VerifierSetGeneratorResults,
//) {
//    if ptr.is_null() {
//        return;
//    }
//    Box::from_raw(ptr);
//}
//
///// Deallocates a `ProverResults` object's memory.
/////
///// Should only be called on a still-valid pointer to an object returned by
///// `generate_proofs()`.
//#[no_mangle]
//pub unsafe extern "C" fn prover_results_free(ptr: *mut ProverResults) {
//    if ptr.is_null() {
//        return;
//    }
//    Box::from_raw(ptr);
//}
//
///// Deallocates a `TODO` object's memory.
/////
///// Should only be called on a still-valid pointer to an object returned by
///// `TODO()`.
///// TODO: Do the same for the other arrays as well.
//#[no_mangle]
//pub unsafe extern "C" fn todo(ptr: *mut ArrZKPInitialmessage) {
//    if ptr.is_null() {
//        return;
//    }
//    // TODO std::mem::forget()
//    Box::from_raw(ptr);
//}
//

// ------------------------------------------------------------------------
// Prover API
// ------------------------------------------------------------------------

/// The data needed to generate a CDD ID.
#[derive(Debug, Clone)]
#[repr(C)]
pub struct TestGen {
    pub inner: VecEncoding,
}

#[no_mangle]
pub unsafe extern "C" fn gen_test() -> *mut TestGen {
    let inner = VecEncoding::new(vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    ]);
    println!(
        "------------------> data_in_gen: {:?}",
        slice::from_raw_parts_mut(inner.arr, inner.n)
    );
    box_alloc(TestGen { inner })
}

#[no_mangle]
pub unsafe extern "C" fn consume_test(data: TestGen) {
    println!(
        "------------------> data_in_test: {:?}",
        slice::from_raw_parts_mut(data.inner.arr, data.inner.n)
    );
}
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
    cdd_claims: ArrCddClaimData,
    committed_uids: VecEncoding,
    seed: *const u8,
    seed_size: size_t,
) -> *mut ProverResults {
    assert!(!seed.is_null());
    assert!(seed_size == 32);

    let cdd_claims = cdd_claims.to_vec();

    let committed_uids = CommittedUids::decode(
        &mut &slice::from_raw_parts(committed_uids.arr, committed_uids.n)[..],
    )
    .unwrap(); // TODO unwrap

    let mut rng_seed = [0u8; 32];
    rng_seed.copy_from_slice(slice::from_raw_parts(seed, seed_size as usize));
    let mut rng = StdRng::from_seed(rng_seed);

    let result = Prover::generate_proofs::<StdRng>(&cdd_claims, &committed_uids, &mut rng);

    // Log the error and return.
    if result.is_err() {
        println!("Step 2) Prover -> Verifier error: {:?}", result.is_err());
        return null_mut();
    }

    let (initial_message_vec, final_responses_vec, re_committed_uids) = result.unwrap();

    box_alloc(ProverResults {
        prover_initial_messages: MatrixEncoding::new(initial_message_vec),
        prover_final_responses: MatrixEncoding::new(final_responses_vec),
        committed_uids: VecEncoding::new(re_committed_uids.encode()),
    })
}

// ------------------------------------------------------------------------
// VerifierSetGenerator API
// ------------------------------------------------------------------------

/// Creates a `VerifierSetGeneratorResults` object from a private Uuid (as
/// a Scalar object), a minimum set size, and a seed.
///
/// # Safety TODO revisit all the safety notes and minimize them.
/// Caller is responsible to make sure `private_unique_identifiers`
/// is a valid pointer to a `Scalar` object, and `seed` is a random
/// 32-byte array.
/// Caller is responsible for deallocating memory after use.
///
#[no_mangle]
pub unsafe extern "C" fn generate_committed_set(
    private_unique_identifiers: MatrixEncoding,
    min_set_size: *const size_t,
    seed: *const u8,
    seed_size: size_t,
) -> *mut VerifierSetGeneratorResults {
    assert!(!seed.is_null());
    assert!(seed_size == 32);

    let unique_identifiers = PrivateUids(
        private_unique_identifiers
            .to_vec()
            .into_iter()
            .map(|raw_uid| to_uuid(raw_uid))
            .collect(),
    );
    let mut rng_seed = [0u8; 32];
    rng_seed.copy_from_slice(slice::from_raw_parts(seed, seed_size as usize));

    let min_set_size: Option<usize> = match min_set_size.is_null() {
        true => None,
        false => Some(*min_set_size as usize),
    };

    _generate_committed_set(unique_identifiers, min_set_size, rng_seed)
}

fn _generate_committed_set(
    unique_identifiers: PrivateUids,
    min_set_size: Option<size_t>,
    rng_seed: [u8; 32],
) -> *mut VerifierSetGeneratorResults {
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
        verifier_secrets: VecEncoding::new(verifier_secrets.encode()),
        committed_uids: VecEncoding::new(committed_uids.encode()),
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
    initial_messages: MatrixEncoding,
    final_responses: MatrixEncoding,
    cdd_ids: ArrCddId,
    verifier_secrets: VecEncoding,
    re_committed_uids: VecEncoding,
) -> bool {
    let initial_messages = initial_messages
        .to_vec()
        .into_iter()
        .map(|raw| ZKPInitialmessage::decode(&mut raw.as_slice()).unwrap())
        .collect::<Vec<ZKPInitialmessage>>();

    let final_responses = final_responses
        .to_vec()
        .into_iter()
        .map(|raw| ZKPFinalResponse::decode(&mut raw.as_slice()).unwrap())
        .collect::<Vec<ZKPFinalResponse>>();

    let cdd_ids = cdd_ids.to_vec();

    let verifier_secrets = VerifierSecrets::decode(
        &mut &slice::from_raw_parts(verifier_secrets.arr, verifier_secrets.n)[..],
    )
    .unwrap();
    let re_committed_uids = CommittedUids::decode(
        &mut &slice::from_raw_parts(re_committed_uids.arr, re_committed_uids.n)[..],
    )
    .unwrap();

    let results = Verifier::verify_proofs(
        &initial_messages,
        &final_responses,
        &cdd_ids,
        &verifier_secrets,
        &re_committed_uids,
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
