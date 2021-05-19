//! The `private_identity_audit_ffi` is the Foreign Function Interface (FFI)
//! for the `private_identity_audit` library. It contains APIs for generating
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

/// Used to pass a Vec of u8 between Rust and FFI users.
/// The code assumes that the pointer `ptr` is the start a "continous" block of memory of size `n`.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct VecEncoding {
    ptr: *mut u8,
    n: usize,
}

impl VecEncoding {
    pub fn new(vec: Vec<u8>) -> Self {
        let (ptr, len, _cap) = vec.into_raw_parts();
        Self { ptr, n: len }
    }
    /// Converts the pointer received from FFI to a Vector of u8.
    ///
    /// # Safety
    /// Refer to the safety notes of `Vec::from_raw_parts`.
    unsafe fn to_vec(&self) -> Vec<u8> {
        Vec::from_raw_parts(self.ptr, self.n, self.n)
    }
}

/// Used to pass a 2D Vec of u8 between Rust and FFI users.
/// The code assumes that the pointer `ptr` is the start a "continous" block of memory of size `rows*cols`.
#[repr(C)]
#[derive(Debug)]
pub struct MatrixEncoding {
    ptr: *mut u8,
    rows: usize,
    cols: usize,
}

impl MatrixEncoding {
    /// The code assumes that all the elements of `vec` encode to the same length.
    pub fn new<T: Encode>(vec: Vec<T>) -> Option<Self> {
        let vec = vec
            .iter()
            .map(|item| item.encode())
            .collect::<Vec<Vec<u8>>>();
        let rows = vec.len();
        if let Some(cols) = vec.first() {
            let cols = cols.len();
            for r in vec.iter() {
                if r.len() != cols {
                    println!("Mismatch on encoded data size. Expected all items to encode to {} bytes, found an element that encodes to {} bytes.", cols, r.len());
                    return None;
                }
            }

            let mut flattened_vec: Vec<u8> = Vec::with_capacity(rows * cols);
            for row in vec.iter() {
                flattened_vec.extend(row);
            }
            assert_eq!(flattened_vec.capacity(), rows * cols);
            let (ptr, _len, _cap) = flattened_vec.into_raw_parts();
            Some(Self { ptr, rows, cols })
        } else {
            println!("The input `vec` should have at least two elements");
            None
        }
    }

    fn as_slice(&self) -> &[u8] {
        // SAFETY: Refer to the safety notes of `slice::from_raw_parts_mut`.
        unsafe { slice::from_raw_parts(self.ptr, self.rows * self.cols) }
    }

    fn as_cols(&self) -> impl '_ + Iterator<Item = &[u8]> {
        self.as_slice().chunks_exact(self.cols)
    }
}

/// Used to pass a Vec of `CddClaimData` between Rust and FFI users.
/// The code assumes that the pointer `ptr` is the start a "continous" block of memory of size
/// `n * length of the encoded version of CddClaimData`.
#[repr(C)]
pub struct ArrCddClaimData {
    ptr: *mut CddClaimData,
    n: usize,
}

impl ArrCddClaimData {
    /// Converts the pointer received from FFI to a Vector of CddClaimData.
    ///
    /// # Safety
    /// Refer to the safety notes of `vec::from_raw_parts`.
    unsafe fn to_vec(&self) -> Vec<CddClaimData> {
        Vec::from_raw_parts(self.ptr, self.n, self.n)
    }
}

/// Used to pass a Vec of `ArrCddId` between Rust and FFI users.
/// The code assumes that the pointer `ptr` is the start a "continous" block of memory of size
/// `n * length of the encoded version of ArrCddId`.
#[repr(C)]
pub struct ArrCddId {
    ptr: *mut CddId,
    n: usize,
}

impl ArrCddId {
    /// Converts the pointer received from FFI to a Vector of CddId.
    ///
    /// # Safety
    /// Refer to the safety notes of `vec::from_raw_parts`.
    unsafe fn to_vec(&self) -> Vec<CddId> {
        Vec::from_raw_parts(self.ptr, self.n, self.n)
    }
}

/// Holds the result of the first phase of the protocol. The `verifier_secrets` should be kept
/// private, while the `committed_uids` should be shared with the prover.
#[repr(C)]
pub struct VerifierSetGeneratorResults {
    pub verifier_secrets: VecEncoding,
    pub committed_uids: VecEncoding,
}

/// Holds the result of the second phase of the protocol. All the messages should be shared with
/// the verifier.
#[repr(C)]
pub struct ProverResults {
    pub prover_initial_messages: MatrixEncoding,
    pub prover_final_responses: MatrixEncoding,
    pub committed_uids: VecEncoding,
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
fn to_uuid(raw: &[u8]) -> Scalar {
    assert!(raw.len() == 16, "Expected 16, got {}", raw.len());

    let mut uuid_bytes = [0u8; 16];
    uuid_bytes.copy_from_slice(raw);

    let uuid = Builder::from_bytes(uuid_bytes)
        .set_variant(Variant::RFC4122)
        .set_version(Version::Random)
        .build();

    uuid_to_scalar(uuid)
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
/// # Safety
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
/// # Safety
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
/// # Safety
/// Should only be called on a still-valid pointer to an object returned by
/// `generate_proofs()`.
#[no_mangle]
pub unsafe extern "C" fn prover_results_free(ptr: *mut ProverResults) {
    if ptr.is_null() {
        return;
    }
    Box::from_raw(ptr);
}

// ------------------------------------------------------------------------
// Prover API
// ------------------------------------------------------------------------

/// Creates a `InitialProverResults` object from a CDD claim and a seed.
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

    let committed_uids = CommittedUids::decode(&mut committed_uids.to_vec().as_slice());
    if let Ok(committed_uids) = committed_uids {
        let mut rng_seed = [0u8; 32];
        rng_seed.copy_from_slice(slice::from_raw_parts(seed, seed_size as usize));

        _generate_proofs(cdd_claims, committed_uids, rng_seed)
    } else {
        println!(
            "Error in decoding committed uids: {:?}",
            committed_uids.unwrap_err()
        );
        return null_mut();
    }
}

fn _generate_proofs(
    cdd_claims: Vec<CddClaimData>,
    committed_uids: CommittedUids,
    rng_seed: [u8; 32],
) -> *mut ProverResults {
    let mut rng = StdRng::from_seed(rng_seed);

    let result = Prover::generate_proofs::<StdRng>(&cdd_claims, &committed_uids, &mut rng);

    // Log the error and return.
    match result {
        Err(err) => {
            println!("Error in generating proofs: {:?}", err);
            return null_mut();
        }
        Ok((initial_message_vec, final_responses_vec, re_committed_uids)) => {
            if let Some(prover_initial_messages) = MatrixEncoding::new(initial_message_vec) {
                if let Some(prover_final_responses) = MatrixEncoding::new(final_responses_vec) {
                    return box_alloc(ProverResults {
                        prover_initial_messages,
                        prover_final_responses,
                        committed_uids: VecEncoding::new(re_committed_uids.encode()),
                    });
                }
            }

            return null_mut();
        }
    }
}

// ------------------------------------------------------------------------
// VerifierSetGenerator API
// ------------------------------------------------------------------------

/// Creates a `VerifierSetGeneratorResults` object from a private Uuid (as
/// a Scalar object), a minimum set size, and a seed.
///
/// # Safety
/// Caller is responsible to make sure `private_unique_identifiers`
/// is a valid pointer to a `MatrixEncoding` object, and `seed` is a random
/// 32-byte array.
/// Caller is responsible for deallocating memory after use.
#[no_mangle]
pub unsafe extern "C" fn generate_committed_set(
    private_unique_identifiers: MatrixEncoding,
    min_set_size: *const size_t,
    seed: *const u8,
    seed_size: size_t,
) -> *mut VerifierSetGeneratorResults {
    assert!(!seed.is_null());
    assert!(seed_size == 32);

    let unique_identifiers =
        PrivateUids(private_unique_identifiers.as_cols().map(to_uuid).collect());
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
    match result {
        Err(err) => {
            println!("Error in generating comitted set: {:?}", err);
            return null_mut();
        }
        Ok((verifier_secrets, committed_uids)) => box_alloc(VerifierSetGeneratorResults {
            verifier_secrets: VecEncoding::new(verifier_secrets.encode()),
            committed_uids: VecEncoding::new(committed_uids.encode()),
        }),
    }
}

// ------------------------------------------------------------------------
// Verifier API
// ------------------------------------------------------------------------

/// Verifies the proof of a Uuid's membership in a set of Uuids.
///
/// # Safety
/// Caller is responsible to make sure `initial_message`,
/// `final_response`, `cdd_ids`, `verifier_secrets`,
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
    let initial_messages = if let Ok(decoded) = initial_messages
        .as_cols()
        .map(|mut raw| ZKPInitialmessage::decode(&mut raw))
        .collect::<Result<Vec<ZKPInitialmessage>, _>>()
    {
        decoded
    } else {
        println!("Error in decoding initial messages.");
        return false;
    };

    let final_responses = if let Ok(decoded) = final_responses
        .as_cols()
        .map(|mut raw| ZKPFinalResponse::decode(&mut raw))
        .collect::<Result<Vec<ZKPFinalResponse>, _>>()
    {
        decoded
    } else {
        println!("Error in decoding final responses.");
        return false;
    };

    let cdd_ids = cdd_ids.to_vec();

    let verifier_secrets =
        if let Ok(decoded) = VerifierSecrets::decode(&mut verifier_secrets.to_vec().as_slice()) {
            decoded
        } else {
            println!("Error in decoding verifier secrets.");
            return false;
        };
    let re_committed_uids =
        if let Ok(decoded) = CommittedUids::decode(&mut re_committed_uids.to_vec().as_slice()) {
            decoded
        } else {
            println!("Error in decoding Committed UIDs.");
            return false;
        };

    _verify_proofs(
        initial_messages,
        final_responses,
        cdd_ids,
        verifier_secrets,
        re_committed_uids,
    )
}

fn _verify_proofs(
    initial_messages: Vec<ZKPInitialmessage>,
    final_responses: Vec<ZKPFinalResponse>,
    cdd_ids: Vec<CddId>,
    verifier_secrets: VerifierSecrets,
    re_committed_uids: CommittedUids,
) -> bool {
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
