//! The `private_identity_audit_ffi` is the Foreign Function Interface (FFI)
//! for the `private_identity_audit` library. It contains API for generating
//! unique identity membership proofs and verifying them as part of the
//! PIAL project.

extern crate libc;
use libc::size_t;
use rand::{rngs::StdRng, SeedableRng};
use std::slice;

// use confidential_identity::{build_scope_claim_proof_data, compute_cdd_id, compute_scope_id};
use private_identity_audit::{ChallengeGenerator, ProofGenerator, VerifierSetGenerator};

pub type PrivateUids = private_identity_audit::PrivateUids;
pub type CommittedUids = private_identity_audit::CommittedUids;
pub type Challenge = private_identity_audit::Challenge;
pub type Proofs = private_identity_audit::Proofs;
pub type ProverFinalResponse = private_identity_audit::ProverFinalResponse;
pub type ProverSecrets = private_identity_audit::ProverSecrets;
pub type VerifierSecrets = private_identity_audit::VerifierSecrets;

pub type InitialProver = private_identity_audit::InitialProver;
pub type FinalProver = private_identity_audit::FinalProver;

pub type CddClaimData = confidential_identity::CddClaimData;

pub type RistrettoPoint = cryptography_core::curve25519_dalek::ristretto::RistrettoPoint;
pub type Scalar = cryptography_core::curve25519_dalek::scalar::Scalar;

pub struct InitialProverResults {
    pub prover_secrets: *mut ProverSecrets,
    pub proofs: *mut Proofs,
    // todo maybe add the error code.
}

pub struct VerifierSetGeneratorResults {
    // (VerifierSecrets, CommittedUids, Challenge)
    pub verifier_secrets: *mut VerifierSecrets,
    pub committed_uids: *mut CommittedUids,
    pub challenge: *mut Challenge,
}

fn box_alloc<T>(x: T) -> *mut T {
    Box::into_raw(Box::new(x))
}

// ------------------------------------------------------------------------
// Data Structures
// ------------------------------------------------------------------------

/// Create a new `CddClaimData` object.
///
/// Caller is responsible for calling `cdd_claim_data_free()` to deallocate this object.
/// SAFETY: Caller is also responsible for making sure `investor_did` and
///         `investor_unique_id` point to allocated blocks of memory of `investor_did_size`
///         and `investor_unique_id_size` bytes respectively.
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

// ------------------------------------------------------------------------
// Prover API
// ------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn generate_initial_proofs_wrapper(
    cdd_claim: *const CddClaimData,
    seed: *const u8,
    seed_size: size_t,
) -> *mut InitialProverResults {
    assert!(!cdd_claim.is_null());
    assert!(!seed.is_null());
    assert!(seed_size != 32);

    let cdd_claim: CddClaimData = *cdd_claim;

    let mut rng_seed = [0u8; 32];
    rng_seed.copy_from_slice(slice::from_raw_parts(seed, seed_size as usize));
    let mut rng = StdRng::from_seed(rng_seed);

    let (prover_secrets, proofs) =
        InitialProver::generate_initial_proofs(cdd_claim, &mut rng).unwrap();
    box_alloc(InitialProverResults {
        prover_secrets: box_alloc(prover_secrets),
        proofs: box_alloc(proofs),
    })
}

// fn generate_committed_set_and_challenge<T: RngCore + CryptoRng>(
//     &self,
//     private_unique_identifiers: PrivateUids,
//     min_set_size: Option<usize>,
//     rng: &mut T,
// ) -> Fallible<(VerifierSecrets, CommittedUids, Challenge)>;

#[no_mangle]
pub unsafe extern "C" fn generate_committed_set_and_challenge_wrapper(
    private_unique_identifiers: *mut Scalar,
    private_unique_identifiers_size: size_t,
    min_set_size: *const size_t, // this is optional
    seed: *const u8,
    seed_size: size_t,
) -> *mut VerifierSetGeneratorResults {
    assert!(!private_unique_identifiers.is_null());
    assert!(private_unique_identifiers_size != 0);
    assert!(!seed.is_null());
    assert!(seed_size != 32);

    let unique_identifiers_vec: PrivateUids =
        slice::from_raw_parts_mut(private_unique_identifiers, private_unique_identifiers_size)
            .into();
    // Vec::with_capacity(private_unique_identifiers_size);
    // for i in 0..private_unique_identifiers_size as usize {
    //     unique_identifiers_vec.push(private_unique_identifiers[i]);
    // }

    let min_set_size: Option<usize> = match min_set_size.is_null() {
        true => None,
        false => Some(*min_set_size as usize),
    };

    let mut rng_seed = [0u8; 32];
    rng_seed.copy_from_slice(slice::from_raw_parts(seed, seed_size as usize));
    let mut rng = StdRng::from_seed(rng_seed);

    let (verifier_secrets, committed_uids, challenge) =
        VerifierSetGenerator::generate_committed_set_and_challenge(
            unique_identifiers_vec,
            min_set_size,
            &mut rng,
        )
        .unwrap();

    box_alloc(VerifierSetGeneratorResults {
        verifier_secrets: box_alloc(verifier_secrets),
        committed_uids: box_alloc(committed_uids),
        challenge: box_alloc(challenge),
    })
}
