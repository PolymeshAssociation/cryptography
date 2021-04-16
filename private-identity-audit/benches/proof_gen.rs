use criterion::*;
use cryptography_core::cdd_claim::{compute_cdd_id, CddClaimData};
use cryptography_core::dalek_wrapper::Scalar;
use private_identity_audit::{
    uuid_to_scalar, verifier::gen_random_uuids, CommittedSetGenerator, PrivateUids, ProofGenerator,
    ProofVerifier, Prover, Verifier, VerifierSetGenerator,
};
use rand::{rngs::StdRng, SeedableRng};
use rand_core::RngCore;
use uuid::Uuid;

const UID_SET_MAX: usize = 100_000;

fn setup(rng: &mut StdRng) -> (Vec<CddClaimData>, Vec<Scalar>) {
    let batch_size = 100;

    // Private input of the Verifier.
    let private_uid_set: Vec<Uuid> = gen_random_uuids(UID_SET_MAX, rng);

    // Make a random did for the investor.
    let mut investor_dids = vec![];
    for i in 0..batch_size {
        investor_dids.push([0u8; 32]);
        rng.fill_bytes(&mut investor_dids[i]);
    }

    // Verifier shares one of its uids with the Prover.
    (
        investor_dids
            .iter()
            .map(|did| CddClaimData::new(did, private_uid_set[0].as_bytes()))
            .collect::<Vec<_>>(),
        private_uid_set.into_iter().map(uuid_to_scalar).collect(),
    )
}

fn bench_proof_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("Proof Generation");
    let mut rng = StdRng::from_seed([20u8; 32]);

    let (claims, private_uid_scalar_set) = setup(&mut rng);

    // V -> P: Prover sends `proofs` and Verifier returns a list of 10 uids and the challenge.
    let (_, committed_uids) = VerifierSetGenerator::generate_committed_set(
        PrivateUids(private_uid_scalar_set),
        Some(UID_SET_MAX),
        &mut rng,
    )
    .unwrap();

    group.bench_function("Parallel", |b| {
        b.iter(|| {
            // On a machine with 20 cpus, the following should create 20 threads since the max
            // thread count is the number of cpus.
            let _ = Prover::generate_proofs(&claims, &committed_uids, &mut rng).unwrap();
        })
    });
    group.bench_function("Sequential", |b| {
        b.iter(|| {
            let _ = Prover::generate_proofs(&claims, &committed_uids, &mut rng).unwrap();
        })
    });

    group.finish();
}

fn bench_verify_proofs(c: &mut Criterion) {
    let mut group = c.benchmark_group("Proof Verification");
    let mut rng = StdRng::from_seed([20u8; 32]);

    let (claims, private_uid_scalar_set) = setup(&mut rng);

    // Prover generates cdd_id and places it on the chain.
    let cdd_ids = claims
        .iter()
        .map(|claim| compute_cdd_id(claim))
        .collect::<Vec<_>>();

    // V -> P: Prover sends `proofs` and Verifier returns a list of 10 uids and the challenge.
    let (verifier_secrets, committed_uids) = VerifierSetGenerator::generate_committed_set(
        PrivateUids(private_uid_scalar_set),
        Some(UID_SET_MAX),
        &mut rng,
    )
    .unwrap();
    // On a machine with 20 cpus, the following should create 20 threads since the max
    // thread count is the number of cpus.
    let (initial_message, final_response, re_committed_uids) =
        Prover::generate_proofs(&claims, &committed_uids, &mut rng).unwrap();

    group.bench_function("Parallel", |b| {
        b.iter(|| {
            // On a machine with 20 cpus, the following should create 20 threads since the max
            // thread count is the number of cpus.
            Verifier::verify_proofs(
                &initial_message,
                &final_response,
                &cdd_ids,
                &verifier_secrets,
                &re_committed_uids,
            )
            .iter()
            .for_each(|res| assert!(res.is_ok()));
        })
    });
    group.bench_function("Sequential", |b| {
        b.iter(|| {
            // On a machine with 20 cpus, the following should create 20 threads since the max
            // thread count is the number of cpus.
            Verifier::verify_proofs(
                &initial_message,
                &final_response,
                &cdd_ids,
                &verifier_secrets,
                &re_committed_uids,
            )
            .iter()
            .for_each(|res| assert!(res.is_ok()));
        })
    });

    group.finish();
}

criterion_group! {
    name = provider_proof_gen;
    // Lower the sample size to run faster; larger shuffle sizes are
    // long so we're not microbenchmarking anyways.
    // 10 is the minimum allowed sample size in Criterion.
    config = Criterion::default()
        .sample_size(10);
    targets = bench_proof_generation, bench_verify_proofs
}

criterion_main!(provider_proof_gen);
