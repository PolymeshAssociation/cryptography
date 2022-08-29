use confidential_identity_core::asset_proofs::{
    encryption_proofs::{single_property_prover, single_property_verifier},
    membership_proof::{
        MembershipProofFinalResponse, MembershipProofInitialMessage, MembershipProofVerifier,
        MembershipProverAwaitingChallenge,
    },
    one_out_of_many_proof::OooNProofGenerators,
};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};

use rand::{rngs::StdRng, SeedableRng};
use std::time::Duration;

const SEED_1: [u8; 32] = [42u8; 32];
const BASE: u32 = 4;
const EXPONENT: u32 = 8;
const SET_SIZE: u32 = 65536;

fn bench_membership_verify(
    c: &mut Criterion,
    secret_element_com: RistrettoPoint,
    proofs: Vec<(MembershipProofInitialMessage, MembershipProofFinalResponse)>,
) {
    let generators = OooNProofGenerators::new(EXPONENT, BASE);
    let elements: Vec<Scalar> = (0..SET_SIZE as u32).map(Scalar::from).collect();

    let mut group = c.benchmark_group("membership");

    for (idx, proof) in proofs.into_iter().enumerate() {
        group.bench_with_input(BenchmarkId::new("verification", idx), &proof, |b, proof| {
            b.iter(|| {
                single_property_verifier(
                    &MembershipProofVerifier {
                        secret_element_com,
                        elements_set: elements.as_slice(),
                        generators: &generators,
                    },
                    proof.clone(),
                )
                .unwrap()
            })
        });
    }
    group.finish();
}

fn bench_membership_proof(c: &mut Criterion) {
    let mut rng = StdRng::from_seed(SEED_1);

    let generators = OooNProofGenerators::new(EXPONENT, BASE);

    let elements: Vec<Scalar> = (0..SET_SIZE as u32).map(Scalar::from).collect();

    let secret_member = Scalar::from(28345u32);
    let blinding = Scalar::random(&mut rng);

    let commited_member = generators.com_gens.commit(secret_member, blinding);

    let prover = MembershipProverAwaitingChallenge::new(
        secret_member,
        blinding,
        &generators,
        elements.as_slice(),
        BASE,
        EXPONENT,
    )
    .unwrap();

    let proof =
        single_property_prover::<StdRng, MembershipProverAwaitingChallenge>(prover, &mut rng)
            .unwrap();

    bench_membership_verify(c, commited_member, vec![proof])
}

criterion_group! {
    name = bench_membership_verification;
    // Lower the sample size to run faster; larger shuffle sizes are
    // long so we're not microbenchmarking anyways.
    // 10 is the minimum allowed sample size in Criterion.
    config = Criterion::default().sample_size(10).measurement_time(Duration::new(600, 0));
    targets = bench_membership_proof,
}

criterion_main!(bench_membership_verification);
