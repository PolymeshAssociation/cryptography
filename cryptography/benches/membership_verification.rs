use criterion::{criterion_group, criterion_main, Criterion};
use cryptography::asset_proofs::{
    encryption_proofs::{single_property_prover, single_property_verifier},
    membership_proof::{
        MembershipProofFinalResponse, MembershipProofInitialMessage, MembershipProofVerifier,
        MembershipProverAwaitingChallenge,
    },
    one_out_of_many_proof::OooNProofGenerators,
};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};

use rand::{rngs::StdRng, SeedableRng};
use std::time::Duration;

const SEED_1: [u8; 32] = [42u8; 32];
const BASE: usize = 4;
const EXPONENT: usize = 3;

fn bench_membership_verify(
    c: &mut Criterion,
    secret_element_com: RistrettoPoint,
    proofs: Vec<(MembershipProofInitialMessage, MembershipProofFinalResponse)>,
) {
    let label = format!("membership verification");

    let generators = OooNProofGenerators::new(EXPONENT, BASE);
    let even_elements: Vec<Scalar> = (0..64 as u32).map(|m| Scalar::from(2 * m)).collect();

    c.bench_function_over_inputs(
        &label,
        move |b, proof| {
            b.iter(|| {
                single_property_verifier(
                    &MembershipProofVerifier {
                        secret_element_com,
                        elements_set: even_elements.as_slice(),
                        generators: &generators,
                    },
                    proof.0.clone(),
                    proof.1.clone(),
                )
                .unwrap()
            })
        },
        proofs,
    );
}

fn bench_membership_proof(c: &mut Criterion) {
    let mut rng = StdRng::from_seed(SEED_1);

    let generators = OooNProofGenerators::new(EXPONENT, BASE);

    let even_elements: Vec<Scalar> = (0..64 as u32).map(|m| Scalar::from(2 * m)).collect();
    // let odd_elements: Vec<Scalar> = (0..64 as u32).map(|m| Scalar::from(2 * m + 1)).collect();

    let blinding = Scalar::random(&mut rng);

    let even_member = generators.com_gens.commit(Scalar::from(8u32), blinding);
    // let odd_member = generators.com_gens.commit(Scalar::from(75u32), blinding);

    let prover = MembershipProverAwaitingChallenge::new(
        Scalar::from(8u32),
        blinding,
        &generators,
        even_elements.as_slice().clone(),
        BASE,
        EXPONENT,
    )
    .unwrap();

    let proof =
        single_property_prover::<StdRng, MembershipProverAwaitingChallenge>(prover, &mut rng)
            .unwrap();

    bench_membership_verify(c, even_member, vec![proof])
}

criterion_group! {
    name = bench_membership_verification;
    // Lower the sample size to run faster; larger shuffle sizes are
    // long so we're not microbenchmarking anyways.
    // 10 is the minimum allowed sample size in Criterion.
    config = Criterion::default().sample_size(10).measurement_time(Duration::new(60, 0));
    targets = bench_membership_proof,
}

criterion_main!(bench_membership_verification);
