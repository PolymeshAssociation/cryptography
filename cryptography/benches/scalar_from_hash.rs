use blake2::{Blake2b, Digest};
use criterion::{criterion_group, criterion_main, Criterion};
use curve25519_dalek::scalar::Scalar;
use rand::{thread_rng, Rng};

fn bench_scalar_from_hash(c: &mut Criterion) {
    let label = "scalar from bits bench".to_string();
    let mut input = [0u8; 32];
    thread_rng().fill(&mut input);
    let inputs = vec![input];

    c.bench_function_over_inputs(
        &label,
        move |b, &input| {
            b.iter(|| {
                Scalar::from_bits(input);
            })
        },
        inputs.clone(),
    );

    let label = "scalar from Blake2 hash bench".to_string();
    c.bench_function_over_inputs(
        &label,
        move |b, &input| {
            b.iter(|| {
                let mut hash = [0u8; 64];
                hash.copy_from_slice(Blake2b::default().chain(input).finalize().as_slice());
                Scalar::from_bytes_mod_order_wide(&hash)
            })
        },
        inputs,
    );
}

criterion_group! {
    name = scalar_from_hash;
    // Lower the sample size to run faster; larger shuffle sizes are
    // long so we're not microbenchmarking anyways.
    // 10 is the minimum allowed sample size in Criterion.
    config = Criterion::default()
        .sample_size(10);
    targets = bench_scalar_from_hash,
}

criterion_main!(scalar_from_hash);
