use blake2::{Blake2b, Digest};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use curve25519_dalek::scalar::Scalar;
use rand::{thread_rng, Rng};

fn bench_scalar_from_hash(c: &mut Criterion) {
    let mut input = [0u8; 32];
    thread_rng().fill(&mut input);
    let inputs = vec![input];

    let mut group = c.benchmark_group("Scalar from: ");
    for (idx, input) in inputs.iter().enumerate() {
        group.bench_with_input(BenchmarkId::new("bits", idx), input, |b, input| {
            b.iter(|| {
                Scalar::from_bits(*input);
            })
        });
    }

    for (idx, input) in inputs.iter().enumerate() {
        group.bench_with_input(BenchmarkId::new("Blake2b hash", idx), input, |b, input| {
            b.iter(|| {
                let hash = Blake2b::digest(input).into();
                Scalar::from_bytes_mod_order_wide(&hash)
            })
        });
    }
    group.finish();
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
