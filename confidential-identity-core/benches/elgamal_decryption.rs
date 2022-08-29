use confidential_identity_core::asset_proofs::ElgamalSecretKey;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use curve25519_dalek::scalar::Scalar;

use rand::{rngs::StdRng, SeedableRng};

fn bench_elgamal(c: &mut Criterion) {
    let mut rng = StdRng::from_seed([42u8; 32]);

    let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
    let elg_pub = elg_secret.get_public_key();

    let mut group = c.benchmark_group("elgamal");

    for i in 0..6 {
        let value = 10u32.pow(i);
        group.bench_with_input(BenchmarkId::new("encrypt", value), &value, |b, &value| {
            b.iter(|| elg_pub.encrypt_value(value.into(), &mut rng))
        });
    }

    for i in 0..6 {
        let value = 10u32.pow(i);
        let enc_value = elg_pub.encrypt_value(value.into(), &mut rng).1;
        group.bench_with_input(
            BenchmarkId::new("decrypt", value),
            &enc_value,
            |b, enc_value| {
                b.iter(|| {
                    elg_secret.decrypt(enc_value).unwrap();
                })
            },
        );
    }
    group.finish();
}

criterion_group! {
    name = elgamal_decryption;
    // Lower the sample size to run faster; larger shuffle sizes are
    // long so we're not microbenchmarking anyways.
    // 10 is the minimum allowed sample size in Criterion.
    config = Criterion::default()
        .sample_size(10);
    targets = bench_elgamal,
}

criterion_main!(elgamal_decryption);
