use criterion::{criterion_group, criterion_main, Criterion};
use cryptography::asset_proofs::{CipherText, CommitmentWitness, ElgamalSecretKey};
use curve25519_dalek::scalar::Scalar;

use rand::{rngs::StdRng, SeedableRng};
use std::time::Duration;

fn bench_elgamal_decrypt(
    c: &mut Criterion,
    elg_secret: ElgamalSecretKey,
    ciphers: Vec<CipherText>,
) {
    let label = format!("elgamal enc/dec bench");

    c.bench_function_over_inputs(
        &label,
        move |b, cipher| {
            b.iter(|| {
                elg_secret.decrypt(cipher).unwrap();
            })
        },
        ciphers,
    );
}

fn bench_elgamal(c: &mut Criterion) {
    let mut rng = StdRng::from_seed([42u8; 32]);
    let r = Scalar::random(&mut rng);

    let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
    let elg_pub = elg_secret.get_public_key();

    let encrypted_values: Vec<CipherText> = (0..3)
        .map(|i| {
            let value = 2u32 << i;
            let w = CommitmentWitness::new(value, r).unwrap();
            elg_pub.encrypt(w)
        })
        .collect();

    bench_elgamal_decrypt(c, elg_secret, encrypted_values);
}

criterion_group! {
    name = elgamal_decryption;
    // Lower the sample size to run faster; larger shuffle sizes are
    // long so we're not microbenchmarking anyways.
    // 10 is the minimum allowed sample size in Criterion.
    config = Criterion::default().sample_size(10).measurement_time(Duration::new(60, 0));
    targets = bench_elgamal,
}

criterion_main!(elgamal_decryption);
