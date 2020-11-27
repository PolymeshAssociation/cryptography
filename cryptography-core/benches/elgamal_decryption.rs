use criterion::{criterion_group, criterion_main, Criterion};
use cryptography_core::asset_proofs::{CipherText, ElgamalSecretKey};
use curve25519_dalek::scalar::Scalar;

use rand::{rngs::StdRng, SeedableRng};

fn bench_elgamal_decrypt(
    c: &mut Criterion,
    elg_secret: ElgamalSecretKey,
    ciphers: Vec<(String, CipherText)>,
) {
    let label = "elgamal enc/dec bench".to_string();

    c.bench_function_over_inputs(
        &label,
        move |b, (_label, cipher)| {
            b.iter(|| {
                elg_secret.decrypt(cipher).unwrap();
            })
        },
        ciphers,
    );
}

fn bench_elgamal(c: &mut Criterion) {
    let mut rng = StdRng::from_seed([42u8; 32]);

    let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
    let elg_pub = elg_secret.get_public_key();

    let encrypted_values: Vec<(String, CipherText)> = (0..6)
        .map(|i| {
            let value = 10u32.pow(i);
            let encryptd_value = elg_pub.encrypt_value(value.into(), &mut rng).1;
            (format!("value ({:?})", value), encryptd_value)
        })
        .collect();

    bench_elgamal_decrypt(c, elg_secret, encrypted_values);
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
