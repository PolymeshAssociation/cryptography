//// TODO: all of this file!
//
//use criterion::{criterion_group, criterion_main, Criterion};
//use std::time::Duration;
//
//fn bench_mercat_scenario(c: &mut Criterion, testcase: TestCase) {
//    let label = format!(testcase.title);
//
//    //c.bench_function_over_inputs(
//    //    &label,
//    //    move |b, _| {
//    //        b.iter(|| {
//    //            elg_secret.decrypt(cipher).unwrap();
//    //        })
//    //    },
//    //    ciphers,
//    //);
//}
//
//criterion_group! {
//    name = elgamal_decryption;
//    // Lower the sample size to run faster; larger shuffle sizes are
//    // long so we're not microbenchmarking anyways.
//    // 10 is the minimum allowed sample size in Criterion.
//    config = Criterion::default()
//        .sample_size(10)
//        .measurement_time(Duration::new(60, 0));
//    targets = bench_elgamal,
//}
//
//criterion_main!(bench_mercat_scenario);
//
