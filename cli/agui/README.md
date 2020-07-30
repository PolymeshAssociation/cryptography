# Asset Granularity Unique Identity: Simple Claim Prover

To run the `simple_claim_prover` example:
```
cargo +nightly run --bin scp -- -v -r -c rand_cdd_claim.json -s rand_scope_claim.json -p proof.json -m "my claim"
```

It will generate a random claim and save it to `rand_claim.json`. From this claim it will generate a proof of possession of the unique id over the `"my claim"` message, and save it to `proof.json`.
To learn more about the usage, run:
```
cargo +nightly run --bin scp -- -h
```

To run the `simple_claim_verifier` example:
```
cargo +nightly run --bin scv -- -p proof.json -m "my claim"
```
It will determine whether `proof.json` is a valid proof of possession of the unique ID.
To learn more about the usage, run:
```
cargo +nightly run --bin scv -- -h
```

## Verify WASM support

WASM built is disable in the default feature. If you want to double-check that library can be built
in WASM, you have to enable `no_std` feature.

```
$> cd cryptography
cryptography $> cargo build --target wasm32-unknown-unknown --no-default-features --features no_std
```

To run tests on WASM, follow [wasm-bindgen-test][wasm-bindgen-test].

More specifically, ensure that you have `nodejs` installed and that `wasm-bindgen-test` is a dev dependency.
Now, you can add `#[wasm_bindgen_test]` to any function that you want to be tested for WASM support.

You can run the WASM tests with
```
wasm-pack test --node
```

[wasm-bindgen-test]: https://rustwasm.github.io/docs/wasm-bindgen/wasm-bindgen-test/usage.html
[wiki_main_design]: https://polymath.atlassian.net/wiki/spaces/PC/pages/172523576/Asset+Granularity+Unique+Identity
[wiki_crypto_design]: https://polymath.atlassian.net/wiki/spaces/CE/pages/202571817/Claim+Proof+Prototype