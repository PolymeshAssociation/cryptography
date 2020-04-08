# Cryptography
Repository for cryptographic libraries used in Polymesh.

## Claim Proofs Library
This library implements the Asset Granularity Unique Identity protocol, as described [here][wiki_main_design]. The  cryptographic building blocks are described [here][wiki_crypto_design].

### Documentation
To produce the documenation, run:
```
cargo +nightly doc --open
```
### Build Instructions

Install rust!

Install the nightly version of rust and WASM toolchain.
```
# In the root directory
rustup toolchain install nightly

# install wasm pack from https://rustwasm.github.io/wasm-pack/installer/
# then, inside the cryptography sub-directory, add the nightly version as target
cd cryptography
rustup target add wasm32-unknown-unknown --toolchain nightly
```

If you use a different command to install a specific nightly version, use the same format for adding WASM.

To build the library and examples, run:
```
cargo +nightly build
```

To run the unit tests:
```
cargo +nightly test -- --nocapture
```

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
cryptography $> cargo +nightly b --features no_std
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
