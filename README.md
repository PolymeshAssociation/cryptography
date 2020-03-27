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
cargo run --bin scp -- -v -r -c rand_claim.json -p proof.json -m "my claim"
```

It will generate a random claim and save it to `rand_claim.json`. From this claim it will generate a proof of possession of the unique id over the `"my claim"` message, and save it to `proof.json`.
To learn more about the usage, run:
```
cargo run --bin scp -- -h
```

To run the `simple_claim_verifier` example:
```
cargo run --bin scv -- -p proof.json -m "my claim"
```
It will determine whether `proof.json` is a valid proof of possession of the unique ID.
To learn more about the usage, run:
```
cargo run --bin scv -- -h
```

## Verify WASM support

WASM built is disable in the default feature. If you want to double-check that library can be built
in WASM, you have to enable `no_std` feature.

```
$> cd cryptography
Cryptography $> cargo b --features no_std
```

[wiki_main_design]: https://polymath.atlassian.net/wiki/spaces/PC/pages/172523576/Asset+Granularity+Unique+Identity
[wiki_crypto_design]: https://polymath.atlassian.net/wiki/spaces/CE/pages/202571817/Claim+Proof+Prototype
