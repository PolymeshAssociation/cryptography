# Cryptography
Repository for cryptographic libraries used in Polymath products. While these libraries could in theory be used by other projects, the design and tradeoffs made are in many cases specifically tailored for Polymesh. See https://github.com/PolymathNetwork/Polymesh for more details about Polymesh.

The libraries are divided as per the below headings.

There is a technical whitepaper for the the largest part of this work, the MERCAT library (which stands for Mediated, Encrypted, Reversible, SeCure Asset Transfers and is the name of our asset privacy protocol), however it is still in private review. It will be released publicly in fall 2020 and linked here. 

It's important to note that MERCAT is still in a pre-release state, and protocol implementation will likely be adjusted before release on a Polymesh testnet.

### Claim Proofs Library
This library implements the Asset Granularity Unique Identity protocol, as described [here][wiki_main_design]. The cryptographic building blocks are described [here][wiki_crypto_design].

### Asset Proofs Library
This library implements the essential Zero-Knowledge Proofs that are used in the MERCAT library. For more details see section 5 of the MERCAT whitepaper.

### MERCAT Library
This library implements the necessary API to handle account creation, confidential asset issuance, and confidential asset transfer, as outlined in section 6 of the MERCAT whitepaper.

## Documentation
To produce the documenation, run:
```
cargo +nightly doc --open
```

## Examples
For a bundle of helpful CommandLine Interfaces and test harnesses refer to the [cryptography-framework][cryptography-framework] repository.

## Build Instructions

Install rust!

Install the nightly version of rust and WASM toolchain.
```
# In the root directory
rustup toolchain install nightly

# Install wasm pack from https://rustwasm.github.io/wasm-pack/installer/
# then, inside the cryptography sub-directory, add the nightly version as target.
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

To build and run benchmarks:
```
cargo +nightly bench
```

### Verify WASM support

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
[cryptography-framework]: https://github.com/PolymathNetwork/crypto-framework
