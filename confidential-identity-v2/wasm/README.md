# WASM bindings for Confidential Identity Library


This library provides WASM binding for Confidential Identity Library.
The Rust code can be found at
[polymath CIL library][confidential-identity-rust-lib] and the source
code for the wasm bindings can be found at [WASM bindings][wasm-src].


## CDD Provider Usage

After importing the content of this package in your javascript project, you
can call the `process_create_cdd_id` function to create the CDD ID. The
documentation for this function can be found by running `cargo doc --open`
in the [Rust directory][confidential-identity-rust-lib].


## Investors' Usage

After importing the content of this package in your javascript project, you
can call the `process_create_claim_proof` function to create a
confidential proof for their claim. The documentation for this function
can be found by running `cargo doc --open`
in the [Rust directory][confidential-identity-rust-lib].


## Simple Claim Verifier

This is not supported since the verification is handled by PolyMesh.


## Build Instructions

For comprehensive build instructions, refer to the README.md file in the
root of the [repository][cryptography-rust-lib].

If you have all the necessary tools installed, you can build the wasm
bindings using the following commands.

```bash
# If your active toolchain is stable, then run
rustup run nightly wasm-pack build --release

# If your active toolchain is nightly, then you can use the simpler version and run
wasm-pack build --release
```

This will create the bindings in `./pkg/` directory. You can import
these into any javascript-based project using a wasm-loader.

## Publish

Note that the name in the `package.json` file will be "confidential-identity".
But, in order to properly publish the package, the name should be changed to
`@polymathnetwork/confidential-identity`.


[cryptography-rust-lib]: https://github.com/PolymathNetwork/cryptography/tree/master/README.md
[confidential-identity-rust-lib]: https://github.com/PolymathNetwork/cryptography/tree/master/confidential-identity
[confidential-identity-wasm-src]: https://github.com/PolymathNetwork/cryptography/blob/master/confidential-identity/wasm/src/lib.rs 
