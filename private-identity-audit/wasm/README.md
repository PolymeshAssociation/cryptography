# WASM bindings for Private Identity Audit Library (PIAL)


This library provides WASM binding for the PIAL library.

For comprehensive build instructions, refer to the README.md file in the
root of this repository. If you have all the necessary tools installed,
you can build the wasm bindings using

```bash
# If your active toolchain is stable, then run
rustup run nightly wasm-pack build --release

# If your active toolchain is nightly, then you can use the simpler version and run
wasm-pack build --release
```

This will create the bindings in `./pkg/` directory. You can import
these into any javascript-based project using a wasm-loader.


## CDD Provider Usage
After importing the content of `./pkg/` in your javascript project, you
can use `generate_initial_proofs()` and `generate_challenge_response()` functions
to generate UID membership proofs. The documentation for these functions can be found
by running `cargo doc --open`


## PUIS Usage
After importing the content of `./pkg/` in your javascript project, you
can call the `generate_committed_set_and_challenge()` function to generate a
challenge, and `verify_proofs()` to verify CDD provider's membership proof.
The documentation for this function can be found by running `cargo doc --open`

