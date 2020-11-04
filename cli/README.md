# crypto-framework

This repository contains the CLI and test harness around the
[Polymesh Cryptograph library][cryptography].

The repository has following sections:
- CLI for claim proofs library: see [cil][cil]
- CLI for sending receiving confidential transactions: see [mercat][mercat] for a detailed description.
- Test harness for the confidential transactions: see [mercat/common][harness] for a detailed description.

### Build Instructions

Install rust!

Install the nightly version of rust and WASM toolchain.

```bash
# In the root directory
rustup toolchain install nightly

# install wasm pack from https://rustwasm.github.io/wasm-pack/installer/
# then, inside the cryptography sub-directory, add the nightly version as target
cd cryptography
rustup target add wasm32-unknown-unknown --toolchain nightly
```

If you use a different command to install a specific nightly version, use the same format for
adding WASM.

To run the library's unit tests as well has the test harness, run

```bash
cargo +nightly test --release -- --nocapture
```

For a more verbose test output, run

```bash
RUST_LOG=info cargo +nightly  test --release
```

To build all the CLIs in mercat and cil, run

```bash
cargo +nightly build --release
```

[cryptography]: https://github.com/PolymathNetwork/cryptography
[cil]: cli/cil
[mercat]: cli/mercat
[harness]: cli/mercat/common
