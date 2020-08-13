# crypto-framework

This repository contains the CLI and test harness around the [Polymesh Cryptograph library][cryptography].

The repository has following sections:
- CLI for claim proofs library: see [agui][agui]
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
Fetch the cryptography submodule.

```bash
git submodule update --init
```

If you use a different command to install a specific nightly version, use the same format for adding WASM.


To run the library's unit tests as well has the test harness, run
```bash
RUST_LOG=info cargo +nightly  test --release
```

To build all the CLIs in mercat and agui, run
```bash
cargo +nightly build
```

To run the unit tests:
```
cargo +nightly test -- --nocapture
```

[cryptography]: https://github.com/PolymathNetwork/cryptography
[agui]: https://github.com/PolymathNetwork/crypto-framework/tree/master/agui
[mercat]: https://github.com/PolymathNetwork/crypto-framework/tree/master/mercat
[harness]: https://github.com/PolymathNetwork/crypto-framework/tree/master/mercat/common