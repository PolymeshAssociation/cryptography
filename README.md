# Cryptography

Repository for cryptographic libraries used in Polymath products. While these libraries could in
theory be used by other projects, the design and tradeoffs made are in many cases specifically
tailored for Polymesh. See https://github.com/PolymeshAssociation/Polymesh for more details about
Polymesh.

The libraries are divided as per the below headings.

There is a technical whitepaper for the largest part of this work, the MERCAT library
(which stands for Mediated, Encrypted, Reversible, SeCure Asset Transfers and is the name of
our asset privacy protocol) which can be accessed publicly at
[https://polymath.network/resources][mercat-paper] .

It is important to note that MERCAT is still in a pre-release state, and protocol implementation
will likely be adjusted before release on a Polymesh testnet.

## Libraries

### Confidential Identity Library

This library implements the Confidential Identity Library protocol, as described
[here][wiki_main_design]. The cryptographic building blocks are described
[here][wiki_crypto_design].

### Core Cryptography Library

This library implements the essential Zero-Knowledge Proofs that are used in all the libraries
of this repository. For more details see section 5 of the MERCAT whitepaper.

### MERCAT Library

This library implements the necessary API to handle account creation, confidential asset
issuance, and confidential asset transfer, as outlined in section 6 of the MERCAT whitepaper.

## APIs and CLIs

Each library exposes various APIs and CLIs, which can be found inside
each library directory. For example, the confidential identity library
exposes a wasm api, an FFI wrapper, and a CLI.

## Documentation

To produce the documentation, run:

```bash
cargo +nightly doc --open
```

## Build Instructions

TL;DR: run the following to download the toolchain, compile the code,
and run tests and benchmarks.

```bash
# Install prereqs
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup toolchain install nightly
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
rustup target add wasm32-unknown-unknown --toolchain nightly
cargo install cbindgen


# Build and test the rust code
cargo +nightly build --release
cargo +nightly test --release -- --nocapture
cargo +nightly bench

# Build WASM bindings
cd ./cryptography-core
rustup run nightly wasm-pack test --node
cd -

cd ./confidential-identity/wasm/
rustup run nightly wasm-pack build --release
cd -

cd ./mercat/wasm/
rustup run nightly wasm-pack build --release
cd -


# Build C bindings
cd ./confidential-identity/ffi/
cbindgen --config cbindgen.toml --crate confidential-identity-ffi --output examples/c_example.h
# Manually replace `typedef` with `typedef struct` in the generated file
gcc examples/c_example.c -L../../target/release/ -l confidential_identity_ffi -o example.out
cd -

# Generate and open the documentation
cargo doc --open
```

More detailed steps:

Install rust from https://www.rust-lang.org/tools/install
On linux-based systems, you can run

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

This will install the `stable` version of rust, but this repository
requires the `nightly` version. To install the nightly version, run

```bash
rustup toolchain install nightly
```

Running `rustup show` should show both a stable and a nightly version.
Note that if the nightly version is not the active toolchain, you will
need to add `+nightly` to the commands. The rest of the commands in the
readme assume that your active toolchain is `stable` and therefore, you
will see `+nightly` in the commands.

Next, install WASM support so that the code can be run on the browser.
Install wasm-pack from https://rustwasm.github.io/wasm-pack/installer/

On linux-based systems, you can run

```bash
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
```

By default, rust compiles for your Operating System, to enable the code
to be compiled for wasm, you need to add a target for it.

```bash
rustup target add wasm32-unknown-unknown --toolchain nightly
# View the list of installed targets
rustup +nightly target list | grep installed
```

If you use a different command to install a specific nightly version, use the same format for
adding WASM.

To build the library and all the projects, run from the root directory
of the repository.

```bash
cargo +nightly build --release
```

To build the wasm versions, change to a `wasm` directory and run

```bash
cd ./confidential-identity/wasm/
rustup run nightly wasm-pack build --release
```

To generate C bindings, first install the `cbindgen` tool.

```bash
cargo install cbindgen
```

Next, generate the bindings by going to an `ffi` directory and running
the following command.

```bash
cbindgen --config cbindgen.toml --crate confidential-identity-ffi --output examples/c_example.h
# Note that unfortunately `cbindgen` doesn't map the typedefs properly, so manually replace `typedef` with `typedef struct`.
# Then, build the bindings using the following command.
gcc examples/c_example.c -L../../target/release/ -l confidential_identity_ffi -o example.out
```

Run the unit tests with:

```bash
cargo +nightly test --release -- --nocapture
```

Build and run the benchmarks with:

```bash
cargo +nightly bench
```

Generate and open the documentation with `cargo doc --open`.

### Verify WASM support

WASM built is disabled in the default feature. If you want to double-check that library can be
built in WASM, you have to enable `no_std` feature.

```bash
$ cd cryptography-core
cryptography-core $ cargo build +nightly --target wasm32-unknown-unknown --no-default-features --features no_std
```

To run tests on WASM, follow [wasm-bindgen-test][wasm-bindgen-test].

More specifically, ensure that you have `nodejs` installed and that `wasm-bindgen-test` is a
dev dependency. Now, you can add `#[wasm_bindgen_test]` to any function that you want to be
tested for WASM support.

You can run the WASM tests with

```bash
rustup run nightly wasm-pack test --node
```

[wasm-bindgen-test]: https://rustwasm.github.io/docs/wasm-bindgen/wasm-bindgen-test/usage.html
[wiki_main_design]: https://polymesh.atlassian.net/wiki/spaces/PC/pages/172523576/Asset+Granularity+Unique+Identity
[wiki_crypto_design]: https://polymesh.atlassian.net/wiki/spaces/CE/pages/202571817/Claim+Proof+Prototype
[mercat-paper]: https://info.polymath.network/cs/c/?cta_guid=9dab4f08-f83b-4682-9aff-806161fadfa7&signature=AAH58kGwwttiprV_ahCcsg9jx4d7sDcTug&placement_guid=7b405314-ade5-48d5-8143-1622a545448a&click=34bcee43-5f48-4d28-b28f-71a27f9a901b&hsutk=b438673d645d6ae5ac515c177200a48e&canon=https%3A%2F%2Fpolymath.network%2Fresources&portal_id=4703451&redirect_url=APefjpGNTUtthjOVK6QYdk_-PL9D6OAzM2VCYb7J4LhcV3iCGtpU2IRpNw3ZYh-dU7CZpEGmueyCnKbsmj6KYiF23DUwQL_CB0uteyVXdrLMO0LO32kxSDhtnCK2kWZYwgk6XH47zFTvb_vPNlHLEN9FeceoaUSdrVaJ4pGzgFjL6q2XRWBDX_W0i4P28C0JZxnAKfM-UQH2VH2xWt2wyBvk9kcuV-bu42BOTu1RJSPSGy27MArSihbQVeL8Cccu0IUOK6Ld7vTEGanGK8dtDPUOzpEhkxmaOpwFfpoyDum-NaSZtBWNQ6fZhvEJhqz9NLBYFjju5w9REDT8Iso3jKIu0EM7cLsAivTS2DBgYofp_Q6-Dq6ubhw&__hstc=225977093.b438673d645d6ae5ac515c177200a48e.1593533608372.1603731569270.1604512109227.10&__hssc=225977093.1.1604512109227&__hsfp=4241984383
