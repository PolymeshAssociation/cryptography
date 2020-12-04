# Cryptography

Repository for cryptographic libraries used in Polymath products. While these libraries could in
theory be used by other projects, the design and tradeoffs made are in many cases specifically
tailored for Polymesh. See https://github.com/PolymathNetwork/Polymesh for more details about
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

To produce the documenation, run:

```bash
cargo +nightly doc --open
```

## Build Instructions

Install rust!

Install the nightly version of rust and WASM toolchain.

```bash
# In the root directory
rustup toolchain install nightly

# Install wasm pack from https://rustwasm.github.io/wasm-pack/installer/
# then, inside the cryptography sub-directory, add the nightly version as target.
rustup target add wasm32-unknown-unknown --toolchain nightly
```

If you use a different command to install a specific nightly version, use the same format for
adding WASM.

To build the library and examples, run:

```bash
cargo +nightly build --release
```

To run the unit tests:

```bash
cargo +nightly test --release -- --nocapture
```

To build and run benchmarks:

```bash
cargo +nightly bench
```

### Verify WASM support

WASM built is disabled in the default feature. If you want to double-check that library can be
built in WASM, you have to enable `no_std` feature.

```bash
$ cd cryptography-core
cryptography-core $ cargo build --target wasm32-unknown-unknown --no-default-features --features no_std
```

To run tests on WASM, follow [wasm-bindgen-test][wasm-bindgen-test].

More specifically, ensure that you have `nodejs` installed and that `wasm-bindgen-test` is a
dev dependency. Now, you can add `#[wasm_bindgen_test]` to any function that you want to be
tested for WASM support.

You can run the WASM tests with

```bash
wasm-pack test --node
```

[wasm-bindgen-test]: https://rustwasm.github.io/docs/wasm-bindgen/wasm-bindgen-test/usage.html
[wiki_main_design]: https://polymath.atlassian.net/wiki/spaces/PC/pages/172523576/Asset+Granularity+Unique+Identity
[wiki_crypto_design]: https://polymath.atlassian.net/wiki/spaces/CE/pages/202571817/Claim+Proof+Prototype
[mercat-paper]: https://info.polymath.network/cs/c/?cta_guid=9dab4f08-f83b-4682-9aff-806161fadfa7&signature=AAH58kGwwttiprV_ahCcsg9jx4d7sDcTug&placement_guid=7b405314-ade5-48d5-8143-1622a545448a&click=34bcee43-5f48-4d28-b28f-71a27f9a901b&hsutk=b438673d645d6ae5ac515c177200a48e&canon=https%3A%2F%2Fpolymath.network%2Fresources&portal_id=4703451&redirect_url=APefjpGNTUtthjOVK6QYdk_-PL9D6OAzM2VCYb7J4LhcV3iCGtpU2IRpNw3ZYh-dU7CZpEGmueyCnKbsmj6KYiF23DUwQL_CB0uteyVXdrLMO0LO32kxSDhtnCK2kWZYwgk6XH47zFTvb_vPNlHLEN9FeceoaUSdrVaJ4pGzgFjL6q2XRWBDX_W0i4P28C0JZxnAKfM-UQH2VH2xWt2wyBvk9kcuV-bu42BOTu1RJSPSGy27MArSihbQVeL8Cccu0IUOK6Ld7vTEGanGK8dtDPUOzpEhkxmaOpwFfpoyDum-NaSZtBWNQ6fZhvEJhqz9NLBYFjju5w9REDT8Iso3jKIu0EM7cLsAivTS2DBgYofp_Q6-Dq6ubhw&__hstc=225977093.b438673d645d6ae5ac515c177200a48e.1593533608372.1603731569270.1604512109227.10&__hssc=225977093.1.1604512109227&__hsfp=4241984383
