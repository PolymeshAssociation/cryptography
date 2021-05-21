# Private Identity Audit Library FFI Wrapper

## Build Instructions

Build the cryptography library in release mode:

```bash
cargo +nightly build --release
```

To regenerate the C header file; First install the `cbindgen` tool:

```bash
cargo install cbindgen
```

Second:

```bash
cbindgen --config cbindgen.toml --crate private-identity-audit-ffi --output include/private_identity_audit.h
```

To build the example using gcc, run:

```bash
gcc examples/c_example.c -I include -L../../target/release/ -l private_identity_audit_ffi -l confidential_identity_ffi -o examples.out
```
NOTE: CDD providers use the CIL to generate CDD IDs, and that's why this FFI is linking with `confidential_identity_ffi`.
