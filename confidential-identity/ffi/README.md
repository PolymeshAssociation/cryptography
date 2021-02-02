# Confidential Identity Library FFI Wrapper

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
cbindgen --config cbindgen.toml --crate confidential-identity-ffi --output examples/c_example.h
```

Note that unfortunately `cbindgen` doesn't map the typedefs properly, so manually replace `typedef`
with `typedef struct`, e.g.:

```rust
typedef struct <StructName> <StructName>;
```

To build the example using gcc, run:

```bash
gcc examples/c_example.c -I include -L../../target/release/ -l confidential_identity_ffi -o example.out
```
