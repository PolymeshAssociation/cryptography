# Asset Proofs Library FFI Wrapper

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
cbindgen --config cbindgen.toml --crate claim-proofs-ffi --output examples/c_example.h
```

Note that unfortunately `cbindgen` doesn't map the typedefs properly, so manually replace `typedef`
with `typedef struct`, e.g.:

```rust
typedef struct <StructName> <StructName>;
```

To build the example using gcc, run:

```bash
gcc examples/c_example.c -Ltarget/release/ -l claim_proofs_ffi -o example.out
```
