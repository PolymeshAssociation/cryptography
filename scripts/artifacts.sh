#! /bin/bash

ROOT=$( cd `dirname $0`/..;  pwd )
ARTIFACT_DIR="artifacts"

cd "$ROOT"
cargo build --release

# ---------------------------------------------------------------------------------
# -                          Cryptography Core Artifacts                          -
# ---------------------------------------------------------------------------------
CORE_ROOT="$ROOT/cryptography-core"
rm -rf "$CORE_ROOT/$ARTIFACT_DIR"
mkdir  "$CORE_ROOT/$ARTIFACT_DIR"
cd     "$CORE_ROOT"

# ====== Rust Library Source code
mkdir -p "$ARTIFACT_DIR/sources/cryptography-core"
find . -type f -not -path "./target/*" -not -path "./artifacts/*" -exec cp --parents {} "$ARTIFACT_DIR/sources/cryptography-core" \;

# ====== Rust Library Crate
# TODO: Having issue with versions...


# ---------------------------------------------------------------------------------
# -                                 Mercat Artifacts                              -
# ---------------------------------------------------------------------------------
MERCAT_ROOT="$ROOT/mercat"
rm -rf "$MERCAT_ROOT/$ARTIFACT_DIR"
mkdir  "$MERCAT_ROOT/$ARTIFACT_DIR"
cd     "$MERCAT_ROOT"

# ====== Rust Library Source code
mkdir -p "$ARTIFACT_DIR/sources/cryptography-core"
mkdir -p "$ARTIFACT_DIR/sources/mercat"
find ../cryptography-core -type f -not -path "../cryptography-core/target/*" -not -path "../cryptography-core/artifacts/*" -exec cp --parents {} "$ARTIFACT_DIR/sources/cryptography-core" \;
find . -type f -not -path "./target/*" -not -path "./artifacts/*" -not -path "./wasm/*" -not -path "./cli/*" -not -path "./ffi/*" -exec cp --parents {} "$ARTIFACT_DIR/sources/mercat" \;

# ====== Rust Library Crate
# TODO: Having issue with versions...

# ====== WASM npm package

# ====== C Libraries

# ====== CLI Executables


# ---------------------------------------------------------------------------------
# -                          Confidential Identity Artifacts                      -
# ---------------------------------------------------------------------------------
CONFIDENTIAL_IDENTITY_ROOT="$ROOT/confidential-identity"
rm -rf "$CONFIDENTIAL_IDENTITY_ROOT/$ARTIFACT_DIR"
mkdir  "$CONFIDENTIAL_IDENTITY_ROOT/$ARTIFACT_DIR"
cd     "$CONFIDENTIAL_IDENTITY_ROOT"

# ====== Rust Library Source code
mkdir -p "$ARTIFACT_DIR/sources/cryptography-core"
mkdir -p "$ARTIFACT_DIR/sources/confidential-identity"
find ../cryptography-core -type f -not -path "../cryptography-core/target/*" -not -path "../cryptography-core/artifacts/*" -exec cp --parents {} "$ARTIFACT_DIR/sources/cryptography-core" \;
find . -type f -not -path "./target/*" -not -path "./artifacts/*" -not -path "./wasm/*" -not -path "./cli/*" -not -path "./ffi/*" -exec cp --parents {} "$ARTIFACT_DIR/sources/confidential-identity" \;

# ====== Rust Library Crate
# TODO: Having issue with versions...

# ====== WASM npm package

# ====== C Libraries

# ====== CLI Executables

