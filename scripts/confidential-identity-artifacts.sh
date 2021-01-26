#! /bin/bash

# This script is written with the intention of being run by CI/CD pipelines.

# A temporary directory `confidential-identity/artifacts` is used to gather and compress various
# artifacts. Once the artifacts are created, they are moved the the artifact directory in the
# root of the repository `cryptography/artifacts`. The CI will then upload everything in the
# root artifact directory to the github release.

# At the moment we publish the following artifacts for this crate.
# 1. Rust source code. TODO: also publish the Rust library to crates.io
# 2. WASM bindings as an npm package. TODO: also publish the npm package to npmjs.com
# 3. CLI executables (for linux x64).
# 4. FFI binding (a *.so file + a *.h header file)

set -e

ROOT=$( cd `dirname $0`/..;  pwd )
PREFIX="$ROOT/confidential-identity"

echo "----------------------- Build the binaries ------------------------"
cd "$ROOT" && cargo build --release

echo "------------------- Packaging cryptography-core -------------------"
# Prep directories
rm -rf "$PREFIX/artifacts"
mkdir  "$PREFIX/artifacts"
mkdir -p "$ROOT/artifacts"

# Gather artifacts
"$ROOT/scripts/source_artifact.sh" "$ROOT/cryptography-core" "$PREFIX/artifacts/src/cryptography-core"
"$ROOT/scripts/source_artifact.sh" "$PREFIX"                 "$PREFIX/artifacts/src/confidential-identity"
"$ROOT/scripts/crate_artifact.sh"
"$ROOT/scripts/npm_artifact.sh"    "$PREFIX/wasm"            "$PREFIX/artifacts/npm/"

echo "Packing Confidential Identity CLI binaries..."
mkdir -p "$PREFIX/artifacts/linux-x64"
cp "$ROOT/target/release/polymath-scp"                       "$PREFIX/artifacts/linux-x64/"
cp "$ROOT/target/release/polymath-scv"                       "$PREFIX/artifacts/linux-x64/"

echo "Packing Confidential Identity FFI bindings..."
mkdir -p "$PREFIX/artifacts/ffi"
cp "$ROOT/target/release/libconfidential_identity_ffi.so"    "$PREFIX/artifacts/ffi"
cp "$PREFIX/ffi/confidential_identity.h"                     "$PREFIX/artifacts/ffi"

# Compress artifacts and move them to a central location
"$ROOT/scripts/compress.sh" confidential-identity "$PREFIX/artifacts" "$ROOT/artifacts"
