#! /bin/bash

# This script is written with the intention of being run by CI/CD pipelines.

# A temporary directory `mercat/artifacts` is used to gather and compress various
# artifacts. Once the artifacts are created, they are moved the the artifact directory in the
# root of the repository `cryptography/artifacts`. The CI will then upload everything in the
# root artifact directory to the github release.

# At the moment we publish the following artifacts for this crate.
# 1. Rust source code. TODO: also publish the Rust library to crates.io
# 2. WASM bindings as an npm package. TODO: also publish the npm package to npmjs.com
# 3. CLI executables (for linux x64).

set -e

ROOT=$( cd `dirname $0`/..;  pwd )
PREFIX="$ROOT/mercat"

echo "----------------------- Build the binaries ------------------------"
cd "$ROOT" && cargo build --release

echo "------------------- Packaging cryptography-core -------------------"
# Prep directories
rm -rf "$PREFIX/artifacts"
mkdir  "$PREFIX/artifacts"
mkdir -p "$ROOT/artifacts"

# Gather artifacts
"$ROOT/scripts/source_artifact.sh" "$ROOT/cryptography-core" "$PREFIX/artifacts/src/cryptography-core"
"$ROOT/scripts/source_artifact.sh" "$PREFIX"                 "$PREFIX/artifacts/src/mercat"
"$ROOT/scripts/crate_artifact.sh"
"$ROOT/scripts/npm_artifact.sh"    "$PREFIX/wasm"            "$PREFIX/artifacts/npm/"

echo "Packing MERCAT CLI binaries..."
mkdir -p "$PREFIX/artifacts/linux-x64"
cp "$ROOT/target/release/mercat-interactive" "$PREFIX/artifacts/linux-x64/"
cp "$ROOT/target/release/mercat-chain-setup" "$PREFIX/artifacts/linux-x64/"
cp "$ROOT/target/release/mercat-mediator"    "$PREFIX/artifacts/linux-x64/"
cp "$ROOT/target/release/mercat-account"     "$PREFIX/artifacts/linux-x64/"
cp "$ROOT/target/release/mercat-validator"   "$PREFIX/artifacts/linux-x64/"

# Compress artifacts and move them to a central location
"$ROOT/scripts/compress.sh" mercat "$PREFIX/artifacts" "$ROOT/artifacts"
