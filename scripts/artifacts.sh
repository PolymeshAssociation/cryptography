#! /bin/bash

ROOT=$( cd `dirname $0`/..;  pwd )
ARTIFACT_DIR="artifacts"
mkdir $ARTIFACT_DIR

echo "Building the binaries..."
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
echo "Packing core source files..."
mkdir -p "$ARTIFACT_DIR/src/cryptography-core"
find . -type f -not -path "./target/*" -not -path "./artifacts/*" -exec cp --parents {} "$ARTIFACT_DIR/src/cryptography-core" \;
tar -czvf cryptography-core-src.tar.gz "$ARTIFACT_DIR/src"
mv cryptography-core-src.tar.gz "$ROOT/$ARTIFACT_DIR"
rm -rf "$ARTIFACT_DIR/src"

# ====== Rust Library Crate
echo "Packing core lib... SKIPPED"
# TODO: Having issue with versions...


# ---------------------------------------------------------------------------------
# -                                 Mercat Artifacts                              -
# ---------------------------------------------------------------------------------
MERCAT_ROOT="$ROOT/mercat"
rm -rf "$MERCAT_ROOT/$ARTIFACT_DIR"
mkdir  "$MERCAT_ROOT/$ARTIFACT_DIR"
cd     "$MERCAT_ROOT"

# ====== Rust Library Source code
echo "Packing MERCAT source files..."
mkdir -p "$ARTIFACT_DIR/src/cryptography-core"
mkdir -p "$ARTIFACT_DIR/src/mercat"
find ../cryptography-core -type f -not -path "../cryptography-core/target/*" -not -path "../cryptography-core/artifacts/*" -exec cp --parents {} "$ARTIFACT_DIR/src/cryptography-core" \;
find . -type f -not -path "./target/*" -not -path "./artifacts/*" -not -path "./wasm/*" -not -path "./cli/*" -exec cp --parents {} "$ARTIFACT_DIR/src/mercat" \;
tar -czvf mercat-src.tar.gz "$ARTIFACT_DIR/src"
mv mercat-src.tar.gz "$ROOT/$ARTIFACT_DIR"
rm -rf "$ARTIFACT_DIR/src"

# ====== Rust Library Crate
echo "Packing MERCAT lib... SKIPPED"
# TODO: Having issue with versions...

# ====== WASM npm package
echo "Packing MERCAT npm package..."
mkdir -p "$ARTIFACT_DIR/npm"
cd $ROOT/mercat/wasm
wasm-pack build --release
cp -r pkg/* "$ROOT/mercat/$ARTIFACT_DIR/npm/"
cd -
tar -czvf mercat-npm.tar.gz "$ARTIFACT_DIR/npm"
mv mercat-npm.tar.gz "$ROOT/$ARTIFACT_DIR"
rm -rf "$ARTIFACT_DIR/npm"
# TODO: publish to npm if run by CI

# ====== CLI Executables
# Copying to linux-x64 since the CI will be an x64 Ubuntu
echo "Packing MERCAT CLI binaries..."
mkdir -p "$ARTIFACT_DIR/bin/linux-x64"
cp "$ROOT/target/release/mercat-interactive" "$ARTIFACT_DIR/bin/linux-x64/"
cp "$ROOT/target/release/mercat-chain-setup" "$ARTIFACT_DIR/bin/linux-x64/"
cp "$ROOT/target/release/mercat-mediator"    "$ARTIFACT_DIR/bin/linux-x64/"
cp "$ROOT/target/release/mercat-account"     "$ARTIFACT_DIR/bin/linux-x64/"
cp "$ROOT/target/release/mercat-validator"   "$ARTIFACT_DIR/bin/linux-x64/"
tar -czvf mercat-bin.tar.gz "$ARTIFACT_DIR/bin"
mv mercat-bin.tar.gz "$ROOT/$ARTIFACT_DIR"
rm -rf "$ARTIFACT_DIR/bin"


# ---------------------------------------------------------------------------------
# -                          Confidential Identity Artifacts                      -
# ---------------------------------------------------------------------------------
CONFIDENTIAL_IDENTITY_ROOT="$ROOT/confidential-identity"
rm -rf "$CONFIDENTIAL_IDENTITY_ROOT/$ARTIFACT_DIR"
mkdir  "$CONFIDENTIAL_IDENTITY_ROOT/$ARTIFACT_DIR"
cd     "$CONFIDENTIAL_IDENTITY_ROOT"

# ====== Rust Library Source code
echo "Packing Confidential Identity source files..."
mkdir -p "$ARTIFACT_DIR/src/cryptography-core"
mkdir -p "$ARTIFACT_DIR/src/confidential-identity"
find ../cryptography-core -type f -not -path "../cryptography-core/target/*" -not -path "../cryptography-core/artifacts/*" -exec cp --parents {} "$ARTIFACT_DIR/src/cryptography-core" \;
find . -type f -not -path "./target/*" -not -path "./artifacts/*" -not -path "./wasm/*" -not -path "./cli/*" -not -path "./ffi/*" -exec cp --parents {} "$ARTIFACT_DIR/src/confidential-identity" \;
tar -czvf confidential-identity-src.tar.gz "$ARTIFACT_DIR/src"
mv confidential-identity-src.tar.gz "$ROOT/$ARTIFACT_DIR"
rm -rf "$ARTIFACT_DIR/src"

# ====== Rust Library Crate
echo "Packing Confidential Identity lib... SKIPPED"
# TODO: Having issue with versions...

# ====== WASM npm package
echo "Packing Confidential Identity npm package..."
mkdir -p "$ARTIFACT_DIR/npm"
cd $ROOT/confidential-identity/wasm
wasm-pack build --release
cp -r pkg/* "$ROOT/confidential-identity/$ARTIFACT_DIR/npm/"
cd -
tar -czvf confidential-identity-npm.tar.gz "$ARTIFACT_DIR/npm"
mv confidential-identity-npm.tar.gz "$ROOT/$ARTIFACT_DIR"
rm -rf "$ARTIFACT_DIR/npm"
# TODO: publish to npm if run by CI

# ====== C Libraries
echo "Packing Confidential Identity C bindings..."
mkdir -p "$ARTIFACT_DIR/ffi"
cp "$ROOT/target/release/libconfidential_identity_ffi.so" "$ARTIFACT_DIR/ffi"
cp "$CONFIDENTIAL_IDENTITY_ROOT/ffi/confidential_identity.h" "$ARTIFACT_DIR/ffi"
tar -czvf confidential-identity-ffi.tar.gz "$ARTIFACT_DIR/ffi"
mv confidential-identity-ffi.tar.gz "$ROOT/$ARTIFACT_DIR"
rm -rf "$ARTIFACT_DIR/ffi"


# ====== CLI Executables
# Copying to linux-x64 since the CI will be an x64 Ubuntu
echo "Packing Confidential Identity CLI executables..."
mkdir -p "$ARTIFACT_DIR/bin/linux-x64"
cp "$ROOT/target/release/polymath-scp" "$ARTIFACT_DIR/bin/linux-x64/"
cp "$ROOT/target/release/polymath-scv" "$ARTIFACT_DIR/bin/linux-x64/"
tar -czvf confidential-identity-bin.tar.gz "$ARTIFACT_DIR/bin"
mv confidential-identity-bin.tar.gz "$ROOT/$ARTIFACT_DIR"
rm -rf "$ARTIFACT_DIR/bin"

