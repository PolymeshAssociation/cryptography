#! /bin/bash

set -e

SRC_DIR="$1"
DST_DIR="$2"

if [ "$#" -ne 2 ]; then
    echo "$0 <SRC_DIR> <DST_DIR>"
    exit 1
fi

echo "Building npm package from $SRC_DIR to $DST_DIR"

rm -rf "$DST_DIR"
mkdir -p "$DST_DIR"
cd "$SRC_DIR"
cp "$ROOT/LICENSE" .
wasm-pack build --release
cp -r pkg/* "$DST_DIR"

# TODO: publish to npm if run by CI
