#! /bin/bash

set -e

SRC_DIR="$1"
DST_DIR="$2"

if [ "$#" -ne 2 ]; then
    echo "$0 <SRC_DIR> <DST_DIR>"
    exit 1
fi

echo "Gathering Rust source files from $SRC_DIR to $DST_DIR"

cd "$SRC_DIR"
rm -rf "$DST_DIR"
mkdir -p "$DST_DIR"
find . -type f -not -path "./target/*" -not -path "./artifacts/*" -not -path "./wasm/*" -not -path "./cli/*" -not -path "./ffi/*" -exec cp --parents {} "$DST_DIR" \;
