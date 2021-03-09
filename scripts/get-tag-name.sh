#!/bin/bash

set -eo pipefail

ROOT=$( cd `dirname $0`/..;  pwd )

if [ "$#" -ne 1 ]; then
    echo "$0 <PROJECT_NAME>"
    exit 1
fi
PROJECT_NAME="$1"
cd "$ROOT/$PROJECT_NAME"

NEW_VERSION=$(cargo metadata --format-version 1 | python ../scripts/parse-cargo-version.py ${PROJECT_NAME})
echo "Version number: $NEW_VERSION"
echo "TAG_NAME: ${PROJECT_NAME}-v${NEW_VERSION}"

echo "TAG_NAME=${PROJECT_NAME}-v${NEW_VERSION}" >> $GITHUB_ENV
