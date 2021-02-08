#!/bin/bash

set -eo pipefail

ROOT=$( cd `dirname $0`/..;  pwd )

if [ "$#" -ne 3 ]; then
    echo "$0 <PROJECT_NAME>"
    exit 1
fi
PROJECT_NAME="$1"
cd "$ROOT/$PROJECT_NAME"

GET_VERSION_PY='import json,sys;print json.load(sys.stdin)["packages"][0]["version"]'
NEW_VERSION=$(cargo metadata --format-version 1 | python -c "$GET_VERSION_PY")
echo "Version number: $NEW_VERSION"

echo "TAG_NAME=${PROJECT_NAME}-v${NEW_VERSION}" >> $GITHUB_ENV
