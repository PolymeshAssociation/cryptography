#! /bin/bash

set -eo pipefail

PROJECT_DIR=$1

if [ "$#" -ne 1 ]; then
    echo "$0 <PROJECT_DIR>"
    exit 1
fi

cd "$PROJECT_DIR"

GET_VERSION_PY='import json,sys;print(json.load(sys.stdin)["packages"][0]["version"])'
NEW_VERSION=$(cargo metadata --format-version 1 | python -c "$GET_VERSION_PY")
git checkout $PREV_SHA
PREV_VERSION=$(cargo metadata --format-version 1 | python -c "$GET_VERSION_PY")
echo "---> Version before the PR $PREV_VERSION"
echo "---> Version before in the PR $NEW_VERSION"

if [ "$PREV_VERSION" == "$NEW_VERSION" ]
then
  echo "VERSION_CHANGED=" >> $GITHUB_ENV
else
  echo "VERSION_CHANGED=yes" >> $GITHUB_ENV
  echo "NEW_VERSION=$NEW_VERSION" >> $GITHUB_ENV
fi

