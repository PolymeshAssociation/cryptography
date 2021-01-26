#! /bin/bash

set -e

PROJECT_NAME=$1
SRC_DIR=$2
DST_DIR=$3

if [ "$#" -ne 3 ]; then
    echo "$0 <PROJECT_NAME> <SRC_DIR> <DST_DIR>"
    exit 1
fi

mkdir -p "$DST_DIR"
cd "$SRC_DIR"

echo "Compressing $SRC_DIR"
for ARTIFACT_NAME in $(ls -1)
do
	tar -czvf $PROJECT_NAME-$ARTIFACT_NAME.tar.gz "$ARTIFACT_NAME" > /dev/null
	sha256sum $PROJECT_NAME-$ARTIFACT_NAME.tar.gz > $PROJECT_NAME-$ARTIFACT_NAME.sha256sum
	mv $PROJECT_NAME-$ARTIFACT_NAME.tar.gz    "$DST_DIR"
	mv $PROJECT_NAME-$ARTIFACT_NAME.sha256sum "$DST_DIR"
	rm -rf "$SRC_DIR/$ARTIFACT_NAME"
done
