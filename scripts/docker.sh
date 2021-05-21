#! /bin/bash

set -eo pipefail

ROOT=$( cd `dirname $0`/..;  pwd )


if [ "$#" -ne 1 ]; then
    echo "$0 run/build"
    exit 1
fi

if [ "$1" == "run" ] 
then
  docker run --rm -it -v "$(pwd)":/src cryptography-dev /bin/bash
fi

if [ "$1" == "build" ] 
then
  cd docker && docker build . -t cryptography-dev
fi
