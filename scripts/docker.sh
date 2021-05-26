#! /bin/bash

set -eo pipefail

ROOT=$( cd `dirname $0`/..;  pwd )


if [ "$#" -eq 0 ]; then
    echo "$0 run/build/shell"
    exit 1
fi

if [ "$1" == "shell" ] 
then
  docker run --rm -it -v "$(pwd)":/src cryptography /bin/bash
fi

if [ "$1" == "build" ] 
then
  cd docker && docker build -t cryptography .
fi

if [ "$1" == "run" ] 
then
  shift 1
  docker run -v "$(pwd)":/src -w /src cryptography $@
fi

if [ "$1" == "copy-run" ] 
then
  shift 1
  docker cp . cryptography:/src
  docker run -w /src cryptography $@
fi

