#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd "$SCRIPT_DIR/.."

docker build --platform=linux/amd64 -f scripts/build-dist.Dockerfile -t oneshell-dist-builder .

docker run --platform=linux/amd64 -u "$(id -u):$(id -g)" --rm -v $(pwd):/pwd oneshell-dist-builder bash -c 'cd /pwd && ./scripts/build-dist.sh'
