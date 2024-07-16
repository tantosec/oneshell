#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd "$SCRIPT_DIR/.."

docker buildx build --platform linux/amd64,linux/arm64 -t tantosec/oneshell:latest --push .