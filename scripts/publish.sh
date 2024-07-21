#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd "$SCRIPT_DIR/.."

mkdir -p dist

echo "Building and publishing to docker hub..."

docker buildx build --platform linux/amd64,linux/arm64 -t tantosec/oneshell:latest --push .

echo "Building and publishing to Github releases..."

extract_platform() {
    id=$(docker create --platform "$1" tantosec/oneshell)
    tf="mktemp"
    docker cp "$id:/oneshell" - > "$tf"
    tar -O -xf "$tf" > dist/oneshell-"$(echo "$1" | cut -d'/' -f2)"
    rm "$tf"
    docker rm -v "$id"
}

extract_platform "linux/amd64"
extract_platform "linux/arm64"

# TODO: Create tag and automatically use gh command to upload release
echo "Github release artifacts pushed to dist/ directory. Please upload to Github manually."

echo "Publish complete!"