#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd "$SCRIPT_DIR/.."

DIST_DIR=pkg/patching/dist

get_size() {
    echo "$(wc -c <"$1" | cut -d' ' -f 1)"
}

pad_binary() {
    bin_name="$1"
    pad_n="$2"

    echo "Padding binary $bin_name to a multiple of $pad_n bytes"
    bin_size=$(get_size "$bin_name")
    echo "Starting size $bin_size"
    to_add=$(((pad_n - (bin_size % pad_n)) % pad_n))
    echo "Adding $to_add null bytes"

    while [[ $to_add -gt 0 ]]; do
        echo -en "\x00" >> "$1"
        to_add=$((to_add - 1))
    done
}

get_stage_1_key_offset() {
    tf=$(mktemp)
    tf2=$(mktemp)
    sed -E "s/STAGE_2_PAYLOAD_SIZE/8/" stager/stage1/stage1.asm > "$tf"
    nasm -f bin -o "$tf2" "$tf" || { rm "$tf"; exit 1; }
    rm "$tf"

    grep -aob 'AAAAAAAABBBBBBBB' "$tf2" | cut -d':' -f1
    rm "$tf2"
}

echo "Compiling client..."
CGO_ENABLED=0 go build -ldflags '-s -w -extldflags "-static"' -a -o "$DIST_DIR/client" client/main.go || exit 1
pad_binary "$DIST_DIR/client" 16
final_client_size=$(get_size "$DIST_DIR/client")

echo "Compiling stage 2..."
cp stager/stage2/constants.h{,.bak}
# Patching
sed -i -E "s/^#define CLIENT_SIZE .*$/#define CLIENT_SIZE $final_client_size/" stager/stage2/constants.h
key_offset=$(get_stage_1_key_offset)
sed -i -E "s/^#define KEY_OFFSET .*$/#define KEY_OFFSET $key_offset/" stager/stage2/constants.h
# Compile
gcc -s -static -Oz -masm=intel -o stager/stage2/stage2-c.out stager/stage2/stage2.c stager/stage2/aes/{aes.c,gcm.c} || { cp stager/stage2/constants.h{.bak,}; exit 1; }
mv stager/stage2/constants.h{.bak,}

(cd stager/stage2/; nasm -f bin -o ../../$DIST_DIR/stage2-payload.bin stage2.asm) || exit 1

echo "Padding stage 2..."

pad_binary "$DIST_DIR/stage2-payload.bin" 8

final_stage_2_size=$(get_size "$DIST_DIR/stage2-payload.bin")
echo "Padded size $final_stage_2_size"

echo "Compiling stage 1..."
tf=$(mktemp)
sed -E "s/STAGE_2_PAYLOAD_SIZE/$final_stage_2_size/" stager/stage1/stage1.asm > "$tf"
nasm -f bin -o $DIST_DIR/stage1-payload.bin "$tf" || { rm "$tf"; exit 1; }
rm "$tf"

echo "Final sizes:"
wc -c $DIST_DIR/{stage1-payload.bin,stage2-payload.bin,client}