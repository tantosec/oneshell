#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

ndisasm -b 64 -e 120 "$SCRIPT_DIR/a.out" | sed -E 's/^[0-9A-F]+  //'