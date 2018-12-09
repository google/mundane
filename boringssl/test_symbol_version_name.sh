#!/bin/bash

# cd to the directory this script lives in
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ $# -ne 3 ]; then
    echo "Usage: $0 <major> <minor> <patch>" >&2
    exit 1
fi

MAJOR="$1"
MINOR="$2"
PATCH="$3"

LINK_PATTERN="crypto_${MAJOR}_${MINOR}_${PATCH}"
LINK_RESULT=$(grep "#\[link(name = \"${LINK_PATTERN}\")\]" boringssl.rs | wc -l)
if [ "$LINK_RESULT" -ne 1 ]; then
    echo "link attribute missing or incorrect"
    exit 1
fi

LINK_NAME_PATTERN="__RUST_MUNDANE_${MAJOR}_${MINOR}_${PATCH}_[A-Za-z0-9_]\+"
LINK_NAME_RESULT=$(grep -n "#\[link_name = \".*\"\]" boringssl.rs \
                   | grep -v "#\[link_name = \"${LINK_NAME_PATTERN}\"\]")
if [[ ! -z "$LINK_NAME_RESULT" ]]; then
    echo "Mismatched link_name attribute(s) found:"
    echo "$LINK_NAME_RESULT"
    exit 1
fi

exit 0
