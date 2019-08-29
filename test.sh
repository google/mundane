#!/bin/bash

# Copyright 2019 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

set -eu

FEATURES="insecure
kdf
bytes
rsa-pkcs1v15
rsa-test-generate-large-keys
experimental-sha512-ec"

# If --target is not explicitly passed to cargo, it will apply RUSTFLAGS to proc
# macros, which cannot be sanitized.
TARGET=$(rustc -Vv |grep host |cut -d ' ' -f 2)
export RUSTFLAGS="-Z sanitizer=address"

# Test with each feature individually
for features in $FEATURES; do
    cargo test --features "$features" --target "$TARGET"
done

# The symbol conflict test doesn't pass --target to cargo, so sanitizing it
# doesn't work and would in any case be redundant.
RUSTFLAGS="" cargo test --features run-symbol-conflict-test --test integration_tests -- test_symbol_conflict

# Test with all features together to make sure they work
# correctly together. Don't both with run-symbol-conflict-test
# since a) it takes a long time and, b) it isn't affected by
# other features.
cargo test --features "$FEATURES" --target "$TARGET"
