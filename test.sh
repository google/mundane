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

# Test with each feature individually
for features in $FEATURES run-symbol-conflict-test; do
    cargo test --features "$features"
done

# Test with all features together to make sure they work
# correctly together. Don't both with run-symbol-conflict-test
# since a) it takes a long time and, b) it isn't affected by
# other features.
cargo test --features "$FEATURES"
