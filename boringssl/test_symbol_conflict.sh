#!/bin/bash

# Copyright 2018 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

# This script tests that a build with multiple versions of the Mundane crate in
# the same build graph works properly. It performs the following steps:
# - Create a temporary directory
# - Create two copies of Mundane - mundane-v1, and mundane-v2 - which directly
#   expose the boringssl::ffi module so that dependent crates can access the raw
#   symbols
# - Create two crates, one depending on mundane-v1, and one on mundane-v2, each
#   of which exposes all of the BoringSSL symbols from Mundane
# - Create a top-level program which depends on both of these crates
# - Have the top-level program's main link all of the Mundane functions from
#   each of the crates
# - Produce a release build, which forces linking, to make sure that linking
#   these two versions of the library at the same time works properly

set -e

# the directory this script lives in
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_ROOT="${SCRIPT_DIR}/.."

TMP="$(mktemp -d)"
trap "rm -rf $TMP" EXIT
cd "$TMP"

# NOTE: The -L means to follow symlinks
cp -LR "$CRATE_ROOT" mundane-v1
cp -LR "$CRATE_ROOT" mundane-v2
echo "$TMP"

#
# Make Mundane crates
#

# Update the Cargo.toml versions and names in place to be distinct
sed -i'' -e 's/^name =.*/name = "mundane-v1"/' mundane-v1/Cargo.toml
sed -i'' -e 's/^version =.*/version = "1.0.0"/' mundane-v1/Cargo.toml
sed -i'' -e 's/^name =.*/name = "mundane-v2"/' mundane-v2/Cargo.toml
sed -i'' -e 's/^version =.*/version = "2.0.0"/' mundane-v2/Cargo.toml

# Update the link directive to use the right version number
sed -i'' -e 's/#[link(name = "crypto_[0-9]*_[0-9]*_[0-9]*")]/#[link(name = "crypto_1_0_0")]/' mundane-v1/boringssl/boringssl.rs
sed -i'' -e 's/#[link(name = "crypto_[0-9]*_[0-9]*_[0-9]*")]/#[link(name = "crypto_2_0_0")]/' mundane-v2/boringssl/boringssl.rs
# Update the link_name directives to use the right version number
sed -i'' -e 's/__RUST_MUNDANE_[0-9]*_[0-9]*_[0-9]*_/__RUST_MUNDANE_1_0_0_/' mundane-v1/boringssl/boringssl.rs
sed -i'' -e 's/__RUST_MUNDANE_[0-9]*_[0-9]*_[0-9]*_/__RUST_MUNDANE_2_0_0_/' mundane-v2/boringssl/boringssl.rs
# Mark the ffi module as public
sed -i'' -e 's/^mod ffi;$/pub mod ffi;/' mundane-v1/src/boringssl/mod.rs
sed -i'' -e 's/^mod ffi;$/pub mod ffi;/' mundane-v2/src/boringssl/mod.rs
# Make Mundane directly expose the ffi module
echo "pub use boringssl::ffi;" >> mundane-v1/src/lib.rs
echo "pub use boringssl::ffi;" >> mundane-v2/src/lib.rs

#
# Make crates which depend on Mundane
#

# Usage: make_crate <crate name> <dep name>
function make_crate {
    CRATE_NAME="$1"
    DEP_NAME="$2"
    DEP_NAME_RS="$(echo ${DEP_NAME} | tr - _)"

    mkdir "$CRATE_NAME"
    mkdir "${CRATE_NAME}/src"
    # Re-export all symbols from Mundane
    cat >> "${CRATE_NAME}/src/lib.rs" <<EOF
extern crate ${DEP_NAME_RS};

pub use ${DEP_NAME_RS}::ffi::*;
EOF

    cat >> "${CRATE_NAME}/Cargo.toml" <<EOF
[package]
name = "${CRATE_NAME}"
version = "0.0.0"

[dependencies]
${DEP_NAME} = { path = "../${DEP_NAME}" }
EOF
}

make_crate depends-mundane-v1 mundane-v1
make_crate depends-mundane-v2 mundane-v2

#
# Make top-level crate
#

cat >> Cargo.toml <<EOF
[package]
name = "mundane-version-test"
version = "0.0.0"

[dependencies]
depends-mundane-v1 = { path = "./depends-mundane-v1" }
depends-mundane-v2 = { path = "./depends-mundane-v2" }
EOF

mkdir src
cat >> src/main.rs <<EOF
extern crate depends_mundane_v1;
extern crate depends_mundane_v2;

fn main() {
EOF

# Populate the body of main() with lines of the form:
# println!("{:?}", depends_mundane_v1::SYMBOL as *const ());
# println!("{:?}", depends_mundane_v2::SYMBOL as *const ());
#
# Find the functions to use by scraping boringssl.rs.
#
# TODO(joshlf): Are there other types of symbols we want to include (such as
# static variables)?
rg -U 'extern "C" \{\n[^\n]*\n    pub fn [0-9A-Za-z_]*([^)]*)' "${SCRIPT_DIR}/boringssl.rs" | \
    grep '^ *pub fn' | sed -e 's/.*pub fn \([^(]*\).*/println!("{:?}", depends_mundane_v1::\1 as *const ());/' >> src/main.rs
rg -U 'extern "C" \{\n[^\n]*\n    pub fn [0-9A-Za-z_]*([^)]*)' "${SCRIPT_DIR}/boringssl.rs" | \
    grep '^ *pub fn' | sed -e 's/.*pub fn \([^(]*\).*/println!("{:?}", depends_mundane_v2::\1 as *const ());/' >> src/main.rs
echo '}' >> src/main.rs

cargo build --release
