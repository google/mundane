#!/bin/bash

# Copyright 2018 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

# This script tests that a build with multiple versions of the mundane crate in
# the same build graph works properly. It performs the following steps:
# - Create a temporary directory
# - Create two copies of mundane - mundane-v1, and mundane-v2 - which directly
#   expose the boringssl::ffi module so that dependent crates can access the raw
#   symbols
# - Create two crates, one depending on mundane-v1, and one on mundane-v2, each
#   of which exposes all of the BoringSSL symbols from mundane
# - Create a top-level program which depends on both of these crates
# - Have the top-level program's main call all of the mundane functions from
#   each of the crates
# - Produce a release build, which forces linking, to make sure that linking
#   these two versions of the library at the same time works properly

set -e

# the directory this script lives in
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_ROOT="${SCRIPT_DIR}/.."

TMP="$(mktemp -d)"
cd "$TMP"

# NOTE: The -L means to follow symlinks
cp -LR "$CRATE_ROOT" mundane-v1
cp -LR "$CRATE_ROOT" mundane-v2
echo "$TMP"

#
# Make mundane crates
#

# Update the Cargo.toml versions and names in place to be distinct
sed -i '' -e 's/^name =.*/name = "mundane-v1"/' mundane-v1/Cargo.toml
sed -i '' -e 's/^version =.*/version = "1.0.0"/' mundane-v1/Cargo.toml
sed -i '' -e 's/^name =.*/name = "mundane-v2"/' mundane-v2/Cargo.toml
sed -i '' -e 's/^version =.*/version = "2.0.0"/' mundane-v2/Cargo.toml

# Update the link directive to use the right version number
sed -i '' -e 's/#[link(name = "crypto_[0-9]*_[0-9]*_[0-9]*")]/#[link(name = "crypto_1_0_0")]/' mundane-v1/boringssl/boringssl.rs
sed -i '' -e 's/#[link(name = "crypto_[0-9]*_[0-9]*_[0-9]*")]/#[link(name = "crypto_2_0_0")]/' mundane-v2/boringssl/boringssl.rs
# Update the link_name directives to use the right version number
sed -i '' -e 's/__RUST_MUNDANE_[0-9]*_[0-9]*_[0-9]*_/__RUST_MUNDANE_1_0_0_/' mundane-v1/boringssl/boringssl.rs
sed -i '' -e 's/__RUST_MUNDANE_[0-9]*_[0-9]*_[0-9]*_/__RUST_MUNDANE_2_0_0_/' mundane-v2/boringssl/boringssl.rs
# Mark the ffi module as public
sed  -i '' -e 's/^mod ffi;$/pub mod ffi;/' mundane-v1/src/boringssl/mod.rs
sed  -i '' -e 's/^mod ffi;$/pub mod ffi;/' mundane-v2/src/boringssl/mod.rs
# Make mundane directly expose the ffi module
echo "pub use boringssl::ffi;" >> mundane-v1/src/lib.rs
echo "pub use boringssl::ffi;" >> mundane-v2/src/lib.rs

#
# Make crates which depend on mundane
#

# Usage: make_crate <crate name> <dep name>
function make_crate {
    CRATE_NAME="$1"
    DEP_NAME="$2"
    DEP_NAME_RS="$(echo ${DEP_NAME} | tr - _)"

    mkdir "$CRATE_NAME"
    mkdir "${CRATE_NAME}/src"
    # Re-export all symbols from mundane
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

# The body of main() is generated with the following scripts:
# rg -U 'extern "C" \{\n[^\n]*\n    pub fn [0-9A-Za-z_]*([^)]*)' boringssl.rs | grep '^ *pub fn' | sed -e 's/.*pub fn \([^(]*\).*/println!("{:?}", depends_mundane_v1::\1 as *const ());/'
# rg -U 'extern "C" \{\n[^\n]*\n    pub fn [0-9A-Za-z_]*([^)]*)' boringssl.rs | grep '^ *pub fn' | sed -e 's/.*pub fn \([^(]*\).*/println!("{:?}", depends_mundane_v2::\1 as *const ());/'

mkdir src
cat >> src/main.rs <<EOF
extern crate depends_mundane_v1;
extern crate depends_mundane_v2;

fn main() {
println!("{:?}", depends_mundane_v1::ERR_print_errors_cb as *const ());
println!("{:?}", depends_mundane_v1::CBS_init as *const ());
println!("{:?}", depends_mundane_v1::CBS_len as *const ());
println!("{:?}", depends_mundane_v1::CBB_init as *const ());
println!("{:?}", depends_mundane_v1::CBB_cleanup as *const ());
println!("{:?}", depends_mundane_v1::CBB_data as *const ());
println!("{:?}", depends_mundane_v1::CBB_len as *const ());
println!("{:?}", depends_mundane_v1::ED25519_keypair as *const ());
println!("{:?}", depends_mundane_v1::ED25519_sign as *const ());
println!("{:?}", depends_mundane_v1::ED25519_verify as *const ());
println!("{:?}", depends_mundane_v1::ED25519_keypair_from_seed as *const ());
println!("{:?}", depends_mundane_v1::EVP_sha1 as *const ());
println!("{:?}", depends_mundane_v1::EVP_sha256 as *const ());
println!("{:?}", depends_mundane_v1::EVP_sha384 as *const ());
println!("{:?}", depends_mundane_v1::EVP_sha512 as *const ());
println!("{:?}", depends_mundane_v1::EC_GROUP_new_by_curve_name as *const ());
println!("{:?}", depends_mundane_v1::EC_GROUP_get_curve_name as *const ());
println!("{:?}", depends_mundane_v1::EC_curve_nid2nist as *const ());
println!("{:?}", depends_mundane_v1::EC_KEY_new as *const ());
println!("{:?}", depends_mundane_v1::EC_KEY_free as *const ());
println!("{:?}", depends_mundane_v1::EC_KEY_up_ref as *const ());
println!("{:?}", depends_mundane_v1::EC_KEY_get0_group as *const ());
println!("{:?}", depends_mundane_v1::EC_KEY_set_group as *const ());
println!("{:?}", depends_mundane_v1::EC_KEY_generate_key as *const ());
println!("{:?}", depends_mundane_v1::EC_KEY_parse_private_key as *const ());
println!("{:?}", depends_mundane_v1::EC_KEY_marshal_private_key as *const ());
println!("{:?}", depends_mundane_v1::ECDSA_sign as *const ());
println!("{:?}", depends_mundane_v1::ECDSA_verify as *const ());
println!("{:?}", depends_mundane_v1::ECDSA_size as *const ());
println!("{:?}", depends_mundane_v1::EVP_PKEY_new as *const ());
println!("{:?}", depends_mundane_v1::EVP_PKEY_free as *const ());
println!("{:?}", depends_mundane_v1::EVP_PKEY_up_ref as *const ());
println!("{:?}", depends_mundane_v1::EVP_PKEY_assign_EC_KEY as *const ());
println!("{:?}", depends_mundane_v1::EVP_PKEY_get1_EC_KEY as *const ());
println!("{:?}", depends_mundane_v1::EVP_parse_public_key as *const ());
println!("{:?}", depends_mundane_v1::EVP_marshal_public_key as *const ());
println!("{:?}", depends_mundane_v1::PKCS5_PBKDF2_HMAC as *const ());
println!("{:?}", depends_mundane_v1::EVP_PBE_scrypt as *const ());
println!("{:?}", depends_mundane_v1::HMAC_CTX_init as *const ());
println!("{:?}", depends_mundane_v1::HMAC_CTX_cleanup as *const ());
println!("{:?}", depends_mundane_v1::HMAC_Init_ex as *const ());
println!("{:?}", depends_mundane_v1::HMAC_Update as *const ());
println!("{:?}", depends_mundane_v1::HMAC_Final as *const ());
println!("{:?}", depends_mundane_v1::HMAC_size as *const ());
println!("{:?}", depends_mundane_v1::CRYPTO_memcmp as *const ());
println!("{:?}", depends_mundane_v1::RAND_bytes as *const ());
println!("{:?}", depends_mundane_v1::SHA1_Init as *const ());
println!("{:?}", depends_mundane_v1::SHA1_Update as *const ());
println!("{:?}", depends_mundane_v1::SHA1_Final as *const ());
println!("{:?}", depends_mundane_v1::SHA256_Init as *const ());
println!("{:?}", depends_mundane_v1::SHA256_Update as *const ());
println!("{:?}", depends_mundane_v1::SHA256_Final as *const ());
println!("{:?}", depends_mundane_v1::SHA384_Init as *const ());
println!("{:?}", depends_mundane_v1::SHA384_Update as *const ());
println!("{:?}", depends_mundane_v1::SHA384_Final as *const ());
println!("{:?}", depends_mundane_v1::SHA512_Init as *const ());
println!("{:?}", depends_mundane_v1::SHA512_Update as *const ());
println!("{:?}", depends_mundane_v1::SHA512_Final as *const ());
println!("{:?}", depends_mundane_v2::ERR_print_errors_cb as *const ());
println!("{:?}", depends_mundane_v2::CBS_init as *const ());
println!("{:?}", depends_mundane_v2::CBS_len as *const ());
println!("{:?}", depends_mundane_v2::CBB_init as *const ());
println!("{:?}", depends_mundane_v2::CBB_cleanup as *const ());
println!("{:?}", depends_mundane_v2::CBB_data as *const ());
println!("{:?}", depends_mundane_v2::CBB_len as *const ());
println!("{:?}", depends_mundane_v2::ED25519_keypair as *const ());
println!("{:?}", depends_mundane_v2::ED25519_sign as *const ());
println!("{:?}", depends_mundane_v2::ED25519_verify as *const ());
println!("{:?}", depends_mundane_v2::ED25519_keypair_from_seed as *const ());
println!("{:?}", depends_mundane_v2::EVP_sha1 as *const ());
println!("{:?}", depends_mundane_v2::EVP_sha256 as *const ());
println!("{:?}", depends_mundane_v2::EVP_sha384 as *const ());
println!("{:?}", depends_mundane_v2::EVP_sha512 as *const ());
println!("{:?}", depends_mundane_v2::EC_GROUP_new_by_curve_name as *const ());
println!("{:?}", depends_mundane_v2::EC_GROUP_get_curve_name as *const ());
println!("{:?}", depends_mundane_v2::EC_curve_nid2nist as *const ());
println!("{:?}", depends_mundane_v2::EC_KEY_new as *const ());
println!("{:?}", depends_mundane_v2::EC_KEY_free as *const ());
println!("{:?}", depends_mundane_v2::EC_KEY_up_ref as *const ());
println!("{:?}", depends_mundane_v2::EC_KEY_get0_group as *const ());
println!("{:?}", depends_mundane_v2::EC_KEY_set_group as *const ());
println!("{:?}", depends_mundane_v2::EC_KEY_generate_key as *const ());
println!("{:?}", depends_mundane_v2::EC_KEY_parse_private_key as *const ());
println!("{:?}", depends_mundane_v2::EC_KEY_marshal_private_key as *const ());
println!("{:?}", depends_mundane_v2::ECDSA_sign as *const ());
println!("{:?}", depends_mundane_v2::ECDSA_verify as *const ());
println!("{:?}", depends_mundane_v2::ECDSA_size as *const ());
println!("{:?}", depends_mundane_v2::EVP_PKEY_new as *const ());
println!("{:?}", depends_mundane_v2::EVP_PKEY_free as *const ());
println!("{:?}", depends_mundane_v2::EVP_PKEY_up_ref as *const ());
println!("{:?}", depends_mundane_v2::EVP_PKEY_assign_EC_KEY as *const ());
println!("{:?}", depends_mundane_v2::EVP_PKEY_get1_EC_KEY as *const ());
println!("{:?}", depends_mundane_v2::EVP_parse_public_key as *const ());
println!("{:?}", depends_mundane_v2::EVP_marshal_public_key as *const ());
println!("{:?}", depends_mundane_v2::PKCS5_PBKDF2_HMAC as *const ());
println!("{:?}", depends_mundane_v2::EVP_PBE_scrypt as *const ());
println!("{:?}", depends_mundane_v2::HMAC_CTX_init as *const ());
println!("{:?}", depends_mundane_v2::HMAC_CTX_cleanup as *const ());
println!("{:?}", depends_mundane_v2::HMAC_Init_ex as *const ());
println!("{:?}", depends_mundane_v2::HMAC_Update as *const ());
println!("{:?}", depends_mundane_v2::HMAC_Final as *const ());
println!("{:?}", depends_mundane_v2::HMAC_size as *const ());
println!("{:?}", depends_mundane_v2::CRYPTO_memcmp as *const ());
println!("{:?}", depends_mundane_v2::RAND_bytes as *const ());
println!("{:?}", depends_mundane_v2::SHA1_Init as *const ());
println!("{:?}", depends_mundane_v2::SHA1_Update as *const ());
println!("{:?}", depends_mundane_v2::SHA1_Final as *const ());
println!("{:?}", depends_mundane_v2::SHA256_Init as *const ());
println!("{:?}", depends_mundane_v2::SHA256_Update as *const ());
println!("{:?}", depends_mundane_v2::SHA256_Final as *const ());
println!("{:?}", depends_mundane_v2::SHA384_Init as *const ());
println!("{:?}", depends_mundane_v2::SHA384_Update as *const ());
println!("{:?}", depends_mundane_v2::SHA384_Final as *const ());
println!("{:?}", depends_mundane_v2::SHA512_Init as *const ());
println!("{:?}", depends_mundane_v2::SHA512_Update as *const ());
println!("{:?}", depends_mundane_v2::SHA512_Final as *const ());
}
EOF

cargo build --release

cd -
rm -rf "$TMP"