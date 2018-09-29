#!/bin/bash

# Copyright 2018 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

set -e

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

# TODO(joshlf):
# - Use the --use-core flag once std isn't required (see
#   https://github.com/rust-lang-nursery/rust-bindgen/issues/1015)

# Only include the symbols we want. It's important that we take the minimum
# dependency on BoringSSL so that we provide the minimum burden for them. The
# more symbols we depend on, the more likely it is that a change that they want
# to make will affect us, which they will care about, making them either expend
# effort in a graceful transition or decide to abandon the change. Thus, instead
# of whitelisting broad classes of symbols, we explicitly whitelist the exact
# list of symbols that Mundane depends on.
WHITELIST="(CBB|\
CBB_cleanup|\
CBB_data|\
CBB_init|\
CBB_len|\
CBS|\
CBS_init|\
CBS_len|\
CRYPTO_memcmp|\
ECDSA_sign|\
ECDSA_size|\
ECDSA_verify|\
EC_GROUP|\
EC_GROUP_get_curve_name|\
EC_GROUP_new_by_curve_name|\
EC_KEY|\
EC_KEY_free|\
EC_KEY_generate_key|\
EC_KEY_get0_group|\
EC_KEY_marshal_private_key|\
EC_KEY_new|\
EC_KEY_parse_private_key|\
EC_KEY_set_group|\
EC_KEY_up_ref|\
EC_curve_nid2nist|\
ED25519_PRIVATE_KEY_LEN|\
ED25519_PUBLIC_KEY_LEN|\
ED25519_SIGNATURE_LEN|\
ED25519_keypair|\
ED25519_keypair_from_seed|\
ED25519_sign|\
ED25519_verify|\
ERR_print_errors_cb|\
EVP_MD|\
EVP_PBE_scrypt|\
EVP_PKEY|\
EVP_PKEY_assign_EC_KEY|\
EVP_PKEY_free|\
EVP_PKEY_get1_EC_KEY|\
EVP_PKEY_new|\
EVP_PKEY_up_ref|\
EVP_marshal_public_key|\
EVP_parse_public_key|\
EVP_sha1|\
EVP_sha256|\
EVP_sha384|\
EVP_sha512|\
HMAC_CTX|\
HMAC_CTX_cleanup|\
HMAC_CTX_init|\
HMAC_Final|\
HMAC_Init_ex|\
HMAC_Update|\
HMAC_size|\
NID_X9_62_prime256v1|\
NID_secp384r1|\
NID_secp521r1|\
RAND_bytes|\
PKCS5_PBKDF2_HMAC|\
SHA_CTX|\
SHA_DIGEST_LENGTH|\
SHA1_Final|\
SHA1_Init|\
SHA1_Update|\
SHA256_CTX|\
SHA256_DIGEST_LENGTH|\
SHA256_Final|\
SHA256_Init|\
SHA256_Update|\
SHA512_CTX|\
SHA384_DIGEST_LENGTH|\
SHA384_Final|\
SHA384_Init|\
SHA384_Update|\
SHA512_CTX|\
SHA512_DIGEST_LENGTH|\
SHA512_Final|\
SHA512_Init|\
SHA512_Update)"

# NOTE(joshlf): Currently, we don't pass --target since none of the symbols
# we're linking against are architecture-specific (TODO: are any of them
# word-size-specific?). If this ever becomes a problem, then the thing to do is
# probably to generate different files for different platforms
# (boringssl_x86_64.rs, boringssl_arm64.rs, etc) and conditionally compile them
# depending on target.
bindgen bindgen.h --whitelist-function "$WHITELIST" --whitelist-type "$WHITELIST" \
    --whitelist-var "$WHITELIST" -o boringssl.rs -- -I ./boringssl/include

TMP="$(mktemp)"

# Prepend copyright comment, #[allow] for various warnings we don't care about,
# and a line telling Rust to link against libcrypto.
cat >> "$TMP" <<'EOF'
// Copyright 2018 Google LLC
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

#[link(name = "crypto_${MAJOR}_${MINOR}_${PATCH}")] extern {}

EOF
cat boringssl.rs >> "$TMP"

mv "$TMP" boringssl.rs
rustfmt boringssl.rs
