// Copyright 2018 Google LLC
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

//! Almost-raw bindings to the BoringSSL API.
//!
//! The `raw` module provides bindings to the BoringSSL API which add a little
//! bit of safety beyond the safety provided by completely raw bindings by
//! ensuring that all return values are checked for errors, and converting these
//! C-style return values into Rust `Result`s.
//!
//! This module also directly re-exports any raw bindings which are infallible
//! (e.g., `void` functions).

// Infallible functions and the `size_t` type.
pub use boringssl::ffi::{
    size_t, CBB_cleanup, CBB_len, CBS_init, CBS_len, CRYPTO_memcmp, EC_GROUP_get_curve_name,
    ED25519_keypair, ED25519_keypair_from_seed, ERR_print_errors_cb, HMAC_CTX_init, HMAC_size,
    RC4_set_key, RSA_bits, RC4,
};

use std::convert::TryInto;
use std::num::NonZeroUsize;
use std::os::raw::{c_char, c_int, c_uint, c_void};
use std::ptr::{self, NonNull};

use boringssl::ffi::{
    self, BIGNUM, BN_GENCB, CBB, CBS, EC_GROUP, EC_KEY, EVP_MD, EVP_PKEY, HMAC_CTX, RSA, SHA512_CTX,
};

use boringssl::abort::UnwrapAbort;
use boringssl::wrapper::CInit;
use boringssl::BoringError;

macro_rules! impl_hash_context {
    ($ctx:ident, $update:ident, $final:ident) => {
        #[allow(non_snake_case)]
        pub unsafe fn $update(ctx: *mut ffi::$ctx, data: *const c_void, len: size_t) {
            // All XXX_Update functions promise to return 1.
            assert_abort_eq!(ffi::$update(ctx, data, len), 1);
        }
        #[allow(non_snake_case)]
        pub unsafe fn $final(md: *mut u8, ctx: *mut ffi::$ctx) -> Result<(), BoringError> {
            one_or_err(stringify!($final), ffi::$final(md, ctx))
        }
    };
}

// bn.h

// BIGNUMs can be either heap- or stack-allocated, and they keep track of which
// they are internally so that BN_free does the right thing - freeing the object
// itself if heap-allocated, and only freeing its internal state otherwise.
impl_traits!(BIGNUM, CInit => BN_init, CDestruct => BN_free);

#[allow(non_snake_case)]
#[must_use]
pub unsafe fn BN_set_u64(bn: *mut BIGNUM, value: u64) -> Result<(), BoringError> {
    one_or_err("BN_set_u64", ffi::BN_set_u64(bn, value))
}

// bytestring.h

impl_traits!(CBB, CDestruct => CBB_cleanup);
impl_traits!(CBS, CDestruct => _);

#[allow(non_snake_case)]
#[must_use]
pub unsafe fn CBB_init(cbb: *mut CBB, initial_capacity: size_t) -> Result<(), BoringError> {
    one_or_err("CBB_init", ffi::CBB_init(cbb, initial_capacity))
}

#[allow(non_snake_case)]
#[must_use]
pub unsafe fn CBB_data(cbb: *const CBB) -> Result<NonNull<u8>, BoringError> {
    ptr_or_err("CBB_init", ffi::CBB_data(cbb) as *mut _)
}

// curve25519.h

#[allow(non_snake_case)]
#[must_use]
pub unsafe fn ED25519_sign(
    out: *mut [u8; 64],
    message: *const u8,
    message_len: size_t,
    private_key: *const [u8; 64],
) -> Result<(), BoringError> {
    one_or_err(
        "ED25519_sign",
        ffi::ED25519_sign(out as *mut u8, message, message_len, private_key as *const u8),
    )
}

#[allow(non_snake_case)]
#[must_use]
pub unsafe fn ED25519_verify(
    message: *const u8,
    message_len: size_t,
    signature: *const [u8; 64],
    public_key: *const [u8; 32],
) -> bool {
    match ffi::ED25519_verify(message, message_len, signature as *const u8, public_key as *const u8)
    {
        0 => false,
        1 => true,
        // ED25519_verify promises to only return 0 or 1
        _ => unreachable_abort!(),
    }
}

// digest.h

macro_rules! evp_digest {
    ($name:ident) => {
        #[allow(non_snake_case)]
        #[must_use]
        pub unsafe fn $name() -> NonNull<EVP_MD> {
            // These return pointers to statically-allocated objects, so should
            // never fail.
            use boringssl::abort::UnwrapAbort;
            ptr_or_err(stringify!($name), ffi::$name() as *mut _).unwrap_abort()
        }
    };
}

evp_digest!(EVP_md5);
evp_digest!(EVP_sha1);
evp_digest!(EVP_sha256);
evp_digest!(EVP_sha384);
evp_digest!(EVP_sha512);

// ec.h

#[allow(non_snake_case)]
#[must_use]
pub unsafe fn EC_GROUP_new_by_curve_name(nid: c_int) -> Result<NonNull<EC_GROUP>, BoringError> {
    ptr_or_err("EC_GROUP_new_by_curve_name", ffi::EC_GROUP_new_by_curve_name(nid))
}

// ec_key.h

impl_traits!(EC_KEY, CNew => EC_KEY_new, CUpRef => EC_KEY_up_ref, CFree => EC_KEY_free);
impl_traits!(EVP_PKEY, CNew => EVP_PKEY_new, CUpRef => EVP_PKEY_up_ref, CFree => EVP_PKEY_free);

#[allow(non_snake_case)]
#[must_use]
pub unsafe fn EC_curve_nid2nist(nid: c_int) -> Result<NonNull<c_char>, BoringError> {
    ptr_or_err("EC_curve_nid2nist", ffi::EC_curve_nid2nist(nid) as *mut _)
}

#[allow(non_snake_case)]
#[must_use]
pub unsafe fn EC_KEY_generate_key(key: *mut EC_KEY) -> Result<(), BoringError> {
    one_or_err("EC_KEY_generate_key", ffi::EC_KEY_generate_key(key))
}

#[allow(non_snake_case)]
#[must_use]
pub unsafe fn EC_KEY_get0_group(key: *const EC_KEY) -> Result<NonNull<EC_GROUP>, BoringError> {
    ptr_or_err("EC_KEY_get0_group", ffi::EC_KEY_get0_group(key) as *mut _)
}

#[allow(non_snake_case)]
#[must_use]
pub unsafe fn EC_KEY_marshal_private_key(
    cbb: *mut CBB,
    key: *const EC_KEY,
    enc_flags: c_uint,
) -> Result<(), BoringError> {
    one_or_err("EC_KEY_marshal_private_key", ffi::EC_KEY_marshal_private_key(cbb, key, enc_flags))
}

#[allow(non_snake_case)]
#[must_use]
pub unsafe fn EC_KEY_parse_private_key(
    cbs: *mut CBS,
    group: *const EC_GROUP,
) -> Result<NonNull<EC_KEY>, BoringError> {
    ptr_or_err("EC_KEY_parse_private_key", ffi::EC_KEY_parse_private_key(cbs, group))
}

#[allow(non_snake_case)]
#[must_use]
pub unsafe fn EC_KEY_set_group(
    key: *mut EC_KEY,
    group: *const EC_GROUP,
) -> Result<(), BoringError> {
    one_or_err("EC_KEY_set_group", ffi::EC_KEY_set_group(key, group))
}

// ecdsa.h

#[allow(non_snake_case)]
#[must_use]
pub unsafe fn ECDSA_sign(
    type_: c_int,
    digest: *const u8,
    digest_len: size_t,
    sig: *mut u8,
    sig_len: *mut c_uint,
    key: *const EC_KEY,
) -> Result<(), BoringError> {
    one_or_err("ECDSA_sign", ffi::ECDSA_sign(type_, digest, digest_len, sig, sig_len, key))
}

#[allow(non_snake_case)]
#[must_use]
pub unsafe fn ECDSA_size(key: *const EC_KEY) -> Result<NonZeroUsize, BoringError> {
    NonZeroUsize::new(ffi::ECDSA_size(key).into_usize())
        .ok_or_else(|| BoringError::consume_stack("ECDSA_size"))
}

#[allow(non_snake_case)]
#[must_use]
pub unsafe fn ECDSA_verify(
    type_: c_int,
    digest: *const u8,
    digest_len: size_t,
    sig: *const u8,
    sig_len: size_t,
    key: *const EC_KEY,
) -> bool {
    match ffi::ECDSA_verify(type_, digest, digest_len, sig, sig_len, key) {
        1 => true,
        0 => false,
        // ECDSA_verify promises to only return 0 or 1
        _ => unreachable_abort!(),
    }
}

// evp.h

#[allow(non_snake_case)]
#[must_use]
pub unsafe fn EVP_marshal_public_key(
    cbb: *mut CBB,
    key: *const EVP_PKEY,
) -> Result<(), BoringError> {
    one_or_err("EVP_marshal_public_key", ffi::EVP_marshal_public_key(cbb, key))
}

#[allow(non_snake_case)]
#[must_use]
pub unsafe fn EVP_parse_public_key(cbs: *mut CBS) -> Result<NonNull<EVP_PKEY>, BoringError> {
    ptr_or_err("EVP_parse_public_key", ffi::EVP_parse_public_key(cbs))
}

#[allow(non_snake_case)]
#[must_use]
pub unsafe fn EVP_PKEY_assign_EC_KEY(
    pkey: *mut EVP_PKEY,
    key: *mut EC_KEY,
) -> Result<(), BoringError> {
    one_or_err("EVP_PKEY_assign_EC_KEY", ffi::EVP_PKEY_assign_EC_KEY(pkey, key))
}

#[allow(non_snake_case)]
#[must_use]
pub unsafe fn EVP_PKEY_assign_RSA(pkey: *mut EVP_PKEY, key: *mut RSA) -> Result<(), BoringError> {
    one_or_err("EVP_PKEY_assign_RSA", ffi::EVP_PKEY_assign_RSA(pkey, key))
}

#[allow(non_snake_case)]
#[must_use]
pub unsafe fn EVP_PKEY_get1_EC_KEY(pkey: *mut EVP_PKEY) -> Result<NonNull<EC_KEY>, BoringError> {
    ptr_or_err("EVP_PKEY_get1_EC_KEY", ffi::EVP_PKEY_get1_EC_KEY(pkey))
}

#[allow(non_snake_case)]
#[must_use]
pub unsafe fn EVP_PKEY_get1_RSA(pkey: *mut EVP_PKEY) -> Result<NonNull<RSA>, BoringError> {
    ptr_or_err("EVP_PKEY_get1_RSA", ffi::EVP_PKEY_get1_RSA(pkey))
}

#[allow(non_snake_case)]
#[allow(clippy::too_many_arguments)]
#[must_use]
pub unsafe fn EVP_PBE_scrypt(
    password: *const c_char,
    password_len: size_t,
    salt: *const u8,
    salt_len: size_t,
    N: u64,
    r: u64,
    p: u64,
    max_mem: size_t,
    out_key: *mut u8,
    key_len: size_t,
) -> Result<(), BoringError> {
    one_or_err(
        "EVP_PBE_scrypt",
        ffi::EVP_PBE_scrypt(
            password,
            password_len,
            salt,
            salt_len,
            N,
            r,
            p,
            max_mem,
            out_key,
            key_len,
        ),
    )
}

#[cfg(feature = "kdf")]
#[allow(non_snake_case)]
#[allow(clippy::too_many_arguments)]
#[must_use]
pub unsafe fn PKCS5_PBKDF2_HMAC(
    password: *const c_char,
    password_len: size_t,
    salt: *const u8,
    salt_len: size_t,
    iterations: c_uint,
    digest: *const EVP_MD,
    key_len: size_t,
    out_key: *mut u8,
) -> Result<(), BoringError> {
    one_or_err(
        "PKCS5_PBKDF2_HMAC",
        ffi::PKCS5_PBKDF2_HMAC(
            password,
            password_len,
            salt,
            salt_len,
            iterations,
            digest,
            key_len,
            out_key,
        ),
    )
}

// hmac.h

// NOTE: We don't implement CInit because some functions that take an HMAC_CTX
// pointer have extra invariants beyond simply having called HMAC_CTX_init. If
// we implemented CInit, then safe code would be able to construct a
// CStackWrapper<HMAC_CTX> using Default::default, and then pass a pointer to
// that object to functions that require extra initialization, leading to
// usoundness.
impl_traits!(HMAC_CTX, CDestruct => HMAC_CTX_cleanup);

#[allow(non_snake_case)]
#[must_use]
pub unsafe fn HMAC_Init_ex(
    ctx: *mut HMAC_CTX,
    key: *const c_void,
    key_len: size_t,
    md: *const EVP_MD,
) -> Result<(), BoringError> {
    one_or_err("HMAC_Init_ex", ffi::HMAC_Init_ex(ctx, key, key_len, md, ptr::null_mut()))
}

#[allow(non_snake_case)]
pub unsafe fn HMAC_Update(ctx: *mut HMAC_CTX, data: *const u8, data_len: size_t) {
    // HMAC_Update promises to return 1.
    assert_abort_eq!(ffi::HMAC_Update(ctx, data, data_len), 1);
}

#[allow(non_snake_case)]
#[must_use]
pub unsafe fn HMAC_Final(
    ctx: *mut HMAC_CTX,
    out: *mut u8,
    out_len: *mut c_uint,
) -> Result<(), BoringError> {
    one_or_err("HMAC_Final", ffi::HMAC_Final(ctx, out, out_len))
}

#[allow(non_snake_case)]
pub unsafe fn HMAC_CTX_copy(dest: *mut HMAC_CTX, src: *const HMAC_CTX) -> Result<(), BoringError> {
    one_or_err("HMAC_CTX_copy", ffi::HMAC_CTX_copy(dest, src))
}

// rand.h

#[allow(non_snake_case)]
pub unsafe fn RAND_bytes(buf: *mut u8, len: size_t) {
    // RAND_bytes promises to return 1.
    assert_abort_eq!(ffi::RAND_bytes(buf, len), 1);
}

// rsa.h

impl_traits!(RSA, CNew => RSA_new, CUpRef => RSA_up_ref, CFree => RSA_free);

#[allow(non_snake_case)]
#[must_use]
pub unsafe fn RSA_generate_key_ex(
    rsa: *mut RSA,
    bits: c_int,
    e: *const BIGNUM,
    cb: *mut BN_GENCB,
) -> Result<(), BoringError> {
    one_or_err("RSA_generate_key_ex", ffi::RSA_generate_key_ex(rsa, bits, e, cb))
}

#[allow(non_snake_case)]
#[must_use]
pub unsafe fn RSA_marshal_private_key(cbb: *mut CBB, rsa: *const RSA) -> Result<(), BoringError> {
    one_or_err("RSA_marshal_private_key", ffi::RSA_marshal_private_key(cbb, rsa))
}

#[allow(non_snake_case)]
#[must_use]
pub unsafe fn RSA_parse_private_key(cbs: *mut CBS) -> Result<NonNull<RSA>, BoringError> {
    ptr_or_err("RSA_parse_private_key", ffi::RSA_parse_private_key(cbs))
}

#[cfg(feature = "rsa-pkcs1v15")]
#[allow(non_snake_case)]
#[must_use]
pub unsafe fn RSA_sign(
    hash_nid: c_int,
    in_: *const u8,
    in_len: c_uint,
    out: *mut u8,
    out_len: *mut c_uint,
    key: *mut RSA,
) -> Result<(), BoringError> {
    one_or_err("RSA_sign", ffi::RSA_sign(hash_nid, in_, in_len, out, out_len, key))
}

#[allow(non_snake_case)]
#[must_use]
pub unsafe fn RSA_sign_pss_mgf1(
    rsa: *mut RSA,
    out_len: *mut size_t,
    out: *mut u8,
    max_out: size_t,
    in_: *const u8,
    in_len: size_t,
    md: *const EVP_MD,
    mgf1_md: *const EVP_MD,
    salt_len: c_int,
) -> Result<(), BoringError> {
    one_or_err(
        "RSA_sign_pss_mgf1",
        ffi::RSA_sign_pss_mgf1(rsa, out_len, out, max_out, in_, in_len, md, mgf1_md, salt_len),
    )
}

#[allow(non_snake_case)]
#[must_use]
pub unsafe fn RSA_size(key: *const RSA) -> Result<NonZeroUsize, BoringError> {
    NonZeroUsize::new(ffi::RSA_size(key).try_into().unwrap_abort())
        .ok_or_else(|| BoringError::consume_stack("RSA_size"))
}

#[cfg(feature = "rsa-pkcs1v15")]
#[allow(non_snake_case)]
#[must_use]
pub unsafe fn RSA_verify(
    hash_nid: c_int,
    msg: *const u8,
    msg_len: size_t,
    sig: *const u8,
    sig_len: size_t,
    rsa: *mut RSA,
) -> bool {
    match ffi::RSA_verify(hash_nid, msg, msg_len, sig, sig_len, rsa) {
        0 => false,
        1 => true,
        // RSA_verify promises to only return 0 or 1
        _ => unreachable_abort!(),
    }
}

#[allow(non_snake_case)]
#[must_use]
pub unsafe fn RSA_verify_pss_mgf1(
    rsa: *mut RSA,
    msg: *const u8,
    msg_len: size_t,
    md: *const EVP_MD,
    mgf1_md: *const EVP_MD,
    salt_len: c_int,
    sig: *const u8,
    sig_len: size_t,
) -> bool {
    match ffi::RSA_verify_pss_mgf1(rsa, msg, msg_len, md, mgf1_md, salt_len, sig, sig_len) {
        0 => false,
        1 => true,
        // RSA_verify_pss_mgf1 promises to only return 0 or 1
        _ => unreachable_abort!(),
    }
}

// rc4.h

impl_traits!(RC4_KEY, CDestruct => _);

// md5.h and sha.h

unsafe impl CInit for ffi::MD5_CTX {
    unsafe fn init(ctx: *mut Self) {
        // MD5_Init promises to return 1.
        assert_abort_eq!(ffi::MD5_Init(ctx), 1);
    }
}

#[allow(non_snake_case)]
pub unsafe fn SHA384_Init(ctx: *mut SHA512_CTX) {
    // SHA384_Init promises to return 1.
    assert_abort_eq!(ffi::SHA384_Init(ctx), 1);
}

// Implemented manually (rather than via impl_traits! or c_init!) so that we can
// assert_abort_eq! that the return value is 1.
unsafe impl CInit for ffi::SHA_CTX {
    unsafe fn init(ctx: *mut Self) {
        // SHA1_Init promises to return 1.
        assert_abort_eq!(ffi::SHA1_Init(ctx), 1);
    }
}
unsafe impl CInit for ffi::SHA256_CTX {
    unsafe fn init(ctx: *mut Self) {
        // SHA256_Init promises to return 1.
        assert_abort_eq!(ffi::SHA256_Init(ctx), 1);
    }
}
unsafe impl CInit for ffi::SHA512_CTX {
    unsafe fn init(ctx: *mut Self) {
        // SHA512_Init promises to return 1.
        assert_abort_eq!(ffi::SHA512_Init(ctx), 1);
    }
}

// implement no-op destructors
impl_traits!(MD5_CTX, CDestruct => _);
impl_traits!(SHA_CTX, CDestruct => _);
impl_traits!(SHA256_CTX, CDestruct => _);
impl_traits!(SHA512_CTX, CDestruct => _);

impl_hash_context!(MD5_CTX, MD5_Update, MD5_Final);
impl_hash_context!(SHA_CTX, SHA1_Update, SHA1_Final);
impl_hash_context!(SHA256_CTX, SHA256_Update, SHA256_Final);
impl_hash_context!(SHA512_CTX, SHA384_Update, SHA384_Final);
impl_hash_context!(SHA512_CTX, SHA512_Update, SHA512_Final);

// utility functions

// If code is 1, returns Ok, otherwise returns Err. f should be the name of the
// function that returned this value.
#[must_use]
pub fn one_or_err<S: TryInto<size_t>>(f: &str, code: S) -> Result<(), BoringError> {
    // If the conversion failed, then the value is definitely not 1 since 1 is
    // representable in `size_t`. Thus, in that case, we assume there was an
    // error.
    if code.try_into().map(|code| code == 1).unwrap_or(false) {
        Ok(())
    } else {
        Err(BoringError::consume_stack(f))
    }
}

// If ptr is non-NULL, returns Ok, otherwise returns Err. f should be the name
// of the function that returned this value.
fn ptr_or_err<T>(f: &str, ptr: *mut T) -> Result<NonNull<T>, BoringError> {
    NonNull::new(ptr).ok_or_else(|| BoringError::consume_stack(f))
}

/// Convert from the `usize` type into the `size_t` type.
///
/// Bindgen generates its own `size_t` Rust type to act as the equivalent of the
/// `size_t` C type. On all current platforms, this is an unsigned integer of
/// the same size as the platform word size (e.g., `u64` on 64-bit platforms).
/// On those platforms, `usize` and `size_t` are, in practice, interchangeable,
/// though the type system doesn't know it. This trait exists to convert between
/// them, and also to ensure that compilation fails if they are not
/// interchangeable on a particular platform.
pub trait IntoSizeT {
    fn into_size_t(self) -> size_t;
}

/// Convert from the `size_t` type into the `usize` type.
pub trait IntoUsize {
    fn into_usize(self) -> usize;
}

#[cfg(target_pointer_width = "64")]
impl IntoSizeT for usize {
    fn into_size_t(self) -> size_t {
        // This is an infallible conversion since we're on a 64-bit platform.
        let x = self as u64;
        // This line will stop compiling if `size_t` is no longer an alias for
        // `u64`.
        x
    }
}

#[cfg(target_pointer_width = "64")]
impl IntoUsize for size_t {
    fn into_usize(self) -> usize {
        // This line will stop compiling if `size_t` is no longer an alias for
        // `u64`.
        let x: u64 = self;
        // This is an infallible conversion since we're on a 64-bit platform.
        x as usize
    }
}

#[cfg(target_pointer_width = "32")]
impl IntoSizeT for usize {
    fn into_size_t(self) -> size_t {
        // This is an infallible conversion since we're on a 32-bit platform.
        let x = self as u32;
        // This line will stop compiling if `size_t` is no longer an alias for
        // `u32`.
        x
    }
}

#[cfg(target_pointer_width = "32")]
impl IntoUsize for size_t {
    fn into_usize(self) -> usize {
        // This line will stop compiling if `size_t` is no longer an alias for
        // `u32`.
        let x: u32 = self;
        // This is an infallible conversion since we're on a 32-bit platform.
        x as usize
    }
}
