// Copyright 2018 Google LLC
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

//! WARNING: INSECURE CRYPTOGRAPHIC OPERATIONS.
//!
//! This module contains cryptographic operations which are considered insecure.
//! These operations should only be used for compatibility with legacy systems -
//! never in new systems!
//!
//! *This module is available if Mundane is built with the `insecure` feature.*

#![deprecated(note = "insecure cryptographic operations")]

#[allow(deprecated)]
#[cfg(feature = "insecure")]
pub use hash::insecure_md5_digest::InsecureMd5Digest;
#[allow(deprecated)]
#[cfg(feature = "insecure")]
pub use hash::insecure_sha1_digest::InsecureSha1Digest;

#[allow(deprecated)]
#[cfg(feature = "insecure")]
pub use hmac::insecure_hmac::{InsecureHmacMd5, InsecureHmacSha1};

#[allow(deprecated)]
#[cfg(all(feature = "kdf", feature = "insecure"))]
pub use kdf::insecure_pbkdf2_hmac_sha1::insecure_pbkdf2_hmac_sha1;

#[allow(deprecated)]
#[cfg(feature = "insecure")]
pub use insecure_rc4::InsecureRc4Key;
