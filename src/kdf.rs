// Copyright 2018 Google LLC
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

//! Key Derivation Functions (KDFs).
//!
//! KDFs are low-level primitives often used to construct higher-level
//! protocols. Unless you're sure that this is what you need, you should
//! probably be using something else. In particular:
//! - If you need password verification, see the [`password`] module.
//!
//! [`password`]: ::password

use std::num::NonZeroU32;

use boringssl;
use hash::Hasher;

/// The PBKDF2 Key Derivation Function.
///
/// `pbkdf2` computes `iter` iterations of PBKDF2 of `password` and `salt`,
/// using an HMAC based on the hash function `H`. It stores the result in
/// `out_key`. Note that PBKDF2 can produce variable-length output, so it will
/// always fill the entirety of `out_key` regardless of its length.
///
/// PBKDF2 is defined in RSA Security LLC's Public Key Cryptography Standards #5
/// (PKCS #5) v2.0. For details, see [RFC 2898 Section 5.2].
///
/// # Security
///
/// While PBKDF2 can produce any amount of key output, the entropy of its output
/// is bounded by the internal state. Be careful that the output key has enough
/// entropy for your needs. See [RFC 2898 Appendix B.1] for a discussion on
/// calculating the effective entropy of PBKDF2. Also remember that new attacks
/// are sometimes discovered, and it is your responsibility to keep up with the
/// latest attacks; RFC 2898's analysis may not be valid forever!
///
/// [RFC 2898 Section 5.2]: https://tools.ietf.org/html/rfc2898#section-5.2
/// [RFC 2898 Appendix B.1]: https://tools.ietf.org/html/rfc2898#appendix-B.1
pub fn pbkdf2<H: Hasher>(password: &[u8], salt: &[u8], iters: NonZeroU32, out_key: &mut [u8]) {
    // PKCS5_PBKDF2_HMAC can only fail on OOM or if iters is 0.
    boringssl::pkcs5_pbkdf2_hmac(password, salt, iters.get(), &H::evp_md(), out_key).unwrap();
}

#[cfg(feature = "insecure")]
pub(crate) mod insecure_pbkdf2_hmac_sha1 {
    use std::num::NonZeroU32;

    #[allow(deprecated)]
    use hash::InsecureSha1;
    use kdf::pbkdf2;

    /// INSECURE: The PBKDF2 Key Derivation Function over HMAC-SHA1.
    ///
    /// # Security
    ///
    /// PBKDF2-HMAC-SHA1 is considered insecure, and should only be used for
    /// compatibility with legacy applications.
    ///
    /// # Behavior
    ///
    /// `pbkdf2_hmac_sha1` computes `iter` iterations of PBKDF2-HMAC-SHA1 of
    /// `password` and `salt`. It stores the result in `out_key`.
    ///
    /// PBKDF2 is defined in RSA Security LLC's Public Key Cryptography
    /// Standards #5 (PKCS #5) v2.0. For details, see [RFC 2898 Section 5.2].
    ///
    /// # Further Security Considerations
    ///
    /// While PBKDF2 can produce any amount of key output, the entropy of its
    /// output is bounded by the internal state. Be careful that the output key
    /// has enough entropy for your needs. See [RFC 2898 Appendix B.1] for a
    /// discussion on calculating the effective entropy of PBKDF2, but keep in
    /// mind that SHA-1's insecurities may affect this analysis! Also remember
    /// that new attacks are sometimes discovered, and it is your responsibility
    /// to keep up with the latest attacks; RFC 2898's analysis may not be valid
    /// forever!
    ///
    /// [RFC 2898 Section 5.2]: https://tools.ietf.org/html/rfc2898#section-5.2
    /// [RFC 2898 Appendix B.1]: https://tools.ietf.org/html/rfc2898#appendix-B.1
    #[deprecated(note = "PBKDF2-HMAC-SHA1 is considered insecure")]
    pub fn insecure_pbkdf2_hmac_sha1(
        password: &[u8], salt: &[u8], iters: NonZeroU32, out_key: &mut [u8],
    ) {
        #[allow(deprecated)]
        pbkdf2::<InsecureSha1>(password, salt, iters, out_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hash::*;

    #[test]
    fn test_smoke() {
        for password_len in 0..8 {
            for salt_len in 0..8 {
                for iters in 1..8 {
                    for out_key_len in 0..8 {
                        fn test<H: Hasher>(
                            password_len: usize, salt_len: usize, iters: u32, out_key_len: usize,
                        ) {
                            let password = [0, 1, 2, 3, 4, 5, 6, 7];
                            let salt = [0, 1, 2, 3, 4, 5, 6, 7];
                            let mut out_key_0 = [0; 8];
                            let mut out_key_1 = [0; 8];

                            pbkdf2::<H>(
                                &password[..password_len],
                                &salt[..salt_len],
                                NonZeroU32::new(iters).unwrap(),
                                &mut out_key_0[..out_key_len],
                            );
                            pbkdf2::<H>(
                                &password[..password_len],
                                &salt[..salt_len],
                                NonZeroU32::new(iters).unwrap(),
                                &mut out_key_1[..out_key_len],
                            );
                            assert_eq!(&out_key_0[..out_key_len], &out_key_1[..out_key_len]);
                        }

                        test::<Sha256>(password_len, salt_len, iters, out_key_len);
                        test::<Sha384>(password_len, salt_len, iters, out_key_len);
                        test::<Sha512>(password_len, salt_len, iters, out_key_len);
                    }
                }
            }
        }
    }
}
