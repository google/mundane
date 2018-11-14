// Copyright 2018 Google LLC
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

//! Password verification.

/// The scrypt password hashing function.
///
/// scrypt was originally proposed in [Stronger Key Derivation via Sequential
/// Memory-Hard Functions] and standardized in [RFC 7914].
///
/// A note on terminology: scrypt is technically a key derivation function, and
/// its output is thus technically a key. However, we expose it here only for
/// the purposes of password verification, and thus we use the term "hash" to
/// refer to its output.
///
/// [Stronger Key Derivation via Sequential Memory-Hard Functions]: https://www.tarsnap.com/scrypt/scrypt.pdf
/// [RFC 7914]: https://tools.ietf.org/html/rfc7914
pub mod scrypt {
    use boringssl;

    // NOTE(joshlf): These are both set to 32 bytes (256 bits). This is probably
    // overkill (128 bits is probably fine, as the lack of entropy in password
    // hashes usually comes primarily from the passwords themselves), but better
    // safe than sorry. Note that this is consistent with the Go scrypt
    // documentation examples (https://godoc.org/golang.org/x/crypto/scrypt),
    // while Go's bcrypt implementation
    // (https://godoc.org/golang.org/x/crypto/bcrypt) uses a 128-bit salt and a
    // 192-bit hash.

    /// The length of an scrypt hash.
    ///
    /// The value of this constant - 32 - is considered part of this API. Any
    /// changes to it will be considered breaking changes.
    pub const SCRYPT_HASH_LEN: usize = 32;
    /// The length of an scrypt salt.
    ///
    /// The value of this constant - 32 - is considered part of this API. Any
    /// changes to it will be considered breaking changes.
    pub const SCRYPT_SALT_LEN: usize = 32;

    /// Recommended parameters for a production server.
    ///
    /// `SCRYPT_PARAMS_SERVER` is an appropriate set of parameters for running
    /// scrypt on a production server in 2018. It targets 100ms of execution
    /// time per generation or verification.
    ///
    /// The value of this constant may be updated periodically in order to keep
    /// up with hardware trends.
    pub const SCRYPT_PARAMS_SERVER: ScryptParams = ScryptParams {
        // NOTE(joshlf): These were taken from the Go scrypt implementation
        // (https://godoc.org/golang.org/x/crypto/scrypt) on 08/14/2018.
        N: 32768,
        r: 8,
        p: 1,
    };

    /// Recommended paramaters for a laptop.
    ///
    /// `SCRYPT_PARAMS_LAPTOP` is an appropriate set of parameters for running
    /// scrypt on a medium-range laptop in 2018. It targets 100ms of execution
    /// time per generation or verification.
    ///
    /// The value of this constant may be updated periodically in order to keep
    /// up with hardware trends.
    pub const SCRYPT_PARAMS_LAPTOP: ScryptParams = ScryptParams {
        // NOTE(joshlf): These were benchmarked on my laptop (2017 MacBook Pro
        // 13-inch with a 3.5 GHz Intel Core i7 - model identifier
        // MacBookPro14,2) on 08/14/2018.
        N: 16384,
        r: 8,
        p: 1,
    };

    /// The parameters to the scrypt function.
    ///
    /// These parameters determine how much effort will be required in order to
    /// generate or verify an scrypt hash. "Effort" here refers to utilization
    /// of of CPU, memory, and memory bandwidth. For more details on what these
    /// parameters mean and their implications, see [The scrypt Parameters]. For
    /// sane defaults, see the `SCRYPT_PARAMS_XXX` constants.
    ///
    /// [The scrypt Parameters]: https://blog.filippo.io/the-scrypt-parameters/
    #[allow(non_snake_case)]
    #[allow(missing_docs)]
    #[derive(Debug, Copy, Clone)]
    pub struct ScryptParams {
        // NOTE(joshlf): These are private so that the user is forced to use one
        // of our presets. If this turns out to be too brittle, it might be
        // worth considering making these public, and simply discouraging
        // (perhaps via a deprecation attribute) setting them directly.
        N: u64,
        r: u64,
        p: u64,
    }

    impl ScryptParams {
        /// Gets the parameter N.
        #[allow(non_snake_case)]
        #[must_use]
        pub fn N(&self) -> u64 {
            self.N
        }

        /// Gets the parameter r.
        #[must_use]
        pub fn r(&self) -> u64 {
            self.r
        }

        /// Gets the parameter p.
        #[must_use]
        pub fn p(&self) -> u64 {
            self.p
        }
    }

    // Don't put a limit on the memory used by scrypt; it's too prone to
    // failure. Instead, rely on choosing sane defaults for N, r, and p to
    // ensure that we don't use too much memory.
    const SCRYPT_MAX_MEM: usize = usize::max_value();

    // TODO(joshlf): Provide a custom Debug impl for ScryptHash?

    /// The output of the scrypt password hashing function.
    #[must_use]
    #[allow(non_snake_case)]
    #[derive(Debug, Copy, Clone)]
    pub struct ScryptHash {
        hash: [u8; SCRYPT_HASH_LEN],
        salt: [u8; SCRYPT_SALT_LEN],
        params: ScryptParams,
    }

    impl ScryptHash {
        // NOTE(joshlf): Normally, having three different parameters in a row of
        // the same type would be dangerous because it's too easy to
        // accidentally pass arguments in the wrong order. In this particular
        // case, it's less of a concern because ScryptHash is only passed to the
        // scrypt_verify function, so the worst that reordering these parameters
        // can due is cause a valid hash to be mistakenly rejected as invalid.
        // If this were a constructor on ScryptParams, which is passed as an
        // argument to scrypt_generate, then a mistake might lead to
        // accidentally generating a hash with weak security parameters, which
        // would be a problem.

        /// Constructs a new `ScryptHash`.
        #[allow(non_snake_case)]
        #[must_use]
        pub fn new(
            hash: [u8; SCRYPT_HASH_LEN],
            salt: [u8; SCRYPT_SALT_LEN],
            N: u64,
            r: u64,
            p: u64,
        ) -> ScryptHash {
            ScryptHash {
                hash,
                salt,
                params: ScryptParams { N, r, p },
            }
        }

        /// Gets the hash.
        #[must_use]
        pub fn hash(&self) -> &[u8; SCRYPT_HASH_LEN] {
            &self.hash
        }

        /// Gets the salt.
        #[must_use]
        pub fn salt(&self) -> &[u8; SCRYPT_SALT_LEN] {
            &self.salt
        }

        /// Gets the params.
        #[must_use]
        pub fn params(&self) -> ScryptParams {
            self.params
        }
    }

    /// Generates an scrypt hash for the given password.
    ///
    /// `scrypt_generate` uses scrypt to generate a hash for the given
    /// `password` using the provided `params`.
    #[must_use]
    pub fn scrypt_generate(password: &[u8], params: &ScryptParams) -> ScryptHash {
        let mut salt = [0u8; SCRYPT_SALT_LEN];
        boringssl::rand_bytes(&mut salt);
        let mut hash = [0u8; SCRYPT_HASH_LEN];
        // Can only fail on OOM, max_mem exceeded (SCRYPT_MAX_MEM is max usize,
        // so that definitely won't happen), or if any of the parameters are
        // invalid (which would be a bug on our part). Thus, we unwrap.
        boringssl::evp_pbe_scrypt(
            password,
            &salt,
            params.N,
            params.r,
            params.p,
            SCRYPT_MAX_MEM,
            &mut hash,
        )
        .unwrap();
        ScryptHash {
            hash,
            salt,
            params: *params,
        }
    }

    /// Verifies a password against an scrypt hash.
    ///
    /// `scrypt_verify` verifies that `password` is the same password that was
    /// used to generate `hash` using scrypt.
    #[must_use]
    pub fn scrypt_verify(password: &[u8], hash: &ScryptHash) -> bool {
        let mut out_hash = [0u8; SCRYPT_HASH_LEN];
        if boringssl::evp_pbe_scrypt(
            password,
            &hash.salt,
            hash.params.N,
            hash.params.r,
            hash.params.p,
            SCRYPT_MAX_MEM,
            &mut out_hash,
        )
        .is_err()
        {
            return false;
        }
        boringssl::crypto_memcmp(&out_hash, &hash.hash)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_scrypt() {
            for _ in 0..16 {
                let mut pass = [0; 128];
                boringssl::rand_bytes(&mut pass);
                // target 1 second of execution for this test on a laptop
                let mut params = SCRYPT_PARAMS_LAPTOP;
                params.N /= 4;
                let hash = scrypt_generate(&pass, &params);
                assert!(
                    scrypt_verify(&pass, &hash),
                    "pass: {:?}, hash: {:?}",
                    &pass[..],
                    hash
                );
            }
        }
    }
}
