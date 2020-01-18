//! Byte manipulation.
//!
//! *This module is available if Mundane is built with the `bytes` feature.*

use boringssl;

/// Reads cryptographically-secure random bytes.
///
/// This is a low-level primitive often used to construct higher-level
/// protocols. Unless you're sure that this is what you need, you should
/// probably be using something else. For example, all key types can be randomly
/// generated using higher-level functions (e.g., [`EcPrivKey::generate`]),
/// scrypt nonces are generated using the [`scrypt_generate`] function, etc.
///
/// [`EcPrivKey::generate`]: ::public::ec::EcPrivKey::generate
/// [`scrypt_generate`]: ::password::scrypt::scrypt_generate
pub fn rand(bytes: &mut [u8]) {
    boringssl::rand_bytes(bytes);
}

/// Constant-time byte sequence equality.
///
/// Returns true iff the bytes at `a` and `b` are equal. Takes an
/// amount of time dependent on length, but independent of individual
/// byte values.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    boringssl::crypto_memcmp(a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_sanity() {
        assert!(constant_time_eq(&[], &[]));
        assert!(!constant_time_eq(&[], &[0]));
        assert!(constant_time_eq(&[0, 1], &[0, 1]));
        assert!(!constant_time_eq(&[0, 1], &[0, 2]));
    }
}
