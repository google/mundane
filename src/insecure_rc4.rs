#![cfg(feature = "insecure")]

use boringssl::{self, CStackWrapper};

/// INSECURE: The RC4 cipher.
///
/// # Security
///
/// RC4 is considered insecure and should only be used for compatibility with
/// legacy applications.
#[deprecated(note = "RC4 is considered insecure")]
#[allow(deprecated)] // Work-around until Rust issue #56195 is resolved
pub struct InsecureRc4Key {
    ctx: CStackWrapper<boringssl::RC4_KEY>,
}

#[allow(deprecated)] // Work-around until Rust issue #56195 is resolved
impl InsecureRc4Key {
    /// INSECURE: Constructs an RC4 cipher from the given key data.
    ///
    /// The data used to construct an RC4 cipher can be of arbitrary length
    /// (within the bounds of `u32`; see below). This includes zero-length keys,
    /// for which care should be taken to avoid.
    ///
    /// # Security
    ///
    /// RC4 is considered insecure and should only be used for compatibility
    /// with legacy applications.
    ///
    /// # Aborts
    ///
    /// This function aborts if the length of the `key` slice exceeds
    /// `u32::MAX`.
    #[deprecated(note = "RC4 is considered insecure")]
    pub fn insecure_new(key: &[u8]) -> Self {
        InsecureRc4Key { ctx: CStackWrapper::rc4_set_key(key.as_ref()) }
    }

    /// INSECURE: Encrypts or decrypts a byte slice into another byte slice.
    ///
    /// RC4 is a symmetrical streaming cipher; there is no distinction between
    /// encryption and decryption.
    ///
    /// The minimum of the input and output slice lengths determines how much
    /// data is read from `input` and written to `output`.
    ///
    /// # Security
    ///
    /// RC4 is considered insecure and should only be used for compatibility
    /// with legacy applications.
    #[deprecated(note = "RC4 is considered insecure")]
    pub fn insecure_xor_stream(&mut self, input: &[u8], output: &mut [u8]) {
        self.ctx.rc4(input, output);
    }
}

#[allow(deprecated)] // Work-around until Rust issue #56195 is resolved
#[cfg(test)]
mod tests {
    use super::*;

    // Compliments `rc4_decrypt`.
    #[test]
    fn rc4_encrypt() {
        let mut rc4 = InsecureRc4Key::insecure_new(b"Key");

        let plaintext = b"Plaintext";
        let mut ciphertext = vec![0u8; 9];

        rc4.insecure_xor_stream(plaintext, &mut ciphertext);
        assert_eq!(&ciphertext, b"\xBB\xF3\x16\xE8\xD9\x40\xAF\x0A\xD3");
    }

    // Compliments `rc4_encrypt`.
    #[test]
    fn rc4_decrypt() {
        let mut rc4 = InsecureRc4Key::insecure_new(b"Key");

        let plaintext = b"\xBB\xF3\x16\xE8\xD9\x40\xAF\x0A\xD3";
        let mut ciphertext = vec![0u8; 9];

        rc4.insecure_xor_stream(plaintext, &mut ciphertext);
        assert_eq!(&ciphertext, b"Plaintext");
    }
}
