// Copyright 2018 Google LLC
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

//! The Ed25519 signature algorithm.

use boringssl::{ed25519_keypair, ed25519_keypair_from_seed, ed25519_sign, ed25519_verify};
use public::{PrivateKey, PublicKey, Signature};
use util::Sealed;
use Error;

const ED25519_PUBLIC_KEY_LEN: usize = ::boringssl::ED25519_PUBLIC_KEY_LEN as usize;
const ED25519_PRIVATE_KEY_LEN: usize = ::boringssl::ED25519_PRIVATE_KEY_LEN as usize;
const ED25519_SIGNATURE_LEN: usize = ::boringssl::ED25519_SIGNATURE_LEN as usize;
// BoringSSL stores both a private and a public key in their private key
// representation. The private key comes first, followed by the public key.
const ED25519_PUBLIC_KEY_OFFSET: usize = ED25519_PRIVATE_KEY_LEN - ED25519_PUBLIC_KEY_LEN;

/// An Ed25519 public key.
pub struct Ed25519PubKey {
    key: [u8; ED25519_PUBLIC_KEY_LEN],
}

impl Ed25519PubKey {
    /// Constructs a new public key from bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; ED25519_PUBLIC_KEY_LEN]) -> Ed25519PubKey {
        Ed25519PubKey { key: bytes }
    }

    /// Gets the raw bytes of the public key.
    #[must_use]
    pub fn bytes(&self) -> &[u8; ED25519_PUBLIC_KEY_LEN] {
        &self.key
    }
}

impl_debug!(Ed25519PubKey, "Ed25519PubKey");

impl Sealed for Ed25519PubKey {}
impl PublicKey for Ed25519PubKey {
    type Private = Ed25519PrivKey;
}

/// An Ed25519 private key.
///
/// An `Ed25519PrivKey` actually includes both the private key and the public
/// key in order to make multiple key signing operations with the same key more
/// efficient.
pub struct Ed25519PrivKey {
    key: [u8; ED25519_PRIVATE_KEY_LEN],
}

impl_debug!(Ed25519PrivKey, "Ed25519PrivKey");

impl Ed25519PrivKey {
    /// Generates a new private key.
    #[must_use]
    pub fn generate() -> Ed25519PrivKey {
        Ed25519PrivKey {
            key: ed25519_keypair(),
        }
    }

    /// Constructs a new private key from a key pair.
    ///
    /// Usually, an Ed25519 private key will be stored as a single 64-byte blob:
    /// the 32-byte private key followed by the 32-byte public key. However, we
    /// accept the two keys as separate arguments in case they are stored
    /// separately.
    #[must_use]
    pub fn from_key_pair_bytes(private: [u8; 32], public: &Ed25519PubKey) -> Ed25519PrivKey {
        let mut key = [0u8; ED25519_PRIVATE_KEY_LEN];
        (&mut key[..32]).copy_from_slice(&private);
        (&mut key[ED25519_PUBLIC_KEY_OFFSET..]).copy_from_slice(&public.key);
        Ed25519PrivKey { key }
    }

    /// Constructs a new private key.
    ///
    /// Unlike [`from_key_pair_bytes`], `from_private_key_bytes` reconstructs
    /// the key (which includes both the private key and the public key
    /// internally) from only the private key.
    ///
    /// [`from_key_pair_bytes`]: ::public::ed25519::Ed25519PrivKey::from_key_pair_bytes
    #[must_use]
    pub fn from_private_key_bytes(private: [u8; 32]) -> Ed25519PrivKey {
        let (_, key) = ed25519_keypair_from_seed(&private);
        Ed25519PrivKey { key }
    }

    /// Gets the raw bytes of the private key.
    #[must_use]
    pub fn bytes(&self) -> &[u8; ED25519_PRIVATE_KEY_LEN] {
        &self.key
    }
}

impl Sealed for Ed25519PrivKey {}
impl PrivateKey for Ed25519PrivKey {
    type Public = Ed25519PubKey;

    fn public(&self) -> Ed25519PubKey {
        let mut public = [0u8; ED25519_PUBLIC_KEY_LEN];
        (&mut public[..]).copy_from_slice(&self.key[ED25519_PUBLIC_KEY_OFFSET..]);
        Ed25519PubKey { key: public }
    }
}

/// An Ed25519 signature.
#[must_use]
pub struct Ed25519Signature {
    sig: [u8; ED25519_SIGNATURE_LEN],
}

impl_debug!(Ed25519Signature, "Ed25519Signature");

impl Ed25519Signature {
    /// Constructs an `Ed25519Signature` signature from raw bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; ED25519_SIGNATURE_LEN]) -> Ed25519Signature {
        Ed25519Signature { sig: bytes }
    }

    /// Gets the raw bytes of the signature.
    #[must_use]
    pub fn bytes(&self) -> &[u8; ED25519_SIGNATURE_LEN] {
        &self.sig
    }

    /// Sign a message.
    ///
    /// `Ed25519Signature` implements [`Signature`], but `Signature`'s [`sign`]
    /// function conservatively returns a `Result`. Ed25519 signatures never
    /// fail, so this function is provided to allow the user to compute an
    /// Ed25519 signature without having to perform error checking.
    ///
    /// [`Signature`]: ::public::Signature
    /// [`sign`]: ::public::Signature::sign
    #[must_use]
    pub fn sign_ed25519(key: &Ed25519PrivKey, message: &[u8]) -> Ed25519Signature {
        Ed25519Signature {
            // ED25519_sign can only return an error on OOM
            sig: ed25519_sign(message, &key.key).unwrap(),
        }
    }
}

impl Sealed for Ed25519Signature {}
impl Signature for Ed25519Signature {
    type PrivateKey = Ed25519PrivKey;

    /// Sign a message.
    ///
    /// Though the [`Signature`] trait requires that [`sign`] return a `Result`,
    /// `Ed25519Signature`'s implementation is guaranteed to always return `Ok`.
    /// Callers may prefer the [`sign_ed25519`] function, which returns an
    /// `Ed25519Signature` rather than a `Result`.
    ///
    /// [`Signature`]: ::public::Signature
    /// [`sign`]: ::public::Signature::sign
    /// [`sign_ed25519`]: ::public::ed25519::Ed25519Signature::sign_ed25519
    fn sign(key: &Ed25519PrivKey, message: &[u8]) -> Result<Ed25519Signature, Error> {
        Ok(Ed25519Signature::sign_ed25519(key, message))
    }

    fn is_valid(&self, key: &Ed25519PubKey, message: &[u8]) -> bool {
        ed25519_verify(message, &self.sig, &key.key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use public::testutil::test_signature_smoke;

    #[test]
    fn test_priv_key_constructors() {
        let key = Ed25519PrivKey::generate();
        let mut private = [0u8; 32];
        (&mut private[..]).copy_from_slice(&key.key[..32]);
        let key2 = Ed25519PrivKey::from_private_key_bytes(private);
        assert_eq!(&key.key[..], &key2.key[..]);

        let mut private = [0u8; 32];
        let mut public = [0u8; 32];
        let bytes = *key.bytes();
        (&mut private[..]).copy_from_slice(&bytes[..32]);
        (&mut public[..]).copy_from_slice(&bytes[32..]);
        let key2 = Ed25519PrivKey::from_key_pair_bytes(private, &Ed25519PubKey::from_bytes(public));
        assert_eq!(&key.key[..], &key2.key[..]);
    }

    #[test]
    fn test_smoke() {
        let key = Ed25519PrivKey::generate();
        let from_bytes = |bytes: &[u8]| {
            let mut sig = [0u8; ED25519_SIGNATURE_LEN];
            let len = ::std::cmp::min(sig.len(), bytes.len());
            (&mut sig[..len]).copy_from_slice(&bytes[..len]);
            Ed25519Signature::from_bytes(sig)
        };
        // for some reason, defining this as a closure results in type inference
        // issues that aren't worth debugging
        fn to_bytes(sig: &Ed25519Signature) -> &[u8] {
            &sig.bytes()[..]
        }
        test_signature_smoke(&key, from_bytes, to_bytes);
    }
}
