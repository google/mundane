// Copyright 2018 Google LLC
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

//! Public key cryptography.

pub mod ec;
pub mod ed25519;

use boringssl::{CHeapWrapper, CStackWrapper};
use public::inner::BoringDerKey;
use util::Sealed;
use Error;

/// The public component of a public/private key pair.
pub trait PublicKey: Sealed + Sized {
    /// The type of the private component.
    type Private: PrivateKey<Public = Self>;
}

/// The private component of a public/private key pair.
pub trait PrivateKey: Sealed + Sized {
    /// The type of the public component.
    type Public: PublicKey<Private = Self>;

    /// Gets the public key corresponding to this private key.
    #[must_use]
    fn public(&self) -> Self::Public;
}

/// A public key which can be encoded as a DER object.
pub trait DerPublicKey: PublicKey + self::inner::DerKey {
    /// Marshals a public key in DER format.
    ///
    /// `marshal_to_der` marshals a public key as a DER-encoded
    /// SubjectPublicKeyInfo structure as defined in [RFC 5280].
    ///
    /// [RFC 5280]: https://tools.ietf.org/html/rfc5280
    #[must_use]
    fn marshal_to_der(&self) -> Vec<u8> {
        let mut evp_pkey = CHeapWrapper::default();
        self.boring().pkey_assign(&mut evp_pkey);
        // cbb_new can only fail due to OOM
        let mut cbb = CStackWrapper::cbb_new(64).unwrap();
        evp_pkey
            .evp_marshal_public_key(&mut cbb)
            .expect("failed to marshal public key");
        cbb.cbb_with_data(<[u8]>::to_vec)
    }

    /// Parses a public key in DER format.
    ///
    /// `parse_from_der` parses a public key from a DER-encoded
    /// SubjectPublicKeyInfo structure as defined in [RFC 5280].
    ///
    /// # Elliptic Curve Keys
    ///
    /// For Elliptic Curve keys ([`EcPubKey`]), the curve itself is validated.
    /// If the curve is not known ahead of time, and any curve must be supported
    /// at runtime, use the [`EcPubKeyAnyCurve::parse_from_der`] function.
    ///
    /// [RFC 5280]: https://tools.ietf.org/html/rfc5280
    /// [`EcPubKey`]: ::public::ec::EcPubKey
    /// [`EcPubKeyAnyCurve::parse_from_der`]: ::public::ec::EcPubKeyAnyCurve::parse_from_der
    #[must_use]
    fn parse_from_der(bytes: &[u8]) -> Result<Self, Error> {
        CStackWrapper::cbs_with_temp_buffer(bytes, |cbs| {
            let mut evp_pkey = CHeapWrapper::evp_parse_public_key(cbs)?;
            // NOTE: For EC, panics if evp_pkey doesn't have its group set. This is
            // OK because EVP_parse_public_key guarantees that the returned key has
            // its group set.
            let key = Self::Boring::pkey_get(&mut evp_pkey)?;
            if cbs.cbs_len() > 0 {
                return Err(Error::new("malformed DER input".to_string()));
            }
            Ok(Self::from_boring(key))
        })
    }
}

/// A private key which can be encoded as a DER object.
pub trait DerPrivateKey: PrivateKey + self::inner::DerKey {
    /// Marshals a private key in DER format.
    ///
    /// `marshal_to_der` marshal a private key as a DER-encoded structure. The
    /// exact structure encoded depends on the type of key:
    /// - For an EC key, it is an ECPrivateKey structure as defined in [RFC
    ///   5915].
    /// - For an RSA key, it is an RSAPrivateKey structure as defined in [RFC
    ///   3447].
    ///
    /// [RFC 5915]: https://tools.ietf.org/html/rfc5915
    /// [RFC 3447]: https://tools.ietf.org/html/rfc3447
    #[must_use]
    fn marshal_to_der(&self) -> Vec<u8> {
        // cbb_new can only fail due to OOM
        let mut cbb = CStackWrapper::cbb_new(64).unwrap();
        self.boring()
            .marshal_private_key(&mut cbb)
            .expect("failed to marshal private key");
        cbb.cbb_with_data(<[u8]>::to_vec)
    }

    /// Parses a private key in DER format.
    ///
    /// `parse_from_der` parses a private key from a DER-encoded format. The
    /// exact structure expected depends on the type of key:
    /// - For an EC key, it is an ECPrivateKey structure as defined in [RFC
    ///   5915].
    /// - For an RSA key, it is an RSAPrivateKey structure as defined in [RFC
    ///   3447].
    ///
    /// # Elliptic Curve Keys
    ///
    /// For Elliptic Curve keys ([`EcPrivKey`]), the curve itself is validated. If
    /// the curve is not known ahead of time, and any curve must be supported at
    /// runtime, use the [`EcPrivKeyAnyCurve::parse_from_der`] function.
    ///
    /// [RFC 5915]: https://tools.ietf.org/html/rfc5915
    /// [RFC 3447]: https://tools.ietf.org/html/rfc3447
    /// [`EcPrivKey`]: ::public::ec::EcPrivKey
    /// [`EcPrivKeyAnyCurve::parse_from_der`]: ::public::ec::EcPrivKeyAnyCurve::parse_from_der
    #[must_use]
    fn parse_from_der(bytes: &[u8]) -> Result<Self, Error> {
        CStackWrapper::cbs_with_temp_buffer(bytes, |cbs| {
            let key = Self::Boring::parse_private_key(cbs)?;
            if cbs.cbs_len() > 0 {
                return Err(Error::new("malformed DER input".to_string()));
            }
            Ok(Self::from_boring(key))
        })
    }
}

/// A cryptographic signature generated by a private key.
pub trait Signature: Sealed + Sized {
    /// The private key type used to generate this signature.
    type PrivateKey: PrivateKey;

    /// Sign a message.
    ///
    /// The input to this function is always a message, never a digest. If a
    /// signature scheme calls for hashing a message and signing the hash
    /// digest, `sign` is responsible for both hashing and signing.
    #[must_use]
    fn sign(key: &Self::PrivateKey, message: &[u8]) -> Result<Self, Error>;

    /// Verify a signature.
    ///
    /// The input to this function is always a message, never a digest. If a
    /// signature scheme calls for hashing a message and signing the hash
    /// digest, `verify` is responsible for both hashing and verifying the
    /// digest.
    #[must_use]
    fn verify(&self, key: &<Self::PrivateKey as PrivateKey>::Public, message: &[u8]) -> bool;
}

mod inner {
    use boringssl::{self, CHeapWrapper, CStackWrapper};
    use Error;

    /// A wrapper around a BoringSSL key object.
    pub trait BoringDerKey: Sized {
        // evp_pkey_assign_xxx
        fn pkey_assign(&self, pkey: &mut CHeapWrapper<boringssl::EVP_PKEY>);

        // evp_pkey_get_xxx; panics if the key is an EC key and doesn't have a group set,
        // and errors if pkey isn't the expected key type
        fn pkey_get(pkey: &mut CHeapWrapper<boringssl::EVP_PKEY>) -> Result<Self, Error>;

        // xxx_parse_private_key
        fn parse_private_key(cbs: &mut CStackWrapper<boringssl::CBS>) -> Result<Self, Error>;

        // xxx_marshal_private_key
        fn marshal_private_key(&self, cbb: &mut CStackWrapper<boringssl::CBB>)
            -> Result<(), Error>;
    }

    /// Properties shared by both public and private keys of a given type.
    pub trait DerKey {
        /// The underlying BoringSSL object wrapper type.
        type Boring: BoringDerKey;

        fn boring(&self) -> &Self::Boring;

        fn from_boring(Self::Boring) -> Self;
    }
}

#[cfg(test)]
mod testutil {
    use super::*;

    /// Smoke test a signature scheme.
    ///
    /// `sig_from_bytes` takes a byte slice and converts it into a signature. If
    /// the byte slice is too long, it either truncate it or treats it as
    /// invalid (it's up to the caller). If the byte slice is too short, it
    /// fills in the remaining bytes with zeroes.
    pub fn test_signature_smoke<S: Signature, F: Fn(&[u8]) -> S, G: Fn(&S) -> &[u8]>(
        key: &S::PrivateKey,
        sig_from_bytes: F,
        bytes_from_sig: G,
    ) {
        // Sign the message, verify the signature, and return the signature.
        // Also verify that, if the wrong signature is used, the signature fails
        // to verify. Also verify that sig_from_bytes works.
        fn sign_and_verify<S: Signature, F: Fn(&[u8]) -> S, G: Fn(&S) -> &[u8]>(
            key: &S::PrivateKey,
            message: &[u8],
            sig_from_bytes: F,
            bytes_from_sig: G,
        ) -> S {
            let sig = S::sign(key, message).unwrap();
            assert!(sig.verify(&key.public(), message));
            let sig2 = S::sign(&key, bytes_from_sig(&sig)).unwrap();
            assert!(!sig2.verify(&key.public(), message));
            sig_from_bytes(bytes_from_sig(&sig))
        }

        // Sign an empty message, and verify the signature. Use the signature as
        // the next message to test, and repeat many times.
        let mut msg = Vec::new();
        for _ in 0..16 {
            msg = bytes_from_sig(&sign_and_verify(
                key,
                &msg,
                &sig_from_bytes,
                &bytes_from_sig,
            ))
            .to_vec();
        }
    }
}
