// Copyright 2018 Google LLC
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

//! The RSA public-key cryptosystem.

mod bits;

pub use public::rsa::bits::{RsaKeyBits, B2048, B3072, B4096, B6144, B8192};

use std::fmt::{self, Debug, Display, Formatter};
use std::marker::PhantomData;

use boringssl::{self, BoringError, CHeapWrapper, CStackWrapper};
use hash::{inner::Digest, Hasher};
use public::rsa::inner::RsaKey;
use public::{inner::DerKey, DerPrivateKey, DerPublicKey, PrivateKey, PublicKey, Signature};
use util::Sealed;
use Error;

mod inner {
    use std::convert::TryInto;
    use std::marker::PhantomData;

    use boringssl::{self, BoringError, CHeapWrapper, CStackWrapper};
    use hash::Hasher;
    use public::inner::BoringDerKey;
    use public::rsa::RsaKeyBits;
    use util::Sealed;
    use Error;

    // A convenience wrapper around boringssl::RSA.
    //
    // RsaKey maintains the following invariants:
    // - The key has B bits
    // - The key has its "n" and "e" parameters initialized
    //
    // This is marked pub and put in this (non-public) module so that using it
    // in impls of the DerKey trait don't result in public-in-private errors.
    #[derive(Clone)]
    pub struct RsaKey<B: RsaKeyBits> {
        // WARNING: Do not expose this mutably. See the comment on `get_key` for
        // more details.
        key: CHeapWrapper<boringssl::RSA>,
        _marker: PhantomData<B>,
    }

    impl<B: RsaKeyBits> RsaKey<B> {
        pub fn generate() -> Result<RsaKey<B>, BoringError> {
            let mut key = CHeapWrapper::default();
            let mut e = CStackWrapper::default();
            // BN_set_u64 can only fail due to OOM.
            e.bn_set_u64(boringssl::RSA_F4.into()).unwrap();
            // try_into can only fail if B::BITS overflows c_int.
            key.rsa_generate_key_ex(B::BITS.try_into().unwrap(), &e.as_c_ref())?;
            Ok(RsaKey { key, _marker: PhantomData })
        }

        /// Creates an `RsaKey` from a BoringSSL `RSA`.
        ///
        /// `from_RSA` validates that `key` has `B` bits.
        #[allow(non_snake_case)]
        pub fn from_RSA(key: CHeapWrapper<boringssl::RSA>) -> Result<RsaKey<B>, Error> {
            B::validate_bits(key.rsa_bits())?;
            Ok(RsaKey { key, _marker: PhantomData })
        }

        /// Gets the key immutably.
        ///
        /// Note that the choice not to provide a mutable getter is an
        /// intentional one. The BoringSSL functions which mutate an RSA key -
        /// descendents of OpenSSL's setter pattern - are very broken. In
        /// particular, overwriting an existing key that has already been used
        /// will produce broken objects and cause unexpected behavior. If
        /// modification is required, create a new key.
        ///
        /// For more details, see [this comment thread].
        ///
        /// [this comment thread]: https://fuchsia-review.googlesource.com/c/mundane/+/486717/2/src/public/rsa/mod.rs#69
        pub fn get_key(&self) -> &CHeapWrapper<boringssl::RSA> {
            &self.key
        }
    }

    impl<B: RsaKeyBits> BoringDerKey for RsaKey<B> {
        fn pkey_assign(&self, pkey: &mut CHeapWrapper<boringssl::EVP_PKEY>) {
            pkey.evp_pkey_assign_rsa(self.key.clone())
        }

        fn pkey_get(pkey: &mut CHeapWrapper<boringssl::EVP_PKEY>) -> Result<Self, Error> {
            let key = pkey.evp_pkey_get1_rsa()?;
            RsaKey::from_RSA(key)
        }

        fn parse_private_key(cbs: &mut CStackWrapper<boringssl::CBS>) -> Result<RsaKey<B>, Error> {
            let key = CHeapWrapper::rsa_parse_private_key(cbs)?;
            RsaKey::from_RSA(key)
        }

        fn marshal_private_key(
            &self,
            cbb: &mut CStackWrapper<boringssl::CBB>,
        ) -> Result<(), Error> {
            self.key.rsa_marshal_private_key(cbb).map_err(From::from)
        }
    }

    trait RsaKeyBitsExt: RsaKeyBits {
        fn validate_bits(bits: usize) -> Result<(), Error> {
            if bits != Self::BITS {
                return Err(Error::new(format!(
                    "unexpected RSA key bit length: got {}; want {}",
                    bits,
                    Self::BITS
                )));
            }
            Ok(())
        }
    }

    impl<B: RsaKeyBits> RsaKeyBitsExt for B {}

    pub trait RsaSignatureScheme: Sealed {
        fn sign<B: RsaKeyBits, H: Hasher>(
            rsa: &RsaKey<B>,
            digest: &[u8],
            sig: &mut [u8],
        ) -> Result<usize, BoringError>;
        fn verify<B: RsaKeyBits, H: Hasher>(rsa: &RsaKey<B>, digest: &[u8], sig: &[u8]) -> bool;
    }

    #[cfg(test)]
    mod tests {
        use std::mem;

        use super::*;
        use public::rsa::tests::get_test_key;
        use public::rsa::{B2048, B3072, B4096, B6144, B8192};

        #[test]
        fn test_refcount() {
            // Test that we refcount properly by creating many clones and then
            // freeing them all. If we decrement the recount below 0, a test in
            // BoringSSL will catch it and crash the program. This test cannot
            // currently detect not decrementing the refcount enough (thus
            // leaking resources).
            //
            // TODO(joshlf): Figure out a way to also test that we decrement the
            // refcount enough.

            fn test<B: RsaKeyBits>() {
                let key = get_test_key::<B>().inner;
                for i in 0..8 {
                    // make i clones and then free them all
                    let mut keys = Vec::new();
                    for _ in 0..i {
                        keys.push(key.clone());
                    }
                    mem::drop(keys);
                }
                mem::drop(key);
            }

            test::<B2048>();
            test::<B3072>();
            test::<B4096>();
            test::<B6144>();
            test::<B8192>();
        }
    }
}

/// A `B`-bit RSA public key.
///
/// `RsaPubKey` is an RSA public key which is `B` bits long.
pub struct RsaPubKey<B: RsaKeyBits> {
    inner: RsaKey<B>,
}

impl<B: RsaKeyBits> Sealed for RsaPubKey<B> {}
impl<B: RsaKeyBits> DerPublicKey for RsaPubKey<B> {}

impl<B: RsaKeyBits> DerKey for RsaPubKey<B> {
    type Boring = RsaKey<B>;
    fn boring(&self) -> &RsaKey<B> {
        &self.inner
    }
    fn from_boring(inner: RsaKey<B>) -> RsaPubKey<B> {
        RsaPubKey { inner }
    }
}

impl<B: RsaKeyBits> PublicKey for RsaPubKey<B> {
    type Private = RsaPrivKey<B>;
}

impl<B: RsaKeyBits> Debug for RsaPubKey<B> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "RsaPubKey")
    }
}

/// A `B`-bit RSA private key.
///
/// `RsaPrivKey` is an RSA private key which is `B` bits long.
pub struct RsaPrivKey<B: RsaKeyBits> {
    inner: RsaKey<B>,
}

impl<B: RsaKeyBits> RsaPrivKey<B> {
    /// Generates a new private key.
    #[must_use]
    pub fn generate() -> Result<RsaPrivKey<B>, Error> {
        Ok(RsaPrivKey { inner: RsaKey::generate()? })
    }
}

impl<B: RsaKeyBits> Sealed for RsaPrivKey<B> {}
impl<B: RsaKeyBits> DerPrivateKey for RsaPrivKey<B> {}

impl<B: RsaKeyBits> DerKey for RsaPrivKey<B> {
    type Boring = RsaKey<B>;
    fn boring(&self) -> &RsaKey<B> {
        &self.inner
    }
    fn from_boring(inner: RsaKey<B>) -> RsaPrivKey<B> {
        RsaPrivKey { inner }
    }
}

impl<B: RsaKeyBits> PrivateKey for RsaPrivKey<B> {
    type Public = RsaPubKey<B>;

    fn public(&self) -> RsaPubKey<B> {
        RsaPubKey { inner: self.inner.clone() }
    }
}

impl<B: RsaKeyBits> Debug for RsaPrivKey<B> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "RsaPrivKey")
    }
}

/// An RSA public key whose bit length is unknown at compile time.
///
/// An `RsaPubKeyAnyBits` is an enum of [`RsaPubKey`]s over all supported bit
/// lengths. It is returned from [`RsaPubKeyAnyBits::parse_from_der`].
#[allow(missing_docs)]
#[derive(Debug)]
pub enum RsaPubKeyAnyBits {
    B2048(RsaPubKey<B2048>),
    B3072(RsaPubKey<B3072>),
    B4096(RsaPubKey<B4096>),
    B6144(RsaPubKey<B6144>),
    B8192(RsaPubKey<B8192>),
}

impl RsaPubKeyAnyBits {
    /// Parses a public key in DER format with any bit length.
    ///
    /// `parse_from_der` is like [`DerPublicKey::parse_from_der`], but it
    /// accepts any bit length rather than a particular bit length.
    ///
    /// Since [`RsaPubKey`] requires a static [`RsaKeyBits`] type parameter, the
    /// `parse_from_der` function on `RsaPubKey`'s `DerPublicKey` implementation
    /// can only be called when the bit length is known ahead of time. This
    /// function, on the other hand, accepts any bit length.
    ///
    /// [`DerPublicKey::parse_from_der`]: ::public::DerPublicKey::parse_from_der
    /// [`PublicKey`]: ::public::PublicKey
    #[must_use]
    pub fn parse_from_der(bytes: &[u8]) -> Result<RsaPubKeyAnyBits, Error> {
        CStackWrapper::cbs_with_temp_buffer(bytes, |cbs| {
            let mut evp_pkey = CHeapWrapper::evp_parse_public_key(cbs)?;
            let key = evp_pkey.evp_pkey_get1_rsa()?;
            if cbs.cbs_len() > 0 {
                return Err(Error::new("excess data provided after valid DER input".to_string()));
            }

            Ok(match key.rsa_bits() {
                B2048::BITS => RsaPubKeyAnyBits::B2048(RsaPubKey { inner: RsaKey::from_RSA(key)? }),
                B3072::BITS => RsaPubKeyAnyBits::B3072(RsaPubKey { inner: RsaKey::from_RSA(key)? }),
                B4096::BITS => RsaPubKeyAnyBits::B4096(RsaPubKey { inner: RsaKey::from_RSA(key)? }),
                B6144::BITS => RsaPubKeyAnyBits::B6144(RsaPubKey { inner: RsaKey::from_RSA(key)? }),
                B8192::BITS => RsaPubKeyAnyBits::B8192(RsaPubKey { inner: RsaKey::from_RSA(key)? }),
                bits => return Err(Error::new(format!("unsupported bit length: {}", bits))),
            })
        })
    }
}

/// An RSA private key whose bit length is unknown at compile time.
///
/// An `RsaPrivKeyAnyBits` is an enum of [`RsaPrivKey`]s over all supported bit
/// lengths. It is returned from [`RsaPrivKeyAnyBits::parse_from_der`].
#[allow(missing_docs)]
#[derive(Debug)]
pub enum RsaPrivKeyAnyBits {
    B2048(RsaPrivKey<B2048>),
    B3072(RsaPrivKey<B3072>),
    B4096(RsaPrivKey<B4096>),
    B6144(RsaPrivKey<B6144>),
    B8192(RsaPrivKey<B8192>),
}

impl RsaPrivKeyAnyBits {
    /// Gets the public key corresponding to this private key.
    #[must_use]
    pub fn public(&self) -> RsaPubKeyAnyBits {
        match self {
            RsaPrivKeyAnyBits::B2048(key) => RsaPubKeyAnyBits::B2048(key.public()),
            RsaPrivKeyAnyBits::B3072(key) => RsaPubKeyAnyBits::B3072(key.public()),
            RsaPrivKeyAnyBits::B4096(key) => RsaPubKeyAnyBits::B4096(key.public()),
            RsaPrivKeyAnyBits::B6144(key) => RsaPubKeyAnyBits::B6144(key.public()),
            RsaPrivKeyAnyBits::B8192(key) => RsaPubKeyAnyBits::B8192(key.public()),
        }
    }

    /// Parses a private key in DER format with any bit length.
    ///
    /// `parse_from_der` is like [`DerPrivateKey::parse_from_der`], but it
    /// accepts any bit length rather that a particular bit length.
    ///
    /// Since [`RsaPrivKey`] requires a static [`RsaKeyBits`] type parameter,
    /// the `parse_from_der` function on `RsaPrivKey`'s `DerPrivateKey`
    /// implementation can only be called when the bit length is known ahead of
    /// time. This function, on the other hand, accepts any bit length.
    ///
    /// [`DerPrivateKey::parse_from_der`]: ::public::DerPrivateKey::parse_from_der
    /// [`PrivateKey`]: ::public::PrivateKey
    #[must_use]
    pub fn parse_from_der(bytes: &[u8]) -> Result<RsaPrivKeyAnyBits, Error> {
        CStackWrapper::cbs_with_temp_buffer(bytes, |cbs| {
            let key = CHeapWrapper::rsa_parse_private_key(cbs)?;
            if cbs.cbs_len() > 0 {
                return Err(Error::new("excess data provided after valid DER input".to_string()));
            }

            Ok(match key.rsa_bits() {
                B2048::BITS => {
                    RsaPrivKeyAnyBits::B2048(RsaPrivKey { inner: RsaKey::from_RSA(key)? })
                }
                B3072::BITS => {
                    RsaPrivKeyAnyBits::B3072(RsaPrivKey { inner: RsaKey::from_RSA(key)? })
                }
                B4096::BITS => {
                    RsaPrivKeyAnyBits::B4096(RsaPrivKey { inner: RsaKey::from_RSA(key)? })
                }
                B6144::BITS => {
                    RsaPrivKeyAnyBits::B6144(RsaPrivKey { inner: RsaKey::from_RSA(key)? })
                }
                B8192::BITS => {
                    RsaPrivKeyAnyBits::B8192(RsaPrivKey { inner: RsaKey::from_RSA(key)? })
                }
                bits => return Err(Error::new(format!("unsupported bit length: {}", bits))),
            })
        })
    }
}

/// An RSA signature scheme.
///
/// An `RsaSignatureScheme` defines how to compute an RSA signature. The primary
/// detail defined by a signature scheme is how to perform padding.
///
/// `RsaSignatureScheme` is implemented by [`RsaPss`] and, if the `rsa-pkcs1v15`
/// feature is enabled, [`RsaPkcs1v15`].
pub trait RsaSignatureScheme:
    Sized + Copy + Clone + Default + Display + Debug + self::inner::RsaSignatureScheme
{
}

/// The RSA-PKCS1v1.5 signature scheme.
///
/// This signature scheme is old, and considered less secure than RSA-PSS. It
/// should only be used for compatibility with legacy systems - never in new
/// systems!
///
/// *This signature scheme is available if Mundane is built with the `rsa-pkcs1v15` feature.*
#[cfg(any(doc, feature = "rsa-pkcs1v15"))]
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Hash)]
pub struct RsaPkcs1v15;

#[cfg(feature = "rsa-pkcs1v15")]
impl Display for RsaPkcs1v15 {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "RSA-PKCS1v1.5")
    }
}

#[cfg(feature = "rsa-pkcs1v15")]
impl Sealed for RsaPkcs1v15 {}
#[cfg(feature = "rsa-pkcs1v15")]
impl RsaSignatureScheme for RsaPkcs1v15 {}

#[cfg(feature = "rsa-pkcs1v15")]
impl self::inner::RsaSignatureScheme for RsaPkcs1v15 {
    fn sign<B: RsaKeyBits, H: Hasher>(
        rsa: &RsaKey<B>,
        digest: &[u8],
        sig: &mut [u8],
    ) -> Result<usize, BoringError> {
        // NOTE: rsa_sign will panic if sig is not large enough to hold the
        // largest possible signature, as RSA_sign has this as a precondition.
        boringssl::rsa_sign(H::nid(), digest, sig, rsa.get_key())
    }
    fn verify<B: RsaKeyBits, H: Hasher>(rsa: &RsaKey<B>, digest: &[u8], sig: &[u8]) -> bool {
        boringssl::rsa_verify(H::nid(), digest, sig, rsa.get_key())
    }
}

impl Display for RsaPss {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "RSA-PSS")
    }
}

/// The RSA-PSS signature scheme.
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Hash)]
pub struct RsaPss;

impl Sealed for RsaPss {}
impl RsaSignatureScheme for RsaPss {}

impl self::inner::RsaSignatureScheme for RsaPss {
    fn sign<B: RsaKeyBits, H: Hasher>(
        rsa: &RsaKey<B>,
        digest: &[u8],
        sig: &mut [u8],
    ) -> Result<usize, BoringError> {
        // We assert here (and not in the RSA-PKCS1v1.5 implementation) because,
        // while our rsa_sign wrapper (which implements PKCS1v1.5) performs this
        // assertion itself (for safety reasons), our rsa_sign_pss_mgf1 wrapper
        // does not. This assertion is an important security and correctness
        // check as well, as passing a too-short signature would result in the
        // signature being truncated.
        assert!(sig.len() >= rsa.get_key().rsa_size().unwrap().get());
        // A salt_len of -1 means to use a salt of the same length as the hash
        // output. This is a reasonable default and, for bit lengths larger than
        // 2048, ensures that the salt will never need to be truncated.
        boringssl::rsa_sign_pss_mgf1(rsa.get_key(), sig, digest, &H::evp_md(), None, -1)
    }
    fn verify<B: RsaKeyBits, H: Hasher>(rsa: &RsaKey<B>, digest: &[u8], sig: &[u8]) -> bool {
        // A salt_len of -2 means to recover the salt length from the signature,
        // and thus to tolerate any salt length.
        boringssl::rsa_verify_pss_mgf1(rsa.get_key(), digest, &H::evp_md(), None, -2, sig)
    }
}

// The maximum length of an RSA-8192 signature. Since this isn't exposed in the
// API, we can increase later if we add support for larger bit sizes.
const MAX_SIGNATURE_LEN: usize = 1024;

/// An RSA signature.
///
/// `RsaSignature` is an RSA signature generated by keys of length `B`, using
/// the signature scheme `S`, and the hash function `H`.
pub struct RsaSignature<B: RsaKeyBits, S: RsaSignatureScheme, H: Hasher> {
    bytes: [u8; MAX_SIGNATURE_LEN],
    // Invariant: len is in [0; MAX_SIGNATURE_LEN). If len is 0, it indicates an
    // invalid signature. Invalid signatures can be produced when a caller
    // invokes from_bytes with a byte slice longer than MAX_SIGNATURE_LEN. Such
    // signatures cannot possibly have been generated by an RSA signature for
    // any of the key sizes or signature schemes we support, and so it could not
    // possibly be valid. In other words, it would never be correct for
    // rsa_verify to return true when invoked on such a signature.
    //
    // However, if we were to simply truncate the byte slice and store a subset
    // of it, then we might open ourselves up to attacks in which an attacker
    // induces a mismatch between the signature that the caller /thinks/ is
    // being verified and the signature that is /actually/ being verified. Thus,
    // it's important that we always reject such signatures.
    //
    // Finally, it's OK for us to use 0 as the sentinal value to mean "invalid
    // signature" because RSA can never produce a 0-byte signature. Thus, we
    // will never produce a 0-byte signature from rsa_sign, and similarly, if
    // the caller constructs a 0-byte signature using from_bytes, it's correct
    // for us to treat it as invalid.
    len: usize,
    _marker: PhantomData<(B, S, H)>,
}

impl<B: RsaKeyBits, S: RsaSignatureScheme, H: Hasher> RsaSignature<B, S, H> {
    /// Constructs an `RsaSignature` from raw bytes.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> RsaSignature<B, S, H> {
        if bytes.len() > MAX_SIGNATURE_LEN {
            // see comment on the len field for why we do this
            return Self::empty();
        }
        let mut ret = Self::empty();
        (&mut ret.bytes[..bytes.len()]).copy_from_slice(bytes);
        ret.len = bytes.len();
        ret
    }

    // TODO(joshlf): Once we have const generics, have this return a
    // fixed-length array.

    /// Gets the raw bytes of this `RsaSignature`.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    fn is_valid_format(&self) -> bool {
        self.len != 0
    }

    fn empty() -> RsaSignature<B, S, H> {
        RsaSignature { bytes: [0u8; MAX_SIGNATURE_LEN], len: 0, _marker: PhantomData }
    }
}

impl<B: RsaKeyBits, S: RsaSignatureScheme, H: Hasher> Sealed for RsaSignature<B, S, H> {}
impl<B: RsaKeyBits, S: RsaSignatureScheme, H: Hasher> Signature for RsaSignature<B, S, H> {
    type PrivateKey = RsaPrivKey<B>;

    fn sign(key: &RsaPrivKey<B>, message: &[u8]) -> Result<RsaSignature<B, S, H>, Error> {
        let digest = H::hash(message);
        let mut sig = RsaSignature::empty();
        sig.len = S::sign::<B, H>(&key.inner, digest.as_ref(), &mut sig.bytes[..])?;
        Ok(sig)
    }

    fn is_valid(&self, key: &RsaPubKey<B>, message: &[u8]) -> bool {
        if !self.is_valid_format() {
            // see comment on RsaSignature::len for why we do this
            return false;
        }
        let digest = H::hash(message);
        S::verify::<B, H>(&key.inner, digest.as_ref(), self.bytes())
    }
}

impl<B: RsaKeyBits, S: RsaSignatureScheme, H: Hasher> Debug for RsaSignature<B, S, H> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "RsaSignature")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hash::Sha256;
    use util::should_fail;

    #[test]
    fn test_generate() {
        RsaPrivKey::<B2048>::generate().unwrap();
        #[cfg(feature = "rsa-test-generate-large-keys")]
        {
            RsaPrivKey::<B3072>::generate().unwrap();
            RsaPrivKey::<B4096>::generate().unwrap();
            RsaPrivKey::<B6144>::generate().unwrap();
            RsaPrivKey::<B8192>::generate().unwrap();
        }
    }

    #[test]
    fn test_marshal_parse() {
        // Test various combinations of parsing and serializing keys.
        //
        // Since we need to test dynamic parsing (the
        // parse_private_key_der_any_bits and parse_public_key_der_any_bits
        // functions), we need a way of unwrapping their return values into a
        // static key type. Unfortunately, there's no way (on stable Rust) to do
        // that generically, so the caller must pass a function which will do
        // it.
        fn test<
            B: RsaKeyBits,
            F: Fn(RsaPrivKeyAnyBits) -> RsaPrivKey<B>,
            G: Fn(RsaPubKeyAnyBits) -> RsaPubKey<B>,
        >(
            unwrap_priv_any: F,
            unwrap_pub_any: G,
        ) {
            const MESSAGE: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7];
            let key = get_test_key::<B>();

            let parsed_key = RsaPrivKey::<B>::parse_from_der(&key.marshal_to_der()).unwrap();
            let parsed_key_any_bits =
                unwrap_priv_any(RsaPrivKeyAnyBits::parse_from_der(&key.marshal_to_der()).unwrap());
            let pubkey = key.public();
            let parsed_pubkey = RsaPubKey::<B>::parse_from_der(&pubkey.marshal_to_der()).unwrap();
            let parsed_pubkey_any_bits =
                unwrap_pub_any(RsaPubKeyAnyBits::parse_from_der(&pubkey.marshal_to_der()).unwrap());

            fn sign_and_verify<B: RsaKeyBits>(privkey: &RsaPrivKey<B>, pubkey: &RsaPubKey<B>) {
                #[cfg(feature = "rsa-pkcs1v15")]
                {
                    let sig =
                        RsaSignature::<B, RsaPkcs1v15, Sha256>::sign(&privkey, MESSAGE).unwrap();
                    assert!(RsaSignature::<B, RsaPkcs1v15, Sha256>::from_bytes(sig.bytes())
                        .is_valid(&pubkey, MESSAGE));
                }
                let sig = RsaSignature::<B, RsaPss, Sha256>::sign(&privkey, MESSAGE).unwrap();
                assert!(RsaSignature::<B, RsaPss, Sha256>::from_bytes(sig.bytes())
                    .is_valid(&pubkey, MESSAGE));
            }

            // Sign and verify with every pair of keys to make sure we parsed
            // the same key we marshaled.
            sign_and_verify(&key, &pubkey);
            sign_and_verify(&key, &parsed_pubkey);
            sign_and_verify(&key, &parsed_pubkey_any_bits);
            sign_and_verify(&parsed_key, &pubkey);
            sign_and_verify(&parsed_key, &parsed_pubkey);
            sign_and_verify(&parsed_key, &parsed_pubkey_any_bits);
            sign_and_verify(&parsed_key_any_bits, &pubkey);
            sign_and_verify(&parsed_key_any_bits, &parsed_pubkey);
            sign_and_verify(&parsed_key_any_bits, &parsed_pubkey_any_bits);

            let _ = RsaPubKey::<B>::marshal_to_der;
            let _ = RsaPubKey::<B>::parse_from_der;
        }

        macro_rules! unwrap_any_bits {
            ($name:ident, $any_type:ty, $key_type:ty, $bits_variant:path) => {
                fn $name(key: $any_type) -> $key_type {
                    match key {
                        $bits_variant(key) => key,
                        _ => panic!("unexpected bits"),
                    }
                }
            };
        }

        unwrap_any_bits!(
            unwrap_priv_key_any_2048,
            RsaPrivKeyAnyBits,
            RsaPrivKey<B2048>,
            RsaPrivKeyAnyBits::B2048
        );
        unwrap_any_bits!(
            unwrap_priv_key_any_3072,
            RsaPrivKeyAnyBits,
            RsaPrivKey<B3072>,
            RsaPrivKeyAnyBits::B3072
        );
        unwrap_any_bits!(
            unwrap_priv_key_any_4096,
            RsaPrivKeyAnyBits,
            RsaPrivKey<B4096>,
            RsaPrivKeyAnyBits::B4096
        );
        unwrap_any_bits!(
            unwrap_priv_key_any_6144,
            RsaPrivKeyAnyBits,
            RsaPrivKey<B6144>,
            RsaPrivKeyAnyBits::B6144
        );
        unwrap_any_bits!(
            unwrap_priv_key_any_8192,
            RsaPrivKeyAnyBits,
            RsaPrivKey<B8192>,
            RsaPrivKeyAnyBits::B8192
        );
        unwrap_any_bits!(
            unwrap_pub_key_any_2048,
            RsaPubKeyAnyBits,
            RsaPubKey<B2048>,
            RsaPubKeyAnyBits::B2048
        );
        unwrap_any_bits!(
            unwrap_pub_key_any_3072,
            RsaPubKeyAnyBits,
            RsaPubKey<B3072>,
            RsaPubKeyAnyBits::B3072
        );
        unwrap_any_bits!(
            unwrap_pub_key_any_4096,
            RsaPubKeyAnyBits,
            RsaPubKey<B4096>,
            RsaPubKeyAnyBits::B4096
        );
        unwrap_any_bits!(
            unwrap_pub_key_any_6144,
            RsaPubKeyAnyBits,
            RsaPubKey<B6144>,
            RsaPubKeyAnyBits::B6144
        );
        unwrap_any_bits!(
            unwrap_pub_key_any_8192,
            RsaPubKeyAnyBits,
            RsaPubKey<B8192>,
            RsaPubKeyAnyBits::B8192
        );

        test::<B2048, _, _>(unwrap_priv_key_any_2048, unwrap_pub_key_any_2048);
        test::<B3072, _, _>(unwrap_priv_key_any_3072, unwrap_pub_key_any_3072);
        test::<B4096, _, _>(unwrap_priv_key_any_4096, unwrap_pub_key_any_4096);
        test::<B6144, _, _>(unwrap_priv_key_any_6144, unwrap_pub_key_any_6144);
        test::<B8192, _, _>(unwrap_priv_key_any_8192, unwrap_pub_key_any_8192);
    }

    #[test]
    fn test_parse_fail() {
        // Test that invalid input is rejected.
        fn test_parse_invalid<B: RsaKeyBits>() {
            should_fail(
                RsaPrivKey::<B>::parse_from_der(&[]),
                "RsaPrivKey::parse_from_der",
                "RSA routines:OPENSSL_internal:BAD_ENCODING",
            );
            should_fail(
                RsaPubKey::<B>::parse_from_der(&[]),
                "RsaPubKey::parse_from_der",
                "public key routines:OPENSSL_internal:DECODE_ERROR",
            );
            should_fail(
                RsaPrivKeyAnyBits::parse_from_der(&[]),
                "RsaPrivKeyAnyBits::parse_from_der",
                "RSA routines:OPENSSL_internal:BAD_ENCODING",
            );
            should_fail(
                RsaPubKeyAnyBits::parse_from_der(&[]),
                "RsaPubKeyAnyBits::parse_from_der",
                "public key routines:OPENSSL_internal:DECODE_ERROR",
            );
        }

        test_parse_invalid::<B2048>();
        test_parse_invalid::<B3072>();
        test_parse_invalid::<B4096>();
        test_parse_invalid::<B6144>();
        test_parse_invalid::<B8192>();

        // Test that, when a particular bit size is expected, other bit sizes are
        // rejected.
        fn test_parse_wrong_bit_size<B1: RsaKeyBits, B2: RsaKeyBits>() {
            let privkey = get_test_key::<B1>();
            let key_der = privkey.marshal_to_der();
            should_fail(
                RsaPrivKey::<B2>::parse_from_der(&key_der),
                "RsaPrivKey::parse_from_der",
                "unexpected RSA key bit length:",
            );
            let key_der = privkey.public().marshal_to_der();
            should_fail(
                RsaPubKey::<B2>::parse_from_der(&key_der),
                "RsaPubKey::parse_from_der",
                "unexpected RSA key bit length:",
            );
        }

        // All pairs of bit sizes, (X, Y), such that X != Y.
        test_parse_wrong_bit_size::<B2048, B3072>();
        test_parse_wrong_bit_size::<B2048, B4096>();
        test_parse_wrong_bit_size::<B2048, B6144>();
        test_parse_wrong_bit_size::<B2048, B8192>();
        test_parse_wrong_bit_size::<B3072, B2048>();
        test_parse_wrong_bit_size::<B3072, B4096>();
        test_parse_wrong_bit_size::<B3072, B6144>();
        test_parse_wrong_bit_size::<B3072, B8192>();
        test_parse_wrong_bit_size::<B4096, B2048>();
        test_parse_wrong_bit_size::<B4096, B3072>();
        test_parse_wrong_bit_size::<B4096, B6144>();
        test_parse_wrong_bit_size::<B4096, B8192>();
        test_parse_wrong_bit_size::<B6144, B2048>();
        test_parse_wrong_bit_size::<B6144, B3072>();
        test_parse_wrong_bit_size::<B6144, B4096>();
        test_parse_wrong_bit_size::<B6144, B8192>();
        test_parse_wrong_bit_size::<B8192, B2048>();
        test_parse_wrong_bit_size::<B8192, B3072>();
        test_parse_wrong_bit_size::<B8192, B4096>();
        test_parse_wrong_bit_size::<B8192, B6144>();
    }

    #[test]
    fn test_signature_smoke() {
        fn test<B: RsaKeyBits>() {
            use public::testutil::test_signature_smoke;
            let key = get_test_key::<B>();
            #[cfg(feature = "rsa-pkcs1v15")]
            test_signature_smoke(
                &key,
                RsaSignature::<_, RsaPkcs1v15, Sha256>::from_bytes,
                RsaSignature::bytes,
            );
            test_signature_smoke(
                &key,
                RsaSignature::<_, RsaPss, Sha256>::from_bytes,
                RsaSignature::bytes,
            );
        }

        test::<B2048>();
        test::<B3072>();
        test::<B4096>();
        test::<B6144>();
        test::<B8192>();
    }

    #[test]
    fn test_invalid_signature() {
        fn test_is_invalid<S: RsaSignatureScheme>(sig: &RsaSignature<B2048, S, Sha256>) {
            assert_eq!(sig.len, 0);
            assert!(!sig.is_valid_format());
            assert!(!sig.is_valid(&get_test_key::<B2048>().public(), &[],));
        }
        #[cfg(feature = "rsa-pkcs1v15")]
        {
            test_is_invalid::<RsaPkcs1v15>(&RsaSignature::from_bytes(&[0; MAX_SIGNATURE_LEN + 1]));
            test_is_invalid::<RsaPkcs1v15>(&RsaSignature::from_bytes(&[]));
        }
        test_is_invalid::<RsaPss>(&RsaSignature::from_bytes(&[0; MAX_SIGNATURE_LEN + 1]));
        test_is_invalid::<RsaPss>(&RsaSignature::from_bytes(&[]));
    }

    // Generating RSA keys is very expensive. In order to make these tests run
    // more quickly, we generate one key of each bit size and hard-code their
    // values here.

    // also used by inner::tests
    pub(super) fn get_test_key<B: RsaKeyBits>() -> RsaPrivKey<B> {
        let bytes = match B::BITS {
            2048 => KEY_2048_DER,
            3072 => KEY_3072_DER,
            4096 => KEY_4096_DER,
            6144 => KEY_6144_DER,
            8192 => KEY_8192_DER,
            _ => unreachable!(),
        };
        RsaPrivKey::parse_from_der(bytes).unwrap()
    }

    const KEY_2048_DER: &[u8] = &[
        48, 130, 4, 163, 2, 1, 0, 2, 130, 1, 1, 0, 157, 144, 201, 22, 221, 190, 44, 223, 66, 13,
        120, 162, 8, 118, 12, 105, 95, 127, 18, 203, 29, 52, 178, 135, 128, 166, 109, 96, 15, 121,
        140, 78, 4, 198, 239, 72, 220, 38, 182, 168, 178, 155, 180, 38, 255, 76, 250, 222, 141,
        247, 208, 132, 163, 157, 255, 86, 92, 14, 131, 26, 236, 64, 84, 185, 95, 186, 103, 255, 96,
        145, 187, 143, 182, 88, 213, 130, 188, 94, 216, 23, 2, 164, 155, 121, 80, 200, 72, 161,
        194, 195, 3, 185, 48, 220, 180, 177, 132, 115, 237, 225, 255, 120, 103, 32, 173, 130, 240,
        207, 169, 124, 27, 59, 47, 197, 89, 118, 119, 198, 80, 168, 31, 85, 127, 149, 114, 192, 36,
        136, 228, 245, 252, 71, 207, 64, 29, 99, 202, 119, 8, 85, 27, 43, 253, 255, 187, 109, 200,
        13, 179, 64, 150, 225, 217, 11, 131, 160, 192, 111, 33, 109, 28, 36, 80, 56, 235, 109, 92,
        182, 193, 167, 196, 56, 89, 93, 19, 236, 88, 198, 67, 103, 69, 189, 93, 42, 193, 200, 106,
        246, 71, 199, 58, 235, 137, 41, 91, 128, 71, 190, 213, 225, 126, 175, 232, 117, 230, 230,
        158, 163, 75, 65, 227, 212, 150, 243, 57, 39, 231, 144, 234, 11, 91, 24, 122, 1, 130, 166,
        93, 129, 74, 151, 139, 184, 31, 144, 32, 90, 81, 112, 93, 3, 154, 229, 4, 89, 231, 33, 79,
        81, 112, 167, 6, 192, 3, 79, 7, 139, 2, 3, 1, 0, 1, 2, 130, 1, 0, 30, 3, 249, 82, 170, 78,
        50, 149, 27, 43, 158, 201, 219, 43, 197, 196, 131, 5, 29, 138, 228, 214, 231, 149, 137,
        139, 234, 181, 12, 109, 158, 173, 52, 26, 195, 117, 145, 62, 172, 184, 41, 66, 33, 8, 246,
        196, 110, 219, 219, 150, 148, 57, 216, 67, 94, 99, 80, 169, 17, 15, 157, 102, 201, 221, 0,
        95, 237, 180, 199, 236, 43, 27, 62, 228, 224, 83, 133, 215, 217, 121, 84, 175, 15, 209, 5,
        243, 9, 103, 11, 71, 132, 27, 144, 179, 210, 150, 40, 129, 191, 20, 184, 202, 114, 118,
        214, 166, 229, 129, 225, 170, 251, 51, 4, 176, 39, 17, 58, 210, 228, 5, 138, 230, 138, 37,
        233, 148, 177, 192, 183, 136, 198, 145, 239, 149, 199, 196, 95, 90, 83, 15, 127, 37, 178,
        189, 37, 74, 181, 119, 82, 113, 213, 190, 148, 211, 132, 180, 112, 215, 159, 34, 89, 21,
        114, 70, 222, 79, 94, 13, 67, 191, 79, 6, 133, 42, 104, 174, 64, 72, 8, 88, 241, 8, 211,
        26, 43, 197, 88, 227, 98, 244, 134, 147, 24, 25, 30, 53, 227, 9, 129, 119, 69, 216, 26, 30,
        193, 12, 217, 66, 164, 162, 236, 170, 166, 240, 179, 83, 61, 248, 181, 56, 58, 103, 167,
        114, 103, 103, 82, 125, 166, 4, 67, 174, 64, 74, 227, 25, 8, 194, 95, 171, 192, 170, 216,
        209, 202, 87, 109, 148, 31, 94, 239, 71, 38, 2, 211, 225, 2, 129, 129, 0, 215, 236, 219,
        65, 123, 172, 178, 60, 25, 195, 40, 241, 174, 134, 91, 252, 40, 70, 117, 50, 10, 106, 49,
        132, 97, 102, 197, 102, 232, 128, 227, 89, 120, 183, 50, 196, 232, 24, 20, 178, 96, 118,
        189, 177, 183, 125, 84, 219, 154, 253, 25, 78, 239, 216, 155, 38, 150, 168, 195, 116, 13,
        108, 217, 222, 242, 121, 118, 22, 4, 182, 44, 54, 164, 136, 133, 125, 214, 44, 116, 96, 97,
        22, 196, 21, 74, 209, 197, 110, 38, 227, 222, 95, 155, 85, 63, 65, 192, 207, 159, 42, 186,
        224, 79, 202, 245, 226, 143, 223, 20, 49, 82, 102, 72, 139, 176, 97, 73, 220, 211, 65, 88,
        174, 131, 24, 39, 25, 5, 97, 2, 129, 129, 0, 186, 207, 29, 244, 110, 171, 89, 247, 230, 95,
        29, 126, 35, 130, 169, 199, 73, 201, 197, 202, 82, 242, 129, 72, 243, 66, 41, 159, 187,
        229, 255, 242, 38, 7, 141, 245, 194, 99, 58, 83, 184, 34, 13, 10, 54, 51, 147, 96, 19, 223,
        60, 98, 237, 42, 186, 214, 231, 195, 80, 172, 118, 74, 205, 251, 87, 11, 77, 146, 130, 72,
        247, 188, 112, 128, 144, 192, 21, 0, 31, 140, 38, 231, 117, 203, 245, 17, 81, 176, 17, 104,
        39, 88, 34, 185, 102, 113, 230, 177, 85, 97, 183, 88, 34, 217, 20, 10, 187, 168, 61, 200,
        2, 70, 200, 38, 139, 237, 122, 1, 3, 93, 236, 75, 3, 202, 219, 102, 200, 107, 2, 129, 128,
        86, 178, 105, 142, 175, 99, 181, 228, 223, 203, 54, 131, 99, 185, 218, 241, 50, 18, 168,
        55, 193, 106, 198, 27, 11, 40, 194, 150, 1, 64, 207, 8, 59, 170, 3, 30, 128, 186, 58, 133,
        44, 170, 64, 156, 60, 186, 123, 249, 249, 15, 42, 188, 65, 29, 77, 158, 126, 219, 160, 46,
        214, 189, 31, 245, 158, 146, 26, 81, 216, 238, 116, 110, 52, 62, 4, 171, 115, 245, 65, 124,
        249, 62, 180, 216, 127, 196, 30, 107, 141, 253, 236, 105, 162, 234, 229, 141, 55, 39, 166,
        22, 248, 21, 220, 179, 247, 106, 82, 174, 21, 99, 128, 92, 69, 64, 161, 63, 78, 242, 245,
        119, 197, 109, 188, 129, 84, 33, 125, 193, 2, 129, 128, 2, 22, 224, 241, 227, 238, 252,
        177, 158, 29, 0, 58, 113, 241, 59, 46, 228, 111, 98, 75, 242, 3, 142, 88, 159, 135, 228,
        233, 73, 115, 184, 26, 32, 60, 195, 100, 181, 72, 224, 213, 32, 225, 24, 158, 61, 158, 244,
        14, 6, 10, 224, 37, 7, 28, 12, 60, 237, 24, 173, 37, 80, 169, 99, 134, 101, 33, 214, 59,
        70, 67, 196, 169, 145, 228, 142, 57, 231, 194, 57, 152, 26, 179, 74, 8, 254, 243, 179, 163,
        49, 126, 165, 186, 1, 161, 107, 56, 232, 232, 160, 216, 215, 241, 31, 106, 168, 35, 186,
        151, 150, 33, 79, 141, 53, 29, 225, 64, 197, 181, 143, 49, 20, 188, 126, 13, 93, 200, 215,
        131, 2, 129, 129, 0, 184, 95, 228, 10, 187, 236, 81, 178, 174, 54, 228, 162, 142, 66, 3,
        16, 70, 20, 111, 164, 11, 168, 193, 184, 124, 114, 227, 109, 226, 190, 18, 121, 174, 153,
        93, 170, 229, 227, 164, 151, 251, 228, 194, 183, 78, 201, 15, 160, 252, 199, 194, 65, 124,
        140, 123, 206, 60, 217, 162, 229, 28, 193, 104, 145, 172, 192, 104, 31, 3, 210, 103, 255,
        136, 210, 233, 17, 161, 60, 176, 118, 222, 48, 35, 60, 17, 158, 196, 84, 188, 65, 62, 168,
        247, 60, 102, 61, 75, 44, 183, 179, 59, 47, 72, 104, 50, 119, 235, 99, 100, 213, 184, 184,
        162, 214, 20, 78, 65, 221, 117, 13, 252, 243, 215, 132, 70, 187, 220, 102,
    ];
    const KEY_3072_DER: &[u8] = &[
        48, 130, 6, 226, 2, 1, 0, 2, 130, 1, 129, 0, 155, 69, 225, 22, 239, 215, 79, 0, 17, 159,
        134, 82, 201, 185, 29, 120, 240, 88, 97, 67, 65, 176, 15, 9, 68, 82, 252, 33, 152, 195, 70,
        57, 191, 35, 250, 205, 196, 55, 160, 29, 119, 31, 171, 232, 196, 138, 103, 228, 127, 60,
        194, 0, 135, 113, 244, 219, 109, 143, 54, 0, 115, 137, 70, 96, 23, 118, 104, 217, 199, 83,
        110, 69, 3, 47, 75, 14, 87, 27, 136, 147, 140, 198, 158, 223, 140, 231, 116, 181, 175, 191,
        55, 126, 173, 26, 229, 64, 3, 73, 243, 24, 42, 246, 47, 113, 105, 225, 231, 36, 54, 60, 54,
        72, 57, 252, 125, 121, 159, 205, 242, 193, 127, 18, 190, 95, 160, 72, 97, 43, 201, 239,
        111, 162, 164, 86, 212, 53, 175, 27, 242, 181, 166, 132, 207, 87, 208, 201, 123, 40, 27,
        30, 43, 199, 206, 216, 50, 218, 235, 148, 74, 251, 104, 242, 119, 88, 201, 131, 57, 160,
        117, 142, 210, 244, 81, 203, 180, 120, 150, 24, 222, 174, 82, 53, 82, 226, 140, 21, 16,
        153, 167, 173, 214, 208, 158, 233, 178, 138, 201, 14, 251, 6, 157, 190, 11, 161, 253, 199,
        3, 103, 129, 78, 189, 203, 174, 152, 172, 221, 70, 27, 205, 224, 70, 32, 247, 58, 237, 195,
        165, 23, 203, 202, 184, 3, 8, 128, 116, 60, 198, 40, 222, 211, 58, 235, 10, 24, 49, 229,
        63, 112, 250, 93, 116, 69, 203, 42, 111, 205, 205, 104, 80, 54, 9, 108, 233, 107, 222, 202,
        101, 51, 27, 99, 76, 68, 136, 121, 36, 21, 252, 99, 134, 91, 211, 73, 187, 226, 253, 239,
        246, 212, 239, 25, 224, 43, 92, 110, 47, 14, 63, 236, 130, 218, 51, 242, 118, 175, 113,
        169, 26, 177, 11, 58, 41, 142, 19, 184, 184, 4, 34, 13, 37, 111, 166, 236, 136, 191, 70,
        218, 224, 10, 96, 113, 46, 117, 194, 99, 203, 204, 54, 98, 221, 89, 30, 194, 216, 26, 98,
        170, 229, 25, 172, 148, 236, 211, 120, 254, 236, 246, 191, 156, 74, 224, 193, 78, 12, 235,
        76, 0, 171, 164, 70, 172, 172, 30, 32, 31, 190, 53, 78, 130, 115, 4, 156, 159, 93, 113, 2,
        3, 1, 0, 1, 2, 130, 1, 127, 27, 63, 80, 222, 190, 109, 29, 145, 163, 190, 241, 202, 117,
        88, 29, 206, 142, 194, 44, 121, 226, 181, 238, 237, 140, 10, 124, 212, 40, 117, 42, 49, 45,
        84, 54, 144, 147, 110, 54, 147, 159, 199, 102, 33, 155, 134, 95, 241, 76, 134, 55, 154, 99,
        184, 132, 129, 32, 140, 59, 171, 241, 125, 234, 185, 210, 14, 222, 55, 103, 104, 94, 97,
        86, 203, 244, 1, 156, 167, 146, 234, 152, 171, 87, 107, 38, 212, 26, 143, 206, 144, 68,
        234, 251, 42, 219, 76, 83, 242, 22, 35, 9, 88, 187, 247, 5, 166, 124, 242, 28, 11, 56, 116,
        55, 198, 245, 54, 185, 178, 125, 204, 79, 165, 156, 41, 196, 152, 125, 45, 172, 163, 196,
        35, 75, 168, 191, 59, 151, 29, 43, 20, 227, 137, 17, 224, 163, 143, 69, 235, 151, 86, 164,
        13, 120, 124, 244, 97, 107, 163, 223, 139, 180, 7, 202, 52, 93, 253, 163, 200, 13, 131,
        189, 82, 222, 213, 233, 55, 71, 17, 103, 244, 0, 245, 136, 194, 102, 199, 239, 21, 92, 252,
        184, 12, 97, 128, 215, 16, 2, 140, 61, 180, 202, 151, 234, 3, 82, 81, 131, 24, 130, 169,
        145, 49, 171, 4, 11, 48, 38, 120, 218, 92, 55, 170, 18, 242, 76, 162, 203, 33, 232, 105,
        20, 25, 212, 205, 208, 65, 18, 45, 154, 202, 92, 32, 32, 59, 173, 254, 254, 11, 252, 113,
        107, 213, 249, 109, 58, 141, 198, 32, 110, 141, 196, 103, 124, 45, 64, 108, 197, 166, 160,
        156, 46, 213, 91, 97, 63, 138, 67, 108, 210, 196, 185, 239, 69, 67, 3, 213, 250, 64, 54, 9,
        217, 247, 233, 89, 126, 227, 77, 163, 210, 167, 217, 201, 45, 24, 12, 4, 138, 99, 117, 197,
        27, 246, 196, 50, 144, 38, 53, 94, 241, 12, 167, 107, 252, 158, 115, 1, 136, 246, 213, 137,
        56, 213, 90, 9, 101, 216, 145, 251, 91, 245, 23, 114, 53, 98, 163, 249, 42, 170, 222, 69,
        160, 123, 67, 239, 43, 204, 121, 173, 249, 159, 172, 250, 173, 139, 204, 116, 224, 249,
        211, 246, 167, 218, 209, 165, 30, 228, 162, 151, 176, 145, 107, 79, 65, 2, 129, 193, 0,
        205, 28, 161, 12, 105, 111, 136, 213, 131, 173, 127, 108, 40, 166, 210, 202, 150, 93, 193,
        183, 27, 203, 113, 143, 158, 37, 168, 120, 119, 179, 44, 107, 170, 201, 130, 91, 56, 101,
        24, 233, 44, 31, 245, 32, 240, 185, 15, 141, 7, 255, 201, 82, 12, 207, 211, 81, 19, 75,
        104, 15, 84, 6, 150, 55, 207, 210, 172, 81, 112, 172, 202, 131, 137, 94, 128, 222, 19, 115,
        1, 7, 153, 239, 224, 26, 72, 119, 80, 121, 2, 252, 116, 58, 82, 139, 127, 141, 101, 110,
        60, 90, 225, 3, 42, 71, 248, 255, 107, 211, 23, 142, 25, 152, 69, 78, 6, 76, 184, 59, 212,
        113, 26, 84, 208, 191, 185, 76, 74, 96, 185, 108, 210, 126, 216, 4, 249, 87, 60, 145, 36,
        9, 9, 114, 27, 55, 245, 72, 97, 88, 153, 230, 145, 184, 144, 48, 30, 208, 12, 166, 152,
        123, 163, 93, 142, 230, 217, 204, 148, 142, 51, 110, 90, 217, 89, 224, 102, 153, 194, 190,
        179, 210, 76, 14, 67, 150, 24, 10, 56, 187, 187, 113, 200, 177, 2, 129, 193, 0, 193, 203,
        207, 38, 88, 169, 136, 23, 171, 85, 36, 253, 133, 172, 111, 160, 201, 86, 63, 6, 155, 249,
        106, 107, 198, 39, 71, 22, 152, 170, 188, 134, 116, 185, 228, 189, 63, 177, 52, 129, 57,
        224, 123, 156, 141, 32, 75, 142, 27, 167, 98, 250, 198, 250, 103, 23, 132, 90, 102, 192,
        16, 65, 214, 75, 56, 170, 252, 26, 59, 91, 242, 153, 67, 59, 101, 230, 22, 21, 58, 108,
        180, 247, 222, 16, 34, 196, 168, 86, 82, 145, 72, 233, 245, 252, 100, 27, 94, 18, 247, 60,
        62, 225, 10, 119, 22, 195, 217, 18, 180, 186, 1, 105, 82, 148, 152, 109, 168, 244, 51, 226,
        92, 201, 231, 231, 43, 147, 183, 199, 28, 132, 125, 79, 142, 238, 13, 45, 55, 189, 95, 6,
        82, 101, 215, 20, 106, 155, 138, 20, 129, 196, 255, 71, 147, 24, 230, 125, 88, 145, 183,
        75, 211, 26, 79, 61, 103, 97, 28, 60, 144, 14, 172, 27, 208, 121, 63, 135, 147, 110, 122,
        127, 208, 109, 202, 168, 213, 233, 207, 221, 247, 12, 16, 193, 2, 129, 192, 52, 73, 191,
        24, 141, 236, 92, 2, 170, 77, 217, 116, 246, 44, 9, 2, 146, 48, 150, 136, 154, 114, 83,
        161, 220, 28, 23, 133, 150, 102, 59, 197, 186, 197, 34, 17, 37, 32, 72, 168, 112, 146, 57,
        8, 75, 181, 177, 172, 47, 68, 218, 202, 170, 239, 116, 28, 112, 1, 194, 38, 94, 50, 75,
        171, 48, 180, 177, 47, 21, 189, 70, 231, 31, 102, 211, 13, 74, 2, 0, 90, 50, 184, 254, 245,
        84, 81, 238, 86, 219, 23, 6, 126, 51, 186, 210, 42, 118, 152, 18, 148, 204, 85, 229, 58,
        113, 212, 147, 101, 61, 213, 0, 219, 91, 151, 151, 109, 137, 109, 223, 43, 114, 29, 251,
        21, 85, 36, 136, 181, 125, 175, 171, 61, 160, 206, 43, 206, 60, 103, 119, 187, 66, 8, 47,
        190, 37, 46, 109, 122, 139, 201, 70, 142, 185, 91, 59, 15, 168, 153, 243, 183, 89, 31, 41,
        165, 218, 18, 24, 48, 228, 21, 150, 221, 95, 215, 31, 240, 196, 191, 158, 209, 214, 135,
        176, 93, 28, 5, 199, 14, 188, 171, 54, 17, 2, 129, 193, 0, 137, 6, 20, 7, 166, 244, 231,
        150, 228, 187, 165, 21, 228, 104, 17, 221, 123, 190, 17, 126, 24, 214, 119, 90, 144, 150,
        192, 250, 199, 35, 33, 125, 104, 22, 240, 22, 167, 108, 34, 21, 164, 216, 134, 78, 32, 178,
        206, 249, 65, 176, 78, 153, 198, 10, 210, 205, 155, 245, 87, 101, 65, 153, 107, 109, 112,
        57, 229, 90, 158, 209, 218, 108, 103, 79, 30, 51, 91, 53, 211, 67, 125, 137, 44, 103, 248,
        77, 88, 65, 0, 204, 92, 227, 159, 219, 190, 228, 98, 213, 194, 29, 196, 207, 213, 88, 114,
        174, 51, 83, 184, 153, 51, 218, 70, 91, 110, 147, 74, 188, 175, 218, 195, 132, 183, 5, 138,
        152, 61, 126, 249, 56, 236, 105, 78, 68, 30, 232, 243, 218, 95, 207, 214, 126, 207, 94, 78,
        42, 127, 173, 20, 60, 55, 203, 97, 196, 95, 100, 13, 53, 170, 134, 96, 82, 223, 232, 40,
        170, 79, 14, 187, 68, 196, 136, 62, 21, 28, 200, 61, 132, 5, 245, 77, 103, 243, 189, 0,
        210, 250, 248, 148, 110, 225, 129, 2, 129, 192, 69, 98, 60, 131, 116, 202, 195, 242, 78,
        179, 132, 128, 252, 241, 35, 98, 23, 138, 45, 146, 103, 203, 31, 236, 138, 167, 173, 196,
        1, 3, 114, 249, 44, 44, 152, 117, 0, 40, 88, 229, 244, 148, 134, 118, 171, 188, 148, 117,
        252, 45, 48, 41, 236, 48, 158, 104, 211, 141, 171, 80, 112, 247, 25, 20, 163, 152, 215, 37,
        198, 207, 97, 131, 223, 51, 190, 237, 224, 192, 161, 56, 153, 8, 108, 177, 34, 33, 249,
        246, 28, 207, 240, 166, 125, 245, 138, 156, 52, 175, 110, 62, 115, 199, 41, 16, 3, 216,
        136, 25, 216, 45, 234, 147, 248, 28, 78, 211, 84, 32, 74, 2, 111, 24, 167, 97, 124, 8, 141,
        72, 28, 176, 29, 244, 232, 13, 79, 1, 147, 247, 6, 54, 227, 140, 114, 236, 252, 249, 161,
        47, 60, 109, 36, 33, 84, 39, 219, 207, 70, 118, 35, 239, 54, 157, 48, 25, 45, 67, 96, 207,
        41, 55, 250, 163, 13, 210, 129, 21, 243, 68, 249, 5, 81, 246, 90, 249, 208, 245, 206, 233,
        249, 4, 220, 17,
    ];
    const KEY_4096_DER: &[u8] = &[
        48, 130, 9, 41, 2, 1, 0, 2, 130, 2, 1, 0, 212, 243, 31, 159, 115, 114, 245, 235, 24, 70,
        183, 24, 37, 250, 171, 195, 176, 232, 35, 171, 96, 190, 224, 166, 7, 80, 214, 67, 47, 127,
        108, 90, 119, 62, 204, 183, 15, 64, 27, 74, 52, 126, 24, 179, 30, 126, 170, 13, 119, 0, 16,
        21, 3, 14, 244, 247, 208, 9, 79, 30, 196, 208, 238, 0, 167, 105, 144, 59, 214, 27, 103,
        145, 0, 59, 77, 152, 243, 245, 40, 115, 120, 48, 209, 121, 179, 126, 4, 4, 224, 117, 226,
        34, 169, 107, 203, 84, 26, 203, 223, 47, 43, 47, 218, 35, 164, 222, 152, 215, 3, 192, 133,
        10, 109, 211, 90, 167, 167, 181, 236, 17, 197, 14, 150, 55, 178, 60, 123, 252, 111, 142,
        214, 38, 31, 14, 20, 211, 86, 78, 150, 131, 181, 31, 130, 198, 6, 0, 211, 38, 12, 228, 57,
        178, 140, 232, 200, 78, 253, 80, 19, 72, 108, 18, 79, 217, 48, 210, 209, 195, 185, 159, 53,
        81, 159, 64, 103, 44, 149, 227, 163, 66, 13, 234, 4, 11, 167, 254, 206, 143, 204, 159, 178,
        147, 110, 243, 243, 208, 52, 139, 87, 175, 134, 204, 39, 148, 243, 238, 100, 49, 101, 61,
        78, 228, 250, 109, 114, 15, 221, 80, 131, 111, 17, 214, 82, 99, 148, 111, 230, 94, 25, 219,
        46, 159, 102, 97, 188, 84, 77, 119, 111, 145, 54, 8, 48, 142, 155, 61, 168, 102, 227, 202,
        8, 2, 195, 21, 153, 62, 218, 124, 168, 175, 89, 70, 133, 202, 224, 22, 250, 99, 24, 231,
        137, 178, 164, 95, 7, 52, 242, 211, 234, 138, 64, 74, 16, 203, 85, 244, 190, 133, 108, 56,
        30, 26, 205, 78, 238, 29, 220, 79, 223, 146, 158, 175, 214, 253, 17, 98, 106, 25, 122, 92,
        137, 237, 219, 127, 7, 253, 70, 173, 179, 217, 126, 239, 35, 8, 237, 104, 50, 15, 122, 235,
        147, 64, 46, 224, 136, 137, 209, 187, 126, 128, 100, 240, 254, 243, 107, 85, 78, 160, 231,
        25, 208, 117, 6, 149, 219, 38, 169, 203, 136, 234, 174, 95, 146, 33, 16, 152, 32, 171, 174,
        197, 241, 2, 120, 206, 203, 107, 195, 22, 155, 154, 135, 4, 44, 12, 38, 243, 100, 11, 73,
        50, 12, 161, 122, 140, 24, 82, 156, 113, 111, 123, 113, 105, 12, 190, 133, 147, 18, 73,
        160, 165, 61, 111, 233, 34, 138, 89, 233, 234, 129, 234, 149, 105, 205, 226, 62, 222, 80,
        250, 249, 158, 12, 17, 136, 38, 218, 105, 87, 131, 129, 141, 66, 68, 237, 123, 83, 149,
        133, 75, 141, 0, 36, 141, 150, 89, 161, 179, 187, 8, 122, 98, 200, 209, 46, 33, 248, 68,
        189, 239, 246, 194, 165, 208, 220, 85, 215, 119, 97, 16, 114, 60, 143, 226, 147, 107, 196,
        176, 21, 77, 216, 199, 107, 39, 2, 198, 128, 239, 237, 229, 223, 35, 104, 55, 225, 184,
        122, 209, 219, 60, 1, 51, 4, 255, 2, 3, 1, 0, 1, 2, 130, 2, 0, 36, 91, 172, 83, 7, 157,
        161, 178, 53, 143, 97, 84, 124, 171, 139, 103, 26, 141, 208, 5, 67, 59, 227, 212, 69, 28,
        126, 176, 178, 235, 225, 30, 163, 12, 116, 92, 110, 252, 165, 140, 42, 97, 59, 43, 93, 242,
        7, 107, 204, 29, 21, 33, 217, 71, 84, 248, 248, 170, 150, 57, 45, 38, 116, 244, 100, 161,
        7, 240, 199, 114, 31, 97, 40, 246, 119, 29, 189, 205, 102, 78, 44, 191, 189, 12, 55, 226,
        180, 161, 246, 134, 250, 8, 171, 255, 141, 20, 59, 141, 2, 122, 165, 183, 130, 89, 162,
        157, 36, 224, 85, 50, 42, 36, 233, 50, 116, 96, 122, 168, 123, 121, 95, 57, 73, 217, 145,
        147, 117, 33, 217, 20, 60, 168, 254, 149, 99, 101, 223, 239, 4, 16, 209, 188, 99, 18, 23,
        85, 77, 183, 201, 236, 175, 147, 54, 46, 202, 128, 126, 12, 141, 118, 72, 137, 105, 219,
        173, 211, 216, 223, 191, 146, 24, 194, 234, 91, 79, 34, 84, 39, 45, 41, 42, 130, 1, 149,
        209, 229, 149, 244, 4, 94, 97, 217, 125, 80, 166, 152, 174, 87, 250, 45, 44, 105, 47, 250,
        229, 25, 23, 63, 61, 199, 85, 112, 143, 247, 94, 201, 169, 162, 69, 6, 146, 55, 147, 18,
        144, 117, 248, 145, 169, 125, 124, 60, 215, 248, 168, 244, 133, 211, 118, 23, 135, 111,
        167, 134, 185, 167, 177, 216, 123, 92, 243, 184, 49, 1, 191, 139, 165, 122, 95, 181, 71,
        212, 50, 239, 97, 70, 40, 91, 124, 35, 78, 156, 116, 94, 222, 42, 232, 20, 2, 17, 166, 121,
        48, 217, 112, 204, 192, 50, 111, 22, 197, 45, 15, 236, 57, 145, 114, 137, 54, 247, 207,
        224, 138, 179, 83, 57, 200, 87, 98, 138, 157, 123, 78, 7, 42, 193, 204, 156, 82, 199, 86,
        34, 157, 219, 64, 140, 224, 169, 29, 103, 191, 171, 44, 102, 47, 235, 195, 176, 81, 25, 46,
        66, 197, 253, 167, 251, 106, 76, 79, 140, 177, 14, 147, 37, 62, 94, 165, 235, 47, 157, 183,
        95, 100, 72, 131, 242, 145, 197, 233, 9, 79, 169, 102, 204, 228, 83, 144, 232, 92, 48, 151,
        144, 241, 190, 12, 21, 215, 157, 135, 123, 22, 50, 210, 147, 21, 132, 220, 233, 207, 100,
        123, 237, 62, 33, 18, 59, 153, 3, 103, 254, 221, 246, 0, 202, 156, 171, 247, 163, 108, 252,
        215, 246, 175, 53, 30, 190, 127, 38, 222, 191, 42, 96, 54, 181, 76, 9, 30, 176, 174, 188,
        130, 105, 16, 69, 139, 232, 238, 157, 193, 48, 62, 71, 247, 21, 241, 156, 249, 12, 207,
        225, 146, 34, 2, 50, 30, 80, 152, 62, 114, 16, 123, 83, 46, 28, 158, 104, 194, 218, 238,
        52, 70, 196, 86, 5, 72, 131, 23, 62, 114, 94, 94, 237, 195, 246, 216, 98, 33, 38, 27, 131,
        249, 78, 1, 233, 191, 64, 18, 60, 94, 136, 146, 25, 2, 130, 1, 1, 0, 236, 211, 131, 146,
        240, 45, 145, 98, 205, 182, 225, 215, 62, 49, 16, 168, 202, 89, 209, 217, 137, 72, 93, 196,
        26, 126, 188, 198, 233, 242, 196, 223, 223, 24, 98, 217, 164, 139, 44, 197, 66, 184, 224,
        58, 214, 92, 57, 240, 74, 97, 75, 15, 75, 210, 34, 248, 99, 12, 85, 88, 186, 143, 16, 95,
        212, 174, 113, 73, 47, 82, 210, 75, 215, 111, 4, 102, 191, 83, 238, 139, 233, 140, 182, 49,
        1, 170, 111, 188, 221, 148, 220, 15, 165, 156, 45, 112, 200, 221, 119, 94, 186, 11, 104,
        106, 155, 204, 55, 107, 252, 222, 228, 91, 137, 157, 179, 187, 253, 240, 81, 137, 247, 206,
        130, 163, 248, 208, 122, 201, 213, 6, 161, 110, 139, 235, 174, 83, 29, 224, 13, 67, 119,
        82, 230, 209, 34, 187, 182, 11, 147, 138, 43, 17, 99, 99, 159, 101, 129, 34, 194, 49, 175,
        245, 76, 194, 112, 14, 11, 156, 242, 117, 144, 80, 97, 96, 194, 26, 154, 107, 42, 171, 248,
        130, 70, 213, 53, 142, 73, 162, 114, 175, 191, 130, 188, 129, 63, 171, 232, 238, 45, 208,
        70, 178, 217, 14, 99, 21, 229, 186, 83, 238, 35, 99, 125, 202, 59, 169, 179, 171, 127, 245,
        7, 69, 22, 31, 165, 182, 159, 12, 211, 143, 48, 126, 48, 159, 242, 54, 86, 119, 230, 232,
        186, 89, 110, 176, 129, 219, 140, 239, 153, 113, 70, 121, 126, 25, 207, 217, 2, 130, 1, 1,
        0, 230, 48, 189, 251, 113, 15, 72, 79, 220, 135, 157, 154, 220, 225, 43, 133, 19, 126, 212,
        132, 100, 198, 225, 213, 63, 28, 240, 175, 214, 26, 81, 109, 120, 35, 189, 151, 139, 233,
        246, 116, 109, 236, 29, 252, 248, 49, 37, 37, 113, 50, 29, 61, 110, 185, 253, 55, 65, 246,
        155, 248, 137, 165, 95, 133, 173, 163, 203, 11, 85, 228, 52, 2, 83, 15, 91, 87, 9, 163,
        197, 45, 32, 56, 212, 190, 163, 94, 252, 237, 210, 195, 109, 65, 32, 133, 205, 80, 31, 239,
        190, 130, 47, 62, 12, 199, 250, 240, 134, 25, 68, 192, 29, 244, 33, 190, 66, 221, 64, 48,
        175, 250, 185, 243, 233, 219, 112, 64, 197, 156, 25, 124, 99, 45, 90, 76, 167, 232, 154,
        108, 106, 107, 24, 121, 146, 124, 33, 139, 60, 162, 19, 93, 114, 6, 37, 122, 173, 115, 205,
        89, 66, 200, 217, 146, 161, 225, 147, 249, 204, 222, 50, 124, 45, 204, 225, 109, 93, 144,
        22, 99, 94, 154, 75, 6, 94, 7, 20, 148, 254, 46, 71, 182, 228, 205, 180, 23, 138, 109, 32,
        31, 166, 191, 223, 222, 105, 83, 88, 59, 60, 59, 4, 90, 216, 169, 197, 224, 224, 7, 252,
        251, 187, 96, 129, 220, 161, 189, 60, 180, 33, 255, 222, 130, 25, 92, 199, 231, 4, 65, 149,
        237, 226, 203, 72, 22, 144, 163, 27, 241, 88, 141, 199, 255, 100, 165, 194, 77, 76, 151, 2,
        130, 1, 1, 0, 233, 52, 147, 80, 227, 79, 139, 229, 198, 122, 187, 67, 112, 75, 114, 131,
        51, 215, 100, 204, 152, 225, 248, 235, 125, 199, 165, 111, 30, 186, 223, 225, 47, 215, 220,
        167, 66, 223, 133, 179, 173, 179, 77, 162, 194, 169, 72, 168, 117, 37, 255, 122, 205, 135,
        220, 197, 201, 11, 65, 19, 193, 137, 213, 110, 248, 136, 218, 167, 93, 129, 105, 242, 34,
        239, 128, 95, 9, 50, 198, 41, 98, 79, 28, 173, 127, 93, 108, 240, 135, 37, 233, 217, 66,
        148, 91, 46, 191, 173, 77, 185, 170, 236, 70, 227, 12, 13, 249, 217, 77, 197, 211, 10, 204,
        165, 205, 114, 102, 105, 250, 113, 40, 227, 99, 67, 194, 100, 209, 52, 228, 159, 197, 225,
        140, 201, 4, 253, 117, 226, 198, 76, 212, 56, 127, 112, 27, 138, 202, 133, 245, 192, 78,
        14, 174, 87, 80, 131, 236, 184, 228, 143, 119, 28, 207, 124, 124, 73, 104, 104, 33, 93, 97,
        65, 181, 210, 72, 241, 87, 116, 6, 46, 23, 229, 121, 136, 196, 87, 27, 237, 106, 143, 227,
        191, 2, 143, 39, 186, 202, 1, 152, 125, 138, 208, 220, 234, 204, 233, 168, 49, 102, 42,
        143, 16, 142, 178, 209, 51, 151, 232, 94, 117, 83, 182, 85, 69, 206, 177, 217, 71, 17, 32,
        228, 120, 174, 187, 34, 17, 29, 238, 174, 36, 40, 52, 158, 202, 18, 229, 182, 143, 206, 2,
        124, 138, 112, 129, 76, 105, 2, 130, 1, 1, 0, 212, 226, 139, 49, 57, 148, 138, 169, 225,
        40, 66, 231, 240, 19, 6, 174, 162, 35, 15, 228, 9, 87, 173, 144, 12, 56, 117, 152, 9, 8,
        121, 250, 37, 187, 216, 33, 137, 178, 44, 205, 236, 195, 11, 208, 226, 176, 128, 204, 41,
        237, 209, 0, 249, 160, 100, 192, 111, 238, 228, 188, 108, 128, 86, 225, 72, 127, 76, 207,
        4, 246, 113, 235, 28, 105, 253, 109, 119, 106, 208, 118, 53, 112, 153, 192, 93, 83, 1, 211,
        232, 177, 248, 30, 221, 55, 33, 116, 82, 180, 228, 153, 125, 155, 131, 50, 135, 175, 94,
        53, 140, 81, 168, 226, 25, 58, 222, 151, 196, 63, 194, 224, 188, 141, 9, 224, 121, 230, 77,
        91, 90, 110, 161, 66, 86, 90, 194, 134, 234, 26, 14, 41, 81, 143, 77, 156, 35, 97, 164, 7,
        184, 165, 25, 72, 249, 236, 132, 241, 174, 30, 57, 23, 139, 176, 130, 170, 30, 178, 77,
        119, 201, 116, 242, 222, 162, 53, 4, 236, 182, 231, 219, 156, 18, 122, 167, 7, 33, 79, 209,
        235, 119, 67, 124, 67, 137, 164, 163, 206, 220, 128, 169, 52, 150, 148, 25, 16, 141, 110,
        234, 251, 33, 193, 234, 210, 200, 64, 122, 176, 168, 149, 30, 235, 215, 237, 246, 95, 14,
        255, 0, 218, 164, 43, 233, 204, 214, 203, 158, 50, 17, 184, 217, 160, 106, 225, 3, 142,
        245, 206, 180, 185, 27, 23, 229, 59, 47, 129, 81, 173, 2, 130, 1, 0, 76, 130, 74, 244, 89,
        158, 116, 139, 71, 176, 72, 4, 245, 245, 121, 88, 62, 249, 41, 189, 201, 58, 73, 84, 108,
        247, 245, 113, 142, 200, 57, 134, 91, 167, 112, 73, 2, 51, 231, 120, 242, 111, 205, 145,
        149, 216, 33, 117, 134, 198, 123, 192, 167, 54, 61, 149, 232, 95, 241, 187, 3, 163, 143,
        212, 29, 50, 144, 202, 225, 247, 125, 67, 32, 94, 172, 94, 208, 48, 238, 215, 140, 77, 92,
        141, 175, 214, 13, 151, 208, 27, 220, 34, 195, 144, 194, 80, 181, 81, 218, 1, 113, 64, 55,
        72, 71, 107, 183, 181, 0, 45, 131, 5, 208, 50, 57, 17, 218, 116, 153, 6, 107, 213, 22, 7,
        248, 125, 205, 232, 229, 101, 86, 148, 216, 74, 166, 81, 10, 202, 160, 56, 61, 249, 238,
        244, 208, 100, 110, 220, 160, 99, 254, 177, 204, 166, 171, 235, 216, 23, 29, 94, 228, 195,
        217, 208, 227, 33, 63, 244, 195, 243, 51, 90, 248, 14, 197, 73, 109, 103, 0, 192, 94, 73,
        83, 110, 112, 252, 245, 51, 211, 103, 9, 188, 253, 235, 20, 57, 48, 76, 243, 100, 69, 134,
        85, 71, 221, 11, 73, 158, 132, 174, 149, 61, 220, 138, 77, 185, 180, 62, 0, 47, 161, 123,
        197, 210, 179, 27, 106, 141, 5, 187, 120, 162, 11, 149, 11, 103, 0, 170, 197, 69, 135, 79,
        102, 28, 77, 103, 193, 98, 66, 180, 95, 91, 160, 227, 183, 89,
    ];
    const KEY_6144_DER: &[u8] = &[
        48, 130, 13, 169, 2, 1, 0, 2, 130, 3, 1, 0, 210, 50, 84, 75, 14, 67, 87, 178, 163, 146, 17,
        76, 126, 24, 137, 87, 161, 145, 154, 204, 108, 83, 237, 24, 99, 154, 10, 184, 17, 182, 63,
        110, 1, 172, 87, 7, 238, 174, 106, 121, 19, 18, 166, 166, 17, 144, 68, 57, 204, 17, 56,
        228, 46, 189, 159, 53, 238, 16, 39, 46, 228, 183, 32, 241, 59, 114, 172, 210, 48, 1, 130,
        114, 188, 65, 215, 20, 192, 33, 231, 169, 29, 170, 47, 98, 96, 128, 15, 173, 93, 167, 239,
        87, 242, 224, 57, 199, 11, 18, 191, 108, 38, 67, 75, 154, 104, 89, 231, 255, 119, 111, 132,
        136, 233, 110, 110, 194, 38, 203, 48, 35, 18, 44, 89, 222, 213, 74, 67, 74, 109, 124, 123,
        74, 94, 51, 229, 1, 45, 147, 53, 184, 20, 5, 82, 51, 7, 77, 84, 33, 123, 1, 167, 185, 189,
        36, 198, 69, 245, 47, 72, 205, 169, 83, 36, 183, 191, 88, 113, 87, 213, 154, 135, 242, 127,
        231, 216, 236, 54, 35, 86, 160, 252, 173, 34, 82, 130, 140, 14, 250, 15, 177, 220, 130,
        192, 89, 83, 251, 61, 53, 5, 205, 64, 246, 41, 113, 221, 63, 111, 123, 221, 189, 141, 157,
        116, 10, 206, 31, 122, 67, 76, 176, 64, 139, 79, 195, 150, 168, 123, 85, 2, 2, 20, 167,
        236, 49, 249, 106, 21, 143, 170, 40, 9, 211, 73, 150, 142, 21, 230, 22, 74, 220, 137, 26,
        106, 185, 238, 68, 29, 51, 234, 122, 122, 37, 239, 230, 227, 129, 97, 170, 123, 57, 222,
        131, 123, 197, 61, 226, 203, 55, 182, 14, 78, 224, 181, 77, 18, 240, 219, 131, 87, 161,
        235, 243, 123, 228, 168, 197, 126, 219, 141, 133, 140, 185, 28, 177, 53, 28, 96, 213, 249,
        185, 88, 111, 166, 30, 233, 16, 149, 176, 203, 195, 200, 108, 24, 202, 96, 204, 105, 87,
        210, 102, 103, 45, 200, 117, 181, 94, 117, 46, 92, 120, 219, 194, 163, 199, 212, 14, 22,
        179, 160, 212, 145, 192, 124, 145, 206, 233, 9, 157, 92, 253, 208, 237, 232, 94, 77, 111,
        5, 254, 19, 137, 102, 57, 127, 148, 165, 201, 43, 34, 107, 241, 34, 79, 143, 190, 137, 196,
        21, 248, 90, 50, 109, 151, 106, 145, 79, 149, 74, 136, 162, 14, 30, 118, 44, 36, 179, 91,
        20, 253, 186, 174, 247, 153, 49, 178, 70, 32, 5, 15, 78, 197, 2, 60, 103, 0, 120, 234, 111,
        232, 79, 77, 186, 101, 137, 244, 56, 99, 171, 4, 238, 130, 75, 152, 60, 70, 134, 97, 155,
        76, 31, 64, 161, 4, 136, 170, 54, 227, 237, 102, 122, 114, 176, 88, 191, 250, 151, 64, 185,
        94, 240, 226, 36, 154, 49, 234, 175, 239, 238, 141, 138, 166, 131, 77, 199, 164, 250, 187,
        1, 27, 53, 235, 56, 126, 165, 224, 249, 165, 56, 182, 100, 199, 198, 160, 19, 11, 107, 255,
        115, 166, 47, 3, 82, 190, 59, 103, 189, 104, 79, 181, 254, 203, 66, 73, 121, 221, 138, 163,
        5, 80, 124, 29, 25, 140, 222, 128, 35, 113, 32, 84, 231, 189, 103, 93, 193, 220, 236, 145,
        185, 227, 211, 191, 75, 221, 26, 159, 88, 42, 119, 52, 78, 221, 234, 171, 128, 64, 174, 43,
        227, 131, 158, 237, 138, 173, 143, 147, 31, 195, 43, 92, 46, 246, 109, 10, 209, 225, 237,
        226, 32, 111, 53, 239, 221, 33, 69, 171, 169, 87, 13, 172, 196, 153, 133, 118, 252, 195,
        102, 224, 240, 30, 126, 28, 21, 33, 243, 234, 194, 79, 114, 182, 165, 188, 3, 111, 185,
        159, 175, 134, 68, 75, 183, 13, 138, 15, 174, 138, 231, 8, 0, 255, 149, 252, 97, 124, 120,
        161, 125, 133, 13, 99, 15, 126, 220, 47, 54, 51, 74, 98, 2, 7, 122, 179, 36, 169, 232, 243,
        110, 204, 217, 131, 171, 17, 134, 238, 95, 55, 52, 166, 55, 103, 224, 222, 224, 240, 73,
        181, 89, 228, 196, 82, 38, 215, 119, 236, 30, 125, 5, 100, 107, 62, 234, 64, 77, 119, 65,
        166, 65, 217, 195, 21, 58, 119, 76, 200, 232, 153, 151, 70, 81, 34, 35, 11, 131, 128, 8,
        131, 80, 196, 22, 34, 139, 80, 164, 219, 23, 222, 208, 97, 120, 213, 104, 226, 162, 19, 90,
        38, 125, 142, 53, 123, 73, 112, 34, 61, 173, 148, 230, 13, 103, 139, 36, 190, 223, 227,
        247, 180, 69, 69, 156, 83, 2, 3, 1, 0, 1, 2, 130, 3, 0, 8, 0, 39, 106, 53, 240, 69, 65,
        196, 237, 21, 224, 121, 250, 56, 28, 16, 71, 201, 3, 23, 234, 119, 223, 82, 71, 54, 58, 60,
        94, 89, 250, 183, 112, 150, 93, 116, 109, 202, 26, 178, 169, 166, 147, 50, 158, 241, 161,
        219, 141, 26, 67, 193, 45, 177, 134, 45, 122, 10, 235, 195, 131, 222, 234, 159, 175, 37,
        57, 216, 222, 237, 214, 173, 40, 186, 101, 141, 76, 157, 19, 56, 80, 86, 126, 97, 154, 238,
        61, 212, 143, 68, 82, 110, 41, 175, 185, 78, 72, 23, 230, 39, 108, 175, 79, 128, 194, 79,
        76, 207, 128, 124, 164, 115, 114, 35, 32, 27, 182, 231, 45, 166, 142, 238, 154, 199, 54,
        140, 234, 35, 209, 181, 165, 166, 129, 70, 41, 173, 208, 233, 30, 9, 17, 12, 200, 105, 114,
        61, 142, 10, 175, 12, 241, 202, 107, 192, 106, 64, 67, 92, 251, 139, 2, 225, 166, 102, 207,
        152, 124, 213, 226, 12, 99, 164, 15, 176, 151, 137, 21, 254, 65, 161, 108, 123, 158, 117,
        94, 156, 97, 83, 64, 155, 90, 148, 180, 177, 184, 33, 227, 199, 69, 65, 64, 61, 98, 154,
        159, 196, 0, 12, 120, 31, 16, 75, 174, 239, 154, 142, 30, 74, 168, 120, 196, 116, 180, 70,
        163, 66, 18, 129, 193, 143, 132, 182, 190, 78, 54, 133, 252, 146, 102, 244, 188, 200, 147,
        196, 243, 187, 110, 196, 201, 177, 36, 66, 196, 177, 247, 128, 191, 13, 161, 60, 205, 253,
        220, 37, 115, 178, 194, 120, 239, 66, 115, 113, 190, 23, 181, 110, 179, 191, 167, 186, 195,
        221, 210, 193, 178, 78, 64, 169, 16, 190, 56, 229, 209, 213, 196, 178, 167, 235, 178, 150,
        33, 35, 160, 241, 27, 19, 234, 129, 23, 87, 112, 228, 123, 79, 182, 180, 99, 230, 213, 156,
        102, 212, 232, 187, 23, 124, 184, 253, 134, 173, 77, 182, 80, 24, 167, 176, 65, 35, 254,
        235, 170, 116, 110, 114, 57, 89, 14, 220, 67, 203, 10, 111, 19, 99, 179, 70, 12, 233, 209,
        181, 102, 160, 206, 26, 23, 108, 60, 120, 4, 230, 81, 176, 243, 248, 253, 119, 185, 87, 47,
        117, 245, 94, 76, 186, 33, 180, 88, 131, 60, 102, 59, 32, 135, 231, 92, 127, 111, 177, 148,
        24, 165, 12, 192, 174, 170, 14, 224, 161, 217, 12, 45, 21, 186, 126, 122, 68, 68, 202, 76,
        168, 188, 119, 144, 156, 66, 66, 59, 142, 230, 80, 37, 32, 240, 191, 124, 185, 103, 8, 87,
        15, 141, 51, 153, 89, 152, 64, 219, 86, 177, 210, 234, 168, 144, 42, 176, 3, 89, 19, 205,
        96, 30, 102, 121, 79, 250, 79, 65, 45, 143, 228, 27, 0, 173, 112, 44, 191, 206, 0, 160, 21,
        137, 190, 66, 26, 215, 149, 42, 61, 182, 28, 59, 234, 66, 86, 209, 149, 223, 222, 30, 55,
        184, 23, 202, 110, 107, 233, 249, 155, 12, 210, 135, 191, 91, 1, 144, 181, 98, 80, 32, 90,
        83, 228, 187, 34, 42, 250, 109, 11, 89, 237, 193, 60, 107, 21, 209, 237, 65, 157, 239, 233,
        225, 153, 174, 135, 87, 110, 1, 102, 103, 222, 39, 235, 32, 87, 10, 135, 100, 176, 116,
        226, 189, 27, 128, 120, 200, 83, 126, 25, 159, 226, 250, 174, 77, 218, 79, 235, 164, 134,
        63, 59, 139, 134, 195, 58, 215, 33, 2, 17, 148, 219, 240, 170, 245, 191, 198, 126, 167,
        205, 212, 66, 209, 66, 177, 10, 165, 246, 122, 76, 171, 174, 190, 38, 159, 0, 108, 61, 114,
        119, 6, 81, 108, 186, 203, 143, 138, 226, 66, 207, 38, 128, 166, 165, 100, 131, 186, 186,
        116, 245, 217, 162, 45, 242, 220, 149, 109, 245, 139, 189, 187, 189, 98, 216, 178, 63, 48,
        134, 115, 6, 94, 136, 41, 100, 88, 57, 109, 48, 148, 213, 182, 216, 163, 232, 227, 225, 85,
        2, 166, 226, 219, 133, 47, 28, 55, 106, 220, 231, 115, 145, 31, 188, 125, 56, 4, 106, 7,
        210, 111, 137, 162, 4, 221, 96, 231, 165, 130, 11, 37, 72, 52, 135, 46, 248, 232, 215, 187,
        9, 155, 242, 145, 28, 84, 110, 164, 101, 9, 244, 104, 129, 202, 195, 94, 117, 255, 194, 60,
        41, 113, 175, 246, 137, 135, 155, 246, 21, 212, 206, 223, 254, 39, 209, 183, 201, 58, 66,
        6, 11, 241, 166, 16, 214, 205, 187, 245, 229, 84, 121, 217, 2, 130, 1, 129, 0, 248, 36,
        248, 215, 117, 19, 169, 248, 112, 7, 241, 212, 143, 95, 151, 144, 191, 125, 142, 212, 89,
        65, 122, 46, 224, 135, 206, 182, 140, 1, 50, 182, 83, 47, 168, 144, 51, 108, 24, 51, 167,
        98, 0, 138, 30, 47, 148, 124, 161, 61, 77, 175, 63, 0, 252, 173, 3, 120, 231, 89, 126, 174,
        129, 193, 39, 32, 31, 120, 255, 16, 208, 103, 226, 244, 214, 243, 205, 138, 138, 78, 14,
        243, 208, 211, 94, 223, 90, 215, 216, 59, 203, 117, 235, 208, 76, 209, 72, 23, 241, 13,
        110, 98, 140, 160, 124, 179, 185, 110, 45, 202, 137, 123, 249, 174, 193, 160, 224, 42, 127,
        254, 206, 68, 116, 246, 156, 124, 147, 24, 180, 92, 125, 153, 45, 119, 113, 103, 102, 198,
        94, 117, 230, 0, 71, 137, 230, 215, 36, 251, 101, 43, 62, 236, 0, 87, 143, 108, 22, 252,
        94, 12, 70, 246, 222, 37, 183, 149, 46, 4, 224, 29, 178, 190, 114, 17, 158, 194, 104, 230,
        192, 201, 46, 124, 185, 209, 178, 25, 209, 237, 206, 116, 89, 134, 240, 73, 81, 90, 84,
        250, 28, 115, 66, 37, 86, 89, 32, 160, 147, 120, 67, 59, 200, 145, 220, 199, 89, 70, 11,
        212, 111, 109, 149, 57, 135, 176, 93, 56, 175, 249, 117, 77, 98, 2, 40, 27, 159, 158, 52,
        180, 56, 21, 136, 104, 229, 107, 186, 92, 50, 57, 103, 238, 191, 145, 192, 184, 99, 70,
        239, 98, 127, 243, 138, 49, 53, 204, 253, 152, 42, 20, 94, 123, 34, 83, 239, 139, 88, 196,
        251, 47, 92, 118, 129, 45, 121, 156, 74, 215, 149, 90, 139, 163, 89, 40, 165, 206, 6, 208,
        68, 1, 167, 119, 167, 100, 10, 236, 67, 145, 242, 52, 3, 46, 69, 133, 242, 41, 58, 16, 76,
        132, 248, 18, 234, 122, 85, 242, 207, 98, 54, 104, 121, 185, 92, 9, 242, 226, 51, 117, 59,
        25, 69, 234, 32, 73, 255, 14, 200, 247, 10, 76, 212, 129, 240, 180, 167, 65, 160, 253, 175,
        166, 242, 216, 98, 66, 183, 142, 143, 60, 225, 183, 232, 94, 215, 93, 122, 65, 191, 218, 5,
        87, 151, 230, 68, 20, 121, 139, 2, 130, 1, 129, 0, 216, 217, 209, 107, 113, 185, 253, 48,
        252, 255, 22, 204, 23, 142, 32, 55, 117, 189, 52, 104, 17, 40, 228, 68, 190, 253, 112, 155,
        111, 74, 188, 157, 179, 104, 60, 182, 81, 100, 93, 172, 64, 189, 205, 34, 167, 196, 49, 39,
        62, 212, 136, 34, 180, 100, 59, 235, 91, 125, 226, 204, 253, 174, 216, 133, 29, 66, 197,
        137, 85, 71, 43, 221, 228, 13, 117, 226, 34, 24, 233, 102, 179, 86, 227, 250, 200, 193, 49,
        108, 16, 119, 59, 176, 116, 173, 231, 250, 67, 46, 120, 88, 134, 148, 72, 251, 241, 41,
        192, 6, 26, 198, 84, 170, 71, 62, 165, 63, 61, 63, 177, 226, 198, 59, 113, 15, 108, 25,
        179, 83, 7, 50, 144, 36, 160, 81, 98, 16, 161, 247, 17, 114, 136, 37, 69, 140, 27, 248,
        236, 126, 199, 62, 48, 26, 72, 159, 252, 171, 112, 36, 69, 16, 187, 251, 74, 126, 73, 48,
        147, 95, 130, 252, 42, 7, 37, 73, 74, 101, 201, 181, 189, 103, 249, 28, 123, 126, 206, 49,
        209, 160, 253, 39, 32, 93, 45, 162, 167, 219, 216, 144, 140, 130, 119, 145, 22, 28, 151,
        61, 201, 174, 222, 147, 237, 67, 254, 3, 178, 7, 79, 208, 16, 209, 180, 103, 183, 56, 73,
        56, 215, 9, 223, 240, 140, 195, 240, 175, 49, 88, 26, 171, 173, 216, 29, 29, 73, 195, 250,
        181, 251, 77, 251, 252, 11, 160, 26, 112, 239, 109, 141, 165, 229, 189, 225, 1, 32, 215,
        40, 70, 137, 51, 26, 237, 254, 210, 163, 59, 192, 228, 78, 136, 208, 40, 99, 87, 215, 249,
        51, 210, 117, 227, 26, 13, 61, 169, 205, 86, 253, 120, 250, 249, 173, 29, 210, 230, 74,
        157, 207, 163, 145, 55, 197, 193, 96, 168, 205, 156, 136, 14, 22, 11, 234, 138, 160, 134,
        130, 206, 111, 52, 246, 209, 184, 240, 123, 178, 116, 159, 170, 236, 167, 44, 2, 128, 46,
        112, 154, 73, 197, 102, 172, 7, 201, 28, 233, 242, 31, 190, 5, 88, 24, 5, 81, 30, 51, 160,
        205, 214, 221, 107, 142, 37, 236, 104, 225, 246, 98, 0, 227, 84, 134, 33, 144, 164, 39,
        163, 113, 89, 2, 130, 1, 129, 0, 236, 183, 160, 103, 49, 121, 179, 192, 155, 103, 8, 204,
        132, 133, 101, 122, 33, 34, 174, 249, 101, 184, 47, 205, 190, 69, 239, 237, 118, 187, 193,
        219, 234, 153, 97, 77, 70, 176, 204, 153, 162, 8, 188, 137, 5, 232, 207, 214, 224, 158, 49,
        152, 135, 26, 242, 240, 61, 138, 189, 240, 67, 8, 72, 33, 177, 168, 84, 61, 193, 221, 17,
        98, 185, 64, 102, 58, 40, 15, 12, 135, 16, 126, 136, 236, 202, 233, 121, 168, 196, 207,
        173, 245, 109, 34, 197, 213, 51, 216, 27, 13, 124, 11, 41, 42, 4, 44, 19, 45, 199, 35, 26,
        106, 153, 50, 155, 230, 83, 82, 87, 206, 4, 137, 139, 166, 162, 123, 184, 123, 109, 187,
        121, 217, 129, 101, 27, 90, 207, 209, 86, 213, 83, 183, 90, 135, 116, 30, 51, 90, 91, 21,
        153, 45, 219, 217, 171, 169, 42, 120, 79, 99, 152, 226, 241, 226, 187, 49, 229, 183, 162,
        240, 209, 206, 25, 213, 51, 69, 52, 123, 68, 215, 230, 175, 247, 55, 210, 150, 13, 12, 181,
        209, 138, 130, 78, 129, 50, 201, 96, 157, 68, 60, 179, 146, 24, 192, 103, 126, 167, 143,
        167, 91, 197, 167, 88, 29, 23, 205, 217, 133, 43, 83, 55, 114, 173, 61, 146, 128, 124, 103,
        21, 254, 223, 11, 61, 165, 180, 108, 96, 204, 183, 95, 219, 68, 109, 239, 137, 213, 95,
        216, 33, 140, 193, 85, 82, 170, 211, 146, 28, 213, 51, 72, 105, 193, 46, 24, 194, 166, 193,
        37, 179, 71, 245, 228, 106, 116, 221, 22, 244, 164, 38, 169, 169, 235, 110, 194, 169, 38,
        229, 132, 126, 7, 51, 11, 178, 184, 75, 9, 172, 134, 131, 114, 130, 205, 206, 25, 187, 15,
        228, 36, 184, 16, 17, 36, 137, 113, 200, 193, 57, 173, 243, 85, 96, 55, 153, 252, 74, 215,
        223, 29, 101, 89, 109, 50, 212, 111, 243, 52, 215, 78, 241, 194, 58, 81, 60, 174, 167, 9,
        251, 218, 117, 51, 12, 35, 218, 22, 162, 116, 191, 119, 28, 221, 77, 71, 102, 1, 234, 36,
        227, 18, 228, 234, 108, 186, 240, 224, 254, 27, 6, 211, 155, 197, 127, 150, 164, 167, 2,
        130, 1, 128, 105, 187, 211, 59, 211, 104, 255, 134, 106, 101, 170, 228, 250, 187, 71, 4,
        35, 185, 140, 155, 13, 122, 229, 202, 139, 97, 162, 13, 119, 247, 117, 254, 98, 226, 249,
        111, 96, 66, 82, 214, 81, 126, 250, 77, 226, 133, 107, 254, 25, 201, 161, 83, 98, 167, 216,
        251, 138, 81, 216, 75, 97, 138, 102, 114, 137, 112, 236, 70, 105, 57, 89, 175, 72, 170, 51,
        135, 126, 94, 173, 55, 113, 76, 117, 190, 235, 50, 31, 249, 244, 17, 95, 30, 75, 214, 27,
        221, 79, 242, 145, 165, 128, 129, 63, 16, 241, 103, 13, 5, 44, 250, 245, 127, 77, 91, 195,
        81, 17, 121, 68, 48, 49, 189, 252, 3, 172, 14, 223, 252, 36, 239, 71, 143, 68, 72, 74, 75,
        151, 221, 147, 57, 72, 30, 252, 73, 51, 190, 108, 249, 232, 6, 111, 135, 241, 79, 104, 240,
        226, 174, 28, 170, 235, 45, 189, 5, 212, 132, 5, 231, 181, 67, 100, 238, 181, 4, 134, 109,
        25, 44, 47, 93, 73, 254, 212, 76, 97, 23, 179, 130, 14, 205, 140, 31, 66, 200, 35, 150,
        179, 130, 207, 176, 49, 194, 161, 136, 113, 74, 36, 83, 202, 157, 80, 60, 45, 215, 249,
        111, 77, 64, 67, 99, 44, 214, 193, 100, 133, 119, 92, 138, 169, 17, 110, 97, 127, 178, 188,
        153, 155, 239, 135, 197, 111, 116, 191, 105, 250, 141, 207, 42, 24, 42, 174, 52, 115, 144,
        11, 126, 92, 105, 190, 154, 149, 226, 105, 243, 222, 228, 125, 179, 88, 119, 33, 31, 237,
        141, 142, 33, 4, 21, 251, 129, 37, 231, 72, 28, 111, 99, 56, 45, 242, 158, 240, 41, 34, 65,
        63, 56, 69, 15, 134, 148, 155, 39, 196, 204, 43, 217, 50, 78, 130, 115, 38, 193, 71, 248,
        1, 242, 244, 86, 253, 22, 120, 236, 253, 76, 208, 182, 127, 126, 132, 241, 101, 46, 255,
        100, 119, 0, 11, 7, 15, 117, 22, 175, 186, 219, 43, 144, 67, 99, 76, 113, 119, 180, 162,
        59, 145, 249, 129, 68, 222, 103, 158, 126, 210, 190, 232, 153, 175, 230, 215, 221, 208, 7,
        197, 131, 111, 84, 224, 77, 239, 107, 203, 20, 11, 137, 2, 130, 1, 129, 0, 218, 172, 202,
        240, 65, 74, 140, 77, 6, 249, 199, 156, 164, 83, 119, 49, 238, 222, 122, 22, 92, 13, 105,
        249, 128, 79, 135, 145, 95, 235, 206, 24, 212, 209, 115, 33, 157, 103, 49, 72, 127, 170,
        196, 13, 195, 198, 115, 253, 91, 153, 4, 53, 60, 223, 40, 84, 3, 179, 209, 187, 198, 156,
        187, 53, 179, 118, 225, 214, 75, 5, 71, 0, 37, 29, 113, 181, 41, 223, 31, 116, 178, 61,
        140, 145, 63, 100, 155, 201, 204, 197, 182, 21, 180, 85, 92, 65, 168, 99, 186, 50, 71, 218,
        14, 188, 151, 198, 111, 74, 152, 106, 167, 27, 183, 23, 133, 188, 166, 136, 20, 244, 231,
        163, 103, 94, 176, 12, 56, 76, 91, 222, 128, 151, 204, 117, 243, 146, 49, 105, 18, 213, 26,
        186, 80, 37, 22, 70, 40, 93, 212, 115, 98, 144, 55, 249, 37, 71, 94, 46, 102, 222, 249, 92,
        85, 251, 111, 27, 40, 126, 242, 70, 223, 1, 129, 144, 163, 195, 59, 208, 14, 167, 81, 28,
        27, 24, 181, 239, 237, 35, 141, 85, 193, 253, 157, 196, 77, 8, 218, 131, 168, 68, 83, 156,
        50, 9, 159, 25, 199, 211, 148, 104, 116, 40, 53, 174, 112, 120, 205, 246, 159, 197, 184, 4,
        173, 153, 24, 17, 247, 90, 212, 198, 136, 13, 146, 91, 219, 109, 57, 44, 68, 53, 27, 74, 9,
        172, 168, 29, 107, 22, 14, 96, 72, 65, 39, 172, 136, 208, 151, 54, 185, 219, 57, 203, 204,
        29, 236, 17, 25, 64, 198, 115, 216, 44, 127, 126, 77, 129, 186, 25, 2, 37, 158, 48, 80, 65,
        180, 140, 102, 98, 11, 212, 82, 3, 216, 82, 75, 65, 15, 165, 182, 210, 204, 116, 150, 215,
        246, 179, 97, 224, 118, 7, 148, 245, 68, 154, 104, 40, 68, 165, 151, 58, 231, 9, 208, 153,
        135, 86, 145, 98, 143, 199, 149, 229, 242, 140, 157, 144, 97, 117, 191, 170, 165, 90, 18,
        120, 164, 81, 81, 220, 130, 241, 193, 23, 175, 81, 98, 8, 52, 252, 174, 59, 161, 64, 111,
        246, 63, 201, 185, 220, 58, 131, 198, 246, 28, 183, 110, 62, 60, 181, 139, 162, 121, 48,
        46, 40,
    ];
    const KEY_8192_DER: &[u8] = &[
        48, 130, 18, 39, 2, 1, 0, 2, 130, 4, 1, 0, 151, 6, 189, 169, 122, 196, 37, 67, 71, 17, 142,
        223, 4, 103, 93, 227, 209, 245, 252, 14, 183, 199, 40, 158, 14, 147, 52, 207, 142, 242, 58,
        153, 65, 81, 74, 208, 165, 33, 8, 168, 167, 167, 121, 250, 142, 102, 69, 56, 167, 220, 187,
        171, 33, 82, 187, 18, 97, 181, 139, 129, 172, 157, 53, 245, 92, 184, 201, 172, 50, 250,
        208, 180, 178, 225, 133, 44, 23, 10, 163, 136, 36, 89, 116, 249, 146, 170, 227, 57, 114,
        180, 27, 139, 142, 218, 227, 0, 127, 17, 19, 225, 54, 193, 237, 149, 148, 70, 190, 15, 78,
        138, 47, 3, 119, 185, 53, 248, 32, 75, 141, 146, 27, 147, 105, 124, 126, 156, 127, 218, 38,
        62, 108, 33, 66, 171, 230, 27, 228, 93, 246, 72, 107, 89, 196, 156, 103, 82, 179, 202, 208,
        140, 145, 70, 77, 22, 14, 55, 100, 249, 103, 223, 127, 85, 223, 198, 33, 98, 16, 119, 144,
        183, 168, 10, 96, 43, 40, 86, 73, 141, 11, 188, 208, 102, 80, 242, 113, 130, 42, 103, 88,
        228, 11, 69, 247, 253, 76, 65, 14, 181, 190, 165, 114, 226, 243, 160, 21, 111, 141, 149,
        110, 98, 230, 125, 162, 189, 221, 192, 152, 198, 174, 12, 184, 51, 239, 77, 76, 250, 201,
        48, 4, 51, 7, 60, 147, 225, 221, 161, 98, 243, 90, 67, 223, 70, 189, 56, 203, 7, 236, 174,
        182, 27, 54, 136, 101, 180, 82, 210, 1, 170, 213, 100, 69, 21, 212, 43, 62, 2, 174, 73,
        202, 210, 116, 149, 215, 171, 106, 169, 160, 64, 146, 77, 24, 183, 151, 83, 54, 13, 64,
        168, 51, 3, 13, 200, 33, 23, 228, 148, 53, 188, 143, 81, 117, 129, 247, 103, 212, 66, 83,
        15, 235, 89, 160, 8, 16, 107, 6, 239, 51, 3, 188, 143, 205, 5, 187, 161, 188, 186, 76, 153,
        81, 167, 42, 121, 91, 75, 13, 10, 247, 135, 53, 165, 66, 58, 53, 33, 203, 15, 39, 195, 191,
        107, 72, 12, 70, 203, 66, 230, 26, 221, 222, 99, 59, 51, 172, 204, 116, 224, 60, 23, 73,
        127, 112, 16, 34, 226, 175, 89, 110, 36, 163, 67, 72, 18, 197, 127, 240, 100, 62, 175, 80,
        248, 55, 234, 35, 192, 168, 31, 225, 87, 18, 226, 107, 11, 122, 227, 50, 23, 192, 90, 213,
        151, 142, 143, 73, 131, 24, 203, 64, 144, 90, 79, 153, 178, 141, 152, 82, 18, 70, 64, 29,
        18, 45, 98, 134, 112, 100, 38, 41, 83, 162, 238, 143, 176, 226, 148, 107, 223, 16, 156,
        212, 229, 252, 79, 7, 165, 57, 40, 132, 119, 209, 244, 4, 160, 190, 76, 17, 170, 14, 5,
        131, 94, 79, 111, 190, 58, 211, 143, 129, 8, 179, 36, 98, 53, 175, 254, 157, 97, 163, 96,
        129, 235, 113, 81, 211, 241, 219, 24, 16, 38, 196, 206, 81, 174, 124, 210, 16, 112, 5, 247,
        186, 26, 44, 99, 160, 230, 126, 227, 124, 110, 54, 224, 41, 243, 104, 11, 114, 84, 232, 54,
        240, 136, 110, 156, 147, 38, 153, 80, 89, 44, 160, 179, 28, 208, 249, 181, 59, 247, 64, 88,
        15, 26, 159, 207, 221, 59, 210, 222, 193, 0, 65, 231, 137, 119, 97, 254, 231, 112, 192, 36,
        251, 238, 229, 177, 167, 97, 151, 187, 158, 168, 157, 63, 238, 148, 88, 58, 92, 239, 9,
        165, 161, 166, 137, 244, 86, 156, 68, 22, 64, 89, 33, 190, 47, 177, 67, 1, 174, 239, 2, 90,
        195, 62, 121, 166, 121, 221, 251, 162, 30, 249, 41, 71, 37, 172, 248, 250, 93, 74, 170, 98,
        100, 48, 194, 246, 132, 172, 190, 121, 172, 238, 179, 59, 85, 232, 205, 141, 52, 12, 126,
        250, 60, 240, 192, 90, 102, 68, 167, 155, 158, 250, 6, 31, 215, 91, 232, 225, 175, 190,
        161, 138, 216, 133, 3, 116, 65, 50, 167, 128, 218, 197, 209, 145, 188, 220, 188, 107, 183,
        76, 1, 69, 158, 175, 63, 202, 101, 22, 239, 214, 85, 168, 13, 220, 206, 80, 216, 154, 114,
        175, 48, 199, 9, 202, 31, 51, 149, 215, 160, 61, 7, 82, 240, 34, 133, 203, 146, 199, 94,
        155, 56, 74, 36, 112, 28, 77, 87, 54, 88, 56, 168, 74, 185, 76, 55, 252, 127, 241, 240,
        205, 229, 157, 128, 90, 200, 48, 98, 104, 11, 203, 152, 173, 26, 38, 54, 140, 120, 183,
        108, 2, 62, 91, 106, 139, 171, 41, 92, 211, 47, 183, 146, 50, 193, 15, 208, 85, 158, 177,
        220, 250, 221, 230, 174, 195, 58, 237, 51, 223, 135, 140, 83, 166, 158, 214, 156, 120, 240,
        255, 209, 38, 19, 42, 245, 7, 127, 73, 137, 26, 28, 84, 200, 24, 20, 106, 254, 207, 19, 91,
        140, 202, 107, 148, 17, 93, 113, 139, 226, 42, 244, 248, 242, 192, 74, 100, 120, 124, 44,
        73, 151, 51, 38, 201, 56, 68, 251, 182, 197, 2, 199, 176, 32, 191, 179, 58, 10, 253, 190,
        239, 155, 96, 102, 97, 188, 13, 93, 67, 189, 15, 128, 103, 250, 80, 152, 24, 171, 179, 110,
        4, 183, 236, 137, 52, 219, 148, 10, 245, 158, 47, 185, 9, 191, 225, 12, 75, 73, 226, 146,
        140, 62, 180, 135, 173, 107, 143, 163, 136, 131, 251, 183, 186, 182, 36, 205, 173, 0, 207,
        172, 252, 138, 220, 230, 40, 6, 156, 121, 216, 7, 76, 34, 213, 33, 221, 42, 221, 38, 110,
        27, 254, 207, 174, 26, 21, 253, 135, 150, 203, 177, 106, 50, 26, 55, 110, 235, 37, 221, 38,
        71, 99, 148, 149, 102, 164, 155, 24, 130, 115, 31, 125, 173, 186, 205, 77, 122, 75, 145,
        49, 227, 163, 135, 100, 195, 157, 101, 240, 224, 137, 68, 231, 95, 235, 176, 151, 35, 84,
        227, 3, 37, 100, 21, 22, 35, 34, 216, 161, 153, 233, 13, 44, 30, 13, 208, 26, 218, 203,
        172, 206, 246, 33, 2, 3, 1, 0, 1, 2, 130, 4, 0, 11, 200, 203, 30, 81, 21, 194, 137, 150,
        31, 76, 220, 98, 137, 213, 69, 236, 81, 107, 30, 83, 225, 62, 174, 92, 153, 72, 110, 228,
        170, 202, 127, 64, 93, 65, 62, 248, 15, 148, 143, 34, 107, 219, 68, 253, 125, 5, 236, 54,
        142, 238, 246, 218, 182, 11, 162, 82, 204, 249, 106, 128, 39, 81, 57, 72, 199, 163, 118,
        228, 16, 117, 158, 15, 242, 48, 115, 193, 5, 131, 190, 161, 5, 120, 238, 235, 110, 153,
        165, 215, 41, 46, 24, 12, 232, 207, 251, 47, 47, 12, 51, 207, 211, 192, 127, 226, 46, 197,
        240, 72, 82, 216, 121, 199, 11, 4, 230, 204, 80, 80, 230, 228, 111, 115, 116, 243, 37, 47,
        133, 188, 99, 181, 8, 192, 92, 204, 235, 2, 190, 1, 52, 99, 234, 0, 129, 42, 191, 197, 135,
        47, 16, 52, 218, 189, 51, 154, 30, 224, 234, 100, 28, 72, 161, 145, 1, 51, 4, 37, 160, 74,
        194, 197, 226, 47, 96, 86, 184, 170, 235, 14, 78, 40, 157, 191, 53, 183, 189, 46, 37, 91,
        198, 137, 137, 167, 96, 212, 165, 35, 234, 115, 10, 146, 101, 26, 152, 244, 107, 60, 171,
        59, 14, 141, 9, 35, 28, 121, 19, 232, 231, 225, 215, 92, 189, 50, 176, 63, 176, 54, 232,
        31, 255, 194, 82, 12, 0, 253, 11, 245, 126, 99, 29, 246, 43, 93, 34, 244, 22, 181, 117,
        105, 128, 196, 151, 206, 133, 204, 75, 150, 53, 56, 10, 231, 168, 29, 34, 213, 167, 28,
        101, 230, 37, 87, 83, 4, 221, 219, 136, 10, 88, 215, 129, 156, 10, 225, 76, 45, 36, 202,
        21, 133, 203, 120, 117, 19, 253, 251, 8, 68, 140, 38, 203, 182, 165, 82, 66, 128, 9, 191,
        212, 247, 106, 138, 37, 238, 240, 6, 253, 189, 167, 142, 60, 83, 69, 93, 255, 112, 12, 66,
        99, 89, 63, 119, 189, 57, 238, 40, 129, 161, 80, 99, 211, 118, 16, 56, 42, 159, 159, 90,
        93, 56, 15, 189, 50, 182, 8, 112, 187, 39, 64, 6, 53, 12, 126, 202, 254, 54, 37, 116, 18,
        230, 25, 131, 75, 67, 9, 152, 160, 156, 11, 80, 80, 244, 236, 0, 12, 172, 91, 138, 23, 160,
        116, 9, 218, 227, 120, 202, 53, 152, 157, 244, 123, 133, 218, 66, 183, 189, 38, 36, 204,
        129, 171, 158, 132, 88, 58, 90, 66, 43, 210, 199, 181, 59, 219, 54, 152, 186, 216, 177,
        178, 25, 130, 156, 87, 122, 129, 133, 19, 4, 57, 2, 54, 230, 175, 232, 242, 39, 91, 163,
        190, 117, 15, 80, 9, 115, 161, 133, 13, 0, 15, 32, 107, 15, 188, 98, 52, 233, 208, 240,
        224, 165, 192, 67, 103, 6, 251, 44, 156, 95, 55, 104, 81, 15, 183, 188, 56, 156, 27, 173,
        5, 160, 5, 152, 213, 71, 122, 48, 252, 22, 240, 139, 125, 68, 218, 222, 98, 254, 196, 218,
        246, 90, 71, 102, 12, 174, 103, 8, 2, 123, 177, 238, 126, 130, 247, 198, 179, 181, 85, 217,
        55, 232, 88, 242, 13, 114, 97, 26, 117, 182, 187, 123, 164, 252, 118, 27, 67, 207, 237,
        166, 148, 101, 204, 73, 12, 4, 184, 50, 68, 147, 99, 230, 201, 228, 129, 133, 238, 184, 54,
        253, 175, 94, 107, 159, 128, 89, 50, 20, 105, 221, 158, 10, 45, 34, 224, 195, 13, 171, 35,
        148, 14, 210, 220, 25, 147, 172, 220, 100, 247, 213, 64, 159, 206, 166, 242, 18, 34, 180,
        166, 2, 166, 167, 211, 33, 161, 36, 166, 98, 215, 254, 178, 214, 183, 77, 91, 150, 12, 102,
        217, 192, 59, 205, 21, 26, 52, 58, 209, 28, 223, 216, 194, 43, 41, 153, 21, 154, 152, 219,
        151, 132, 64, 139, 168, 134, 163, 226, 169, 154, 108, 248, 193, 139, 196, 224, 141, 63, 70,
        197, 211, 121, 32, 71, 138, 50, 241, 99, 8, 179, 24, 165, 213, 48, 95, 54, 174, 251, 156,
        146, 8, 113, 206, 215, 202, 164, 68, 142, 178, 53, 191, 247, 39, 125, 124, 121, 183, 240,
        255, 50, 69, 12, 113, 129, 218, 131, 189, 25, 42, 176, 65, 9, 32, 106, 221, 126, 8, 101,
        158, 177, 201, 137, 88, 141, 196, 128, 131, 119, 208, 98, 153, 116, 77, 216, 192, 160, 65,
        128, 189, 0, 174, 130, 66, 237, 108, 44, 46, 251, 79, 211, 151, 0, 157, 236, 23, 226, 208,
        106, 199, 62, 254, 220, 88, 152, 28, 33, 181, 153, 60, 106, 187, 76, 135, 97, 19, 37, 241,
        245, 53, 12, 9, 227, 239, 108, 81, 140, 96, 189, 202, 82, 220, 186, 175, 81, 167, 183, 99,
        73, 69, 234, 121, 56, 119, 43, 51, 251, 91, 202, 203, 153, 156, 206, 194, 155, 83, 111,
        224, 160, 140, 20, 164, 52, 175, 247, 164, 190, 193, 75, 195, 222, 158, 162, 35, 54, 255,
        213, 200, 115, 76, 235, 20, 179, 170, 33, 157, 74, 236, 120, 50, 173, 104, 91, 17, 100, 8,
        201, 124, 171, 104, 127, 223, 161, 234, 112, 53, 65, 35, 50, 214, 247, 235, 215, 152, 151,
        243, 108, 238, 249, 249, 92, 33, 98, 107, 156, 129, 119, 146, 2, 134, 226, 34, 209, 92,
        245, 93, 223, 203, 42, 33, 186, 170, 87, 41, 34, 201, 112, 110, 177, 97, 216, 121, 156,
        163, 174, 116, 109, 211, 125, 195, 105, 163, 19, 29, 53, 59, 242, 123, 145, 35, 215, 212,
        255, 2, 188, 9, 56, 233, 239, 225, 70, 164, 86, 40, 6, 22, 56, 73, 169, 156, 69, 22, 41,
        58, 39, 148, 143, 33, 185, 148, 167, 61, 200, 126, 9, 75, 183, 86, 150, 103, 76, 188, 125,
        236, 110, 137, 95, 23, 113, 138, 111, 0, 82, 169, 126, 232, 37, 15, 132, 21, 67, 183, 57,
        134, 59, 81, 203, 211, 67, 67, 205, 132, 76, 26, 243, 193, 16, 181, 219, 86, 199, 242, 114,
        28, 117, 210, 43, 62, 212, 209, 2, 130, 2, 1, 0, 197, 133, 16, 244, 209, 245, 72, 63, 87,
        120, 33, 106, 185, 156, 156, 103, 183, 48, 183, 112, 111, 206, 192, 43, 2, 235, 91, 213,
        231, 81, 103, 198, 204, 251, 198, 174, 24, 245, 29, 240, 197, 194, 202, 128, 58, 204, 215,
        124, 11, 147, 106, 73, 154, 21, 56, 18, 161, 55, 182, 51, 46, 61, 240, 99, 94, 46, 175,
        126, 121, 222, 189, 223, 212, 145, 135, 164, 122, 144, 123, 133, 119, 3, 34, 91, 27, 117,
        100, 65, 64, 135, 225, 118, 55, 55, 42, 0, 165, 24, 138, 167, 157, 117, 66, 10, 180, 171,
        144, 147, 100, 154, 119, 170, 185, 196, 179, 64, 220, 123, 123, 44, 128, 198, 226, 95, 123,
        247, 52, 66, 166, 144, 175, 56, 122, 78, 227, 125, 10, 150, 190, 201, 46, 0, 207, 161, 253,
        25, 221, 175, 153, 10, 92, 83, 163, 15, 254, 167, 135, 254, 62, 14, 249, 125, 128, 118,
        118, 87, 148, 120, 54, 152, 143, 97, 212, 13, 120, 208, 190, 140, 144, 19, 189, 190, 123,
        57, 190, 109, 35, 11, 198, 110, 48, 7, 58, 187, 18, 110, 55, 249, 160, 251, 133, 172, 53,
        38, 249, 160, 195, 199, 173, 43, 2, 244, 184, 12, 84, 100, 184, 165, 111, 40, 70, 194, 61,
        248, 183, 127, 88, 39, 69, 108, 119, 151, 113, 211, 87, 83, 66, 52, 255, 233, 19, 2, 121,
        3, 186, 10, 207, 214, 203, 250, 60, 72, 95, 64, 91, 156, 93, 6, 16, 119, 72, 73, 185, 235,
        20, 67, 206, 127, 126, 48, 20, 69, 134, 83, 126, 161, 221, 12, 0, 220, 159, 153, 143, 51,
        155, 163, 251, 149, 154, 68, 250, 15, 155, 214, 238, 243, 6, 243, 212, 219, 165, 223, 43,
        108, 76, 106, 192, 136, 51, 166, 178, 95, 196, 132, 17, 121, 98, 218, 27, 155, 93, 65, 48,
        106, 234, 226, 44, 74, 184, 202, 248, 234, 1, 92, 33, 158, 178, 3, 7, 98, 88, 166, 47, 134,
        8, 10, 232, 157, 71, 213, 115, 251, 255, 192, 177, 249, 243, 184, 30, 60, 173, 160, 223,
        167, 242, 5, 22, 138, 83, 19, 107, 249, 3, 18, 134, 139, 73, 39, 204, 59, 219, 225, 56, 58,
        154, 57, 29, 153, 128, 78, 58, 110, 12, 219, 8, 137, 46, 201, 48, 249, 98, 158, 182, 220,
        163, 91, 209, 254, 14, 234, 173, 144, 237, 229, 92, 160, 21, 198, 12, 189, 66, 136, 168,
        109, 26, 222, 148, 105, 92, 253, 140, 135, 166, 49, 5, 203, 6, 252, 97, 170, 89, 5, 13,
        158, 56, 44, 24, 45, 30, 31, 24, 55, 158, 243, 156, 168, 67, 123, 18, 94, 219, 140, 68,
        191, 118, 174, 120, 22, 49, 134, 219, 159, 50, 215, 105, 116, 215, 11, 195, 149, 215, 125,
        45, 215, 63, 164, 229, 163, 111, 13, 185, 241, 100, 47, 248, 216, 7, 75, 211, 116, 75, 2,
        96, 7, 21, 250, 246, 130, 168, 173, 74, 89, 2, 130, 2, 1, 0, 195, 189, 184, 178, 165, 24,
        87, 159, 40, 216, 251, 86, 48, 243, 138, 111, 132, 48, 252, 89, 136, 205, 79, 233, 151,
        134, 88, 211, 215, 157, 216, 127, 32, 32, 27, 104, 176, 29, 71, 175, 107, 144, 143, 226,
        48, 133, 187, 116, 64, 14, 133, 203, 101, 147, 154, 224, 108, 246, 151, 130, 139, 22, 251,
        150, 121, 237, 23, 149, 223, 254, 213, 81, 12, 138, 13, 103, 145, 190, 195, 247, 71, 210,
        105, 4, 233, 30, 104, 168, 124, 188, 94, 112, 142, 223, 132, 29, 171, 145, 167, 165, 12,
        196, 67, 19, 231, 16, 80, 62, 129, 227, 99, 201, 196, 148, 189, 222, 248, 118, 141, 81,
        228, 126, 15, 158, 2, 15, 10, 138, 124, 242, 149, 224, 249, 140, 193, 107, 116, 90, 132,
        78, 105, 28, 218, 169, 131, 79, 251, 15, 216, 227, 117, 243, 135, 225, 253, 37, 227, 52,
        226, 109, 64, 229, 29, 246, 79, 16, 13, 11, 193, 64, 229, 9, 26, 191, 175, 167, 11, 86,
        200, 213, 142, 67, 152, 98, 83, 12, 148, 35, 46, 239, 237, 42, 22, 227, 115, 53, 211, 19,
        206, 223, 210, 154, 232, 138, 99, 148, 3, 8, 176, 66, 41, 248, 13, 8, 193, 224, 8, 167,
        200, 61, 234, 109, 76, 110, 122, 44, 14, 161, 233, 129, 244, 7, 69, 255, 0, 104, 81, 253,
        231, 66, 55, 118, 243, 17, 191, 224, 10, 234, 220, 85, 27, 89, 5, 145, 120, 216, 34, 185,
        86, 198, 181, 72, 75, 114, 229, 0, 19, 99, 211, 252, 194, 32, 226, 83, 210, 75, 38, 216,
        152, 96, 190, 95, 23, 216, 72, 223, 74, 65, 139, 107, 156, 171, 2, 237, 166, 136, 120, 73,
        186, 137, 3, 86, 90, 167, 130, 154, 48, 0, 158, 172, 219, 88, 246, 45, 212, 161, 244, 140,
        231, 6, 238, 219, 244, 233, 231, 175, 154, 156, 209, 214, 106, 188, 42, 176, 204, 122, 242,
        55, 221, 125, 33, 32, 0, 173, 136, 126, 43, 111, 36, 160, 232, 98, 164, 80, 187, 57, 1,
        187, 29, 163, 160, 166, 171, 185, 21, 230, 251, 36, 24, 230, 242, 255, 127, 179, 18, 165,
        5, 37, 126, 10, 163, 239, 250, 201, 22, 249, 104, 105, 247, 123, 203, 0, 65, 125, 126, 55,
        115, 115, 95, 100, 63, 239, 170, 32, 79, 158, 163, 165, 56, 15, 37, 11, 205, 25, 241, 17,
        122, 143, 122, 142, 202, 166, 120, 25, 93, 57, 200, 90, 85, 83, 213, 237, 167, 214, 82,
        195, 121, 23, 72, 233, 8, 25, 183, 49, 32, 166, 4, 111, 17, 74, 14, 38, 102, 44, 43, 214,
        213, 1, 99, 255, 205, 167, 124, 228, 58, 39, 22, 215, 240, 212, 92, 214, 207, 99, 167, 214,
        90, 185, 105, 79, 161, 253, 111, 119, 195, 79, 188, 232, 217, 209, 75, 206, 93, 36, 79, 89,
        154, 244, 142, 238, 1, 5, 56, 141, 80, 60, 206, 48, 117, 53, 1, 9, 2, 130, 2, 0, 10, 58,
        163, 240, 41, 215, 108, 16, 107, 181, 58, 245, 205, 251, 0, 86, 150, 180, 29, 43, 227, 126,
        111, 145, 74, 171, 105, 172, 32, 56, 165, 9, 52, 160, 109, 95, 162, 199, 62, 239, 179, 46,
        45, 82, 138, 185, 5, 7, 213, 137, 162, 221, 128, 239, 76, 98, 26, 155, 74, 2, 72, 136, 200,
        164, 60, 194, 106, 48, 64, 155, 122, 117, 215, 10, 90, 93, 248, 66, 247, 66, 168, 49, 47,
        92, 76, 133, 189, 213, 107, 68, 30, 55, 3, 17, 6, 73, 214, 66, 249, 27, 73, 26, 67, 123,
        78, 115, 252, 30, 197, 253, 1, 233, 131, 137, 94, 71, 35, 163, 249, 115, 10, 144, 66, 52,
        243, 180, 143, 174, 75, 245, 254, 61, 12, 136, 125, 91, 130, 106, 224, 34, 135, 17, 95,
        175, 97, 238, 46, 254, 227, 12, 24, 79, 244, 135, 229, 134, 67, 146, 181, 32, 13, 103, 164,
        121, 126, 19, 119, 10, 234, 184, 231, 228, 7, 25, 83, 130, 107, 251, 215, 146, 78, 39, 73,
        54, 106, 88, 56, 146, 105, 138, 87, 78, 104, 138, 59, 160, 29, 161, 253, 230, 72, 187, 236,
        92, 194, 92, 195, 6, 218, 62, 249, 254, 54, 113, 221, 5, 2, 82, 254, 248, 181, 1, 102, 56,
        53, 56, 145, 22, 39, 144, 64, 121, 69, 89, 206, 145, 239, 65, 211, 102, 252, 167, 10, 33,
        89, 71, 42, 16, 83, 171, 247, 231, 63, 151, 147, 166, 251, 98, 79, 3, 254, 104, 99, 10,
        123, 152, 47, 95, 134, 231, 114, 133, 79, 57, 143, 187, 78, 57, 74, 234, 34, 17, 207, 202,
        186, 106, 185, 162, 187, 196, 138, 182, 184, 57, 95, 82, 146, 175, 153, 252, 110, 16, 170,
        173, 7, 32, 24, 44, 117, 144, 82, 120, 135, 50, 215, 188, 211, 147, 188, 14, 69, 188, 20,
        135, 212, 246, 53, 153, 1, 12, 241, 235, 28, 122, 234, 250, 206, 249, 61, 46, 168, 172,
        162, 149, 108, 97, 52, 62, 192, 243, 154, 248, 23, 252, 160, 186, 243, 22, 59, 234, 164,
        139, 74, 73, 230, 76, 193, 40, 20, 185, 82, 196, 40, 150, 147, 5, 47, 154, 178, 6, 255,
        146, 32, 89, 88, 151, 80, 163, 28, 115, 240, 174, 182, 87, 185, 143, 113, 46, 214, 44, 116,
        33, 8, 19, 81, 26, 118, 59, 148, 6, 47, 74, 236, 39, 14, 174, 243, 177, 184, 3, 45, 40,
        234, 160, 11, 222, 47, 13, 109, 213, 107, 171, 178, 189, 163, 49, 42, 129, 115, 133, 96,
        234, 212, 19, 183, 145, 1, 7, 133, 33, 211, 29, 62, 76, 27, 118, 211, 87, 210, 81, 187, 72,
        254, 94, 116, 5, 1, 15, 21, 45, 136, 190, 43, 225, 224, 2, 63, 8, 202, 238, 61, 164, 171,
        245, 19, 196, 180, 103, 204, 94, 135, 156, 170, 181, 153, 75, 134, 197, 52, 132, 55, 70,
        62, 54, 223, 186, 137, 125, 166, 194, 162, 177, 2, 130, 2, 0, 117, 191, 171, 91, 203, 244,
        216, 192, 229, 209, 161, 96, 56, 18, 73, 52, 204, 80, 171, 125, 48, 206, 81, 68, 51, 226,
        157, 140, 210, 40, 34, 20, 87, 62, 249, 62, 0, 179, 156, 107, 234, 73, 12, 69, 4, 235, 109,
        216, 128, 176, 59, 204, 31, 78, 171, 220, 85, 176, 1, 116, 134, 55, 77, 33, 56, 55, 103,
        248, 192, 198, 139, 140, 53, 254, 214, 17, 119, 155, 74, 71, 118, 237, 28, 63, 215, 252,
        114, 248, 232, 16, 104, 191, 77, 51, 40, 70, 176, 238, 237, 234, 91, 195, 180, 150, 68,
        105, 139, 220, 14, 70, 187, 192, 164, 128, 213, 183, 75, 192, 5, 67, 62, 48, 151, 52, 118,
        8, 150, 78, 184, 219, 53, 78, 32, 208, 139, 138, 24, 116, 91, 34, 208, 24, 139, 113, 109,
        140, 175, 122, 216, 253, 251, 246, 131, 199, 110, 129, 92, 44, 116, 9, 69, 0, 143, 5, 156,
        138, 11, 79, 6, 242, 2, 213, 119, 65, 216, 104, 164, 105, 144, 102, 231, 45, 194, 125, 99,
        120, 45, 164, 252, 151, 88, 19, 249, 176, 217, 157, 135, 92, 99, 22, 65, 154, 238, 72, 81,
        158, 184, 52, 129, 211, 75, 107, 236, 107, 88, 53, 108, 255, 129, 117, 189, 144, 2, 106,
        115, 20, 13, 185, 88, 190, 212, 13, 140, 13, 218, 48, 231, 33, 213, 251, 255, 97, 142, 215,
        30, 149, 167, 251, 160, 143, 145, 227, 251, 117, 135, 60, 125, 167, 0, 140, 136, 128, 244,
        226, 40, 223, 226, 202, 42, 187, 226, 11, 230, 26, 134, 102, 174, 247, 156, 178, 149, 210,
        158, 133, 125, 80, 213, 90, 152, 132, 35, 186, 188, 8, 58, 37, 222, 54, 123, 255, 240, 2,
        2, 134, 194, 9, 254, 214, 96, 157, 155, 85, 232, 193, 169, 39, 195, 244, 255, 5, 44, 171,
        36, 169, 144, 182, 18, 76, 67, 238, 184, 70, 121, 103, 225, 154, 20, 27, 135, 33, 190, 203,
        129, 156, 226, 127, 3, 161, 216, 102, 243, 100, 99, 116, 45, 44, 29, 222, 113, 245, 252,
        174, 70, 159, 16, 141, 226, 133, 212, 117, 25, 184, 153, 25, 32, 30, 36, 250, 104, 215,
        253, 198, 95, 22, 152, 187, 112, 20, 78, 204, 41, 81, 254, 19, 127, 217, 219, 153, 139,
        200, 194, 173, 105, 170, 6, 59, 104, 53, 251, 131, 32, 197, 248, 155, 162, 104, 225, 81,
        110, 104, 119, 127, 172, 191, 149, 85, 45, 49, 42, 35, 68, 141, 178, 105, 59, 96, 91, 119,
        166, 100, 136, 122, 239, 184, 157, 235, 64, 191, 143, 166, 252, 220, 28, 154, 117, 196,
        198, 94, 15, 201, 209, 236, 239, 52, 91, 199, 39, 246, 190, 233, 0, 240, 55, 209, 187, 37,
        55, 110, 81, 235, 149, 134, 223, 135, 43, 246, 203, 173, 71, 90, 160, 63, 131, 200, 83,
        243, 147, 67, 138, 183, 161, 229, 130, 31, 128, 37, 19, 228, 18, 157, 208, 1, 2, 130, 2, 0,
        121, 233, 67, 85, 17, 47, 208, 63, 84, 250, 125, 126, 148, 109, 27, 174, 18, 32, 38, 189,
        190, 216, 84, 112, 113, 115, 160, 2, 18, 90, 195, 128, 139, 11, 86, 51, 26, 68, 63, 15, 18,
        110, 36, 171, 73, 26, 55, 22, 232, 163, 251, 28, 26, 59, 84, 69, 90, 99, 91, 111, 181, 101,
        79, 152, 165, 230, 245, 90, 114, 38, 237, 128, 249, 185, 176, 162, 2, 116, 219, 68, 141,
        32, 92, 126, 59, 26, 120, 82, 100, 102, 178, 249, 128, 34, 98, 64, 16, 55, 49, 29, 180, 17,
        231, 220, 90, 13, 253, 117, 238, 197, 94, 90, 202, 30, 209, 1, 82, 155, 233, 253, 86, 184,
        48, 219, 131, 243, 59, 165, 28, 200, 31, 190, 122, 245, 219, 158, 177, 48, 154, 253, 114,
        238, 158, 251, 186, 216, 78, 204, 137, 153, 200, 39, 246, 106, 32, 197, 117, 23, 127, 129,
        57, 205, 247, 246, 79, 202, 58, 42, 85, 123, 71, 107, 165, 95, 100, 61, 154, 112, 209, 94,
        139, 200, 0, 102, 145, 139, 186, 49, 72, 49, 74, 112, 76, 69, 130, 15, 102, 110, 230, 88,
        37, 228, 187, 156, 24, 31, 35, 63, 191, 203, 13, 157, 33, 153, 167, 226, 191, 107, 140,
        254, 28, 250, 249, 38, 57, 173, 246, 150, 30, 169, 14, 213, 20, 133, 116, 69, 151, 161, 53,
        248, 214, 186, 7, 89, 107, 173, 48, 231, 7, 30, 255, 248, 101, 123, 84, 167, 122, 208, 87,
        177, 187, 34, 94, 24, 15, 105, 46, 122, 106, 165, 197, 101, 49, 82, 39, 254, 116, 159, 247,
        203, 5, 5, 174, 139, 30, 200, 175, 114, 53, 197, 106, 49, 86, 80, 5, 124, 29, 103, 168, 13,
        10, 57, 199, 224, 69, 9, 48, 13, 253, 49, 93, 208, 33, 56, 43, 217, 133, 3, 209, 251, 230,
        247, 5, 139, 82, 57, 235, 13, 56, 224, 129, 3, 138, 169, 199, 248, 220, 132, 230, 225, 90,
        209, 88, 66, 249, 28, 103, 190, 210, 156, 20, 117, 235, 223, 90, 220, 253, 28, 182, 49, 93,
        164, 185, 25, 66, 52, 198, 219, 151, 117, 189, 248, 241, 137, 191, 175, 90, 226, 195, 82,
        161, 132, 112, 22, 119, 80, 81, 254, 18, 10, 172, 17, 194, 214, 248, 250, 77, 163, 91, 107,
        201, 173, 1, 77, 71, 67, 208, 218, 12, 254, 193, 246, 186, 145, 84, 177, 175, 146, 205,
        214, 28, 45, 142, 90, 171, 237, 126, 35, 176, 221, 9, 151, 122, 79, 87, 112, 30, 141, 77,
        170, 46, 186, 198, 117, 46, 183, 22, 228, 212, 195, 153, 92, 59, 165, 75, 214, 144, 121,
        84, 32, 58, 165, 115, 103, 23, 75, 214, 29, 57, 242, 24, 8, 83, 159, 178, 91, 203, 19, 111,
        8, 169, 235, 61, 4, 13, 2, 254, 147, 46, 79, 249, 154, 91, 67, 49, 94, 173, 204, 17, 112,
        215, 244, 131, 175, 53, 57, 27, 114, 42, 40, 61, 0,
    ];
}
