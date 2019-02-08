// Copyright 2018 Google LLC
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

//! The RSA public-key cryptosystem.

mod bits;

pub use public::rsa::bits::{RsaKeyBits, B2048, B3072, B4096, B6144, B8192};

use std::convert::TryInto;
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
    use std::os::raw::c_uint;

    use boringssl::{self, BoringError, CHeapWrapper, CStackWrapper};
    use hash::Hasher;
    use public::inner::BoringDerKey;
    use public::rsa::RsaKeyBits;
    use util::Sealed;
    use Error;

    // A convenience wrapper around boringssl::RSA.
    //
    // RsaKey maintains the following invariants:
    // - The key is valid.
    // - The key has B bits.
    //
    // This is marked pub and put in this (non-public) module so that using it in impls of
    // the Key trait don't result in public-in-private errors.
    #[derive(Clone)]
    pub struct RsaKey<B: RsaKeyBits> {
        pub key: CHeapWrapper<boringssl::RSA>,
        _marker: PhantomData<B>,
    }

    impl<B: RsaKeyBits> RsaKey<B> {
        pub fn generate() -> Result<RsaKey<B>, BoringError> {
            let mut key = CHeapWrapper::default();
            let mut e = CStackWrapper::default();
            // BN_set_u64 can only fail due to OOM.
            e.bn_set_u64(boringssl::RSA_F4.into()).unwrap();
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
        fn validate_bits(bits: c_uint) -> Result<(), Error> {
            if <c_uint as TryInto<usize>>::try_into(bits).unwrap() != Self::BITS {
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
        use public::rsa::tests::generate_rsa_key;
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
                let key = generate_rsa_key::<B>().inner;
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

            Ok(match key.rsa_bits().try_into().unwrap() {
                B2048::BITS => {
                    RsaPubKeyAnyBits::B2048(RsaPubKey { inner: RsaKey::from_RSA(key.clone())? })
                }
                B3072::BITS => {
                    RsaPubKeyAnyBits::B3072(RsaPubKey { inner: RsaKey::from_RSA(key.clone())? })
                }
                B4096::BITS => {
                    RsaPubKeyAnyBits::B4096(RsaPubKey { inner: RsaKey::from_RSA(key.clone())? })
                }
                B6144::BITS => {
                    RsaPubKeyAnyBits::B6144(RsaPubKey { inner: RsaKey::from_RSA(key.clone())? })
                }
                B8192::BITS => {
                    RsaPubKeyAnyBits::B8192(RsaPubKey { inner: RsaKey::from_RSA(key.clone())? })
                }
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

            Ok(match key.rsa_bits().try_into().unwrap() {
                B2048::BITS => {
                    RsaPrivKeyAnyBits::B2048(RsaPrivKey { inner: RsaKey::from_RSA(key.clone())? })
                }
                B3072::BITS => {
                    RsaPrivKeyAnyBits::B3072(RsaPrivKey { inner: RsaKey::from_RSA(key.clone())? })
                }
                B4096::BITS => {
                    RsaPrivKeyAnyBits::B4096(RsaPrivKey { inner: RsaKey::from_RSA(key.clone())? })
                }
                B6144::BITS => {
                    RsaPrivKeyAnyBits::B6144(RsaPrivKey { inner: RsaKey::from_RSA(key.clone())? })
                }
                B8192::BITS => {
                    RsaPrivKeyAnyBits::B8192(RsaPrivKey { inner: RsaKey::from_RSA(key.clone())? })
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
#[cfg(feature = "rsa-pkcs1v15")]
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
        boringssl::rsa_sign(H::nid(), digest, sig, &rsa.key)
    }
    fn verify<B: RsaKeyBits, H: Hasher>(rsa: &RsaKey<B>, digest: &[u8], sig: &[u8]) -> bool {
        boringssl::rsa_verify(H::nid(), digest, sig, &rsa.key)
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
        assert!(sig.len() >= rsa.key.rsa_size().unwrap().get());
        // A salt_len of -1 means to use a salt of the same length as the hash
        // output. This is a reasonable default and, for bit lengths larger than
        // 2048, ensures that the salt will never need to be truncated.
        boringssl::rsa_sign_pss_mgf1(&rsa.key, sig, digest, &H::evp_md(), None, -1)
    }
    fn verify<B: RsaKeyBits, H: Hasher>(rsa: &RsaKey<B>, digest: &[u8], sig: &[u8]) -> bool {
        // A salt_len of -2 means to recover the salt length from the signature,
        // and thus to tolerate any salt length.
        boringssl::rsa_verify_pss_mgf1(&rsa.key, digest, &H::evp_md(), None, -2, sig)
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
    use lazy_static::lazy_static;

    use super::*;
    use hash::Sha256;
    use util::should_fail;

    // Generating RSA keys is very expensive. In order to make these tests run
    // more quickly, we generate a key of a given bit size only once, and then
    // re-use that key in subsequent tests.
    //
    // Since RsaPrivKey doesn't implement Send, we can't store it directly in a
    // lazy_static. Instead, we store its DER encoding, and parse in
    // generate_rsa_key.
    lazy_static! {
        static ref B2048_KEY: Vec<u8> = RsaPrivKey::<B2048>::generate().unwrap().marshal_to_der();
        static ref B3072_KEY: Vec<u8> = RsaPrivKey::<B3072>::generate().unwrap().marshal_to_der();
        static ref B4096_KEY: Vec<u8> = RsaPrivKey::<B4096>::generate().unwrap().marshal_to_der();
        static ref B6144_KEY: Vec<u8> = RsaPrivKey::<B6144>::generate().unwrap().marshal_to_der();
        static ref B8192_KEY: Vec<u8> = RsaPrivKey::<B8192>::generate().unwrap().marshal_to_der();
    }

    // also used by inner::tests
    pub(super) fn generate_rsa_key<B: RsaKeyBits>() -> RsaPrivKey<B> {
        let bytes = match B::BITS {
            2048 => B2048_KEY.as_slice(),
            3072 => B3072_KEY.as_slice(),
            4096 => B4096_KEY.as_slice(),
            6144 => B6144_KEY.as_slice(),
            8192 => B8192_KEY.as_slice(),
            _ => unreachable!(),
        };
        RsaPrivKey::parse_from_der(bytes).unwrap()
    }

    #[test]
    fn test_generate() {
        generate_rsa_key::<B2048>();
        generate_rsa_key::<B3072>();
        generate_rsa_key::<B4096>();
        generate_rsa_key::<B6144>();
        generate_rsa_key::<B8192>();
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
            let key = generate_rsa_key::<B>();

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
            let privkey = generate_rsa_key::<B1>();
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
            let key = generate_rsa_key::<B>();
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
            assert!(!sig.is_valid(&generate_rsa_key::<B2048>().public(), &[],));
        }
        #[cfg(feature = "rsa-pkcs1v15")]
        {
            test_is_invalid::<RsaPkcs1v15>(&RsaSignature::from_bytes(&[0; MAX_SIGNATURE_LEN + 1]));
            test_is_invalid::<RsaPkcs1v15>(&RsaSignature::from_bytes(&[]));
        }
        test_is_invalid::<RsaPss>(&RsaSignature::from_bytes(&[0; MAX_SIGNATURE_LEN + 1]));
        test_is_invalid::<RsaPss>(&RsaSignature::from_bytes(&[]));
    }
}
