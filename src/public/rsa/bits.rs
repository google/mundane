// Copyright 2018 Google LLC
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

use std::fmt::{self, Debug, Display, Formatter};

use util::Sealed;

/// The bit length of an RSA key.
///
/// The [`RsaPrivKey`] and [`RsaPubKey`] types take a `B: RsaKeyBits` type
/// parameter indicating the key's length in bits.
///
/// We only support bit lengths of 2048 or greater, as smaller bit lengths are
/// considered insecure. If 2048 is considered insecure at some point in the
/// future, then we will remove support for it, which will be a breaking change.
///
/// [`RsaPrivKey`]: ::public::rsa::RsaPrivKey
/// [`RsaPubKey`]: ::public::rsa::RsaPubKey
pub trait RsaKeyBits: Sized + Copy + Clone + Default + Display + Debug + Sealed {
    /// The number of bits.
    const BITS: usize;
}

/// 2048 bits.
///
/// `B2048` indicates a 2048-bit RSA key; it implements [`RsaKeyBits`].
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Hash)]
pub struct B2048;

/// 3072 bits.
///
/// `B3072` indicates a 3072-bit RSA key; it implements [`RsaKeyBits`].
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Hash)]
pub struct B3072;

/// 4096 bits.
///
/// `B4096` indicates a 4096-bit RSA key; it implements [`RsaKeyBits`].
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Hash)]
pub struct B4096;

/// 6144 bits.
///
/// `B6144` indicates a 6144-bit RSA key; it implements [`RsaKeyBits`].
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Hash)]
pub struct B6144;

/// 8192 bits.
///
/// `B8192` indicates a 8192-bit RSA key; it implements [`RsaKeyBits`].
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Hash)]
pub struct B8192;

macro_rules! impl_bits {
    ($name:ident, $bits:expr) => {
        impl RsaKeyBits for $name {
            const BITS: usize = $bits;
        }

        impl Display for $name {
            fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
                write!(f, "{} bits", $bits)
            }
        }

        impl Sealed for $name {}
    };
}

impl_bits!(B2048, 2048);
impl_bits!(B3072, 3072);
impl_bits!(B4096, 4096);
impl_bits!(B6144, 6144);
impl_bits!(B8192, 8192);
