// Copyright 2018 Google LLC
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

use std::borrow::Cow;
use std::fmt::{self, Debug, Display, Formatter};
use std::os::raw::c_int;

use boringssl::{self, BoringError};
use util::Sealed;
use Error;

/// The meat of the `Curve` trait.
///
/// We put the meat of the trait - an inner `Curve` trait which actually has
/// methods on it - in a separate, private module because we don't want these
/// methods to be visible to users.
mod inner {
    use Error;

    use boringssl::{self, CRef};
    use util::Sealed;

    /// An elliptic curve.
    ///
    /// `PCurve` is implemented by `P256`, `P384`, `P521`.
    pub trait PCurve: Sized + Sealed {
        /// Returns this curve's NID.
        ///
        /// Callers are allowed to assume that this NID is a valid one, and are
        /// allowed to panic if it is not.
        fn nid() -> i32;

        /// Returns the group named by `Self::nid()`.
        fn group() -> CRef<'static, boringssl::EC_GROUP> {
            CRef::ec_group_new_by_curve_name(Self::nid()).unwrap()
        }

        /// Validate that an `EC_GROUP` is matches this group.
        ///
        /// If `group` is not equal to the curve's group, `from_group` returns
        /// an error.
        fn validate_group(group: CRef<boringssl::EC_GROUP>) -> Result<(), Error>;
    }
}

/// A NIST P elliptic curve.
///
/// `PCurve` is implemented by [`P256`], [`P384`], and [`P521`]. The P-224 curve
/// is considered insecure, and thus is not supported.
///
/// The P curves are defined by NIST and are used in the ECDSA and ECDH
/// algorithms.
///
/// [`P256`]: ::public::ec::P256
/// [`P384`]: ::public::ec::P384
/// [`P521`]: ::public::ec::P521
pub trait PCurve: Sized + Copy + Clone + Default + Display + Debug + self::inner::PCurve {}

/// The P-256 curve.
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Hash)]
pub struct P256;
/// The P-384 curve.
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Hash)]
pub struct P384;
/// The P-521 curve.
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Hash)]
pub struct P521;

impl Display for P256 {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "P-256")
    }
}
impl Display for P384 {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "P-384")
    }
}
impl Display for P521 {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "P-521")
    }
}

const NID_P256: i32 = boringssl::NID_X9_62_prime256v1 as i32;
const NID_P384: i32 = boringssl::NID_secp384r1 as i32;
const NID_P521: i32 = boringssl::NID_secp521r1 as i32;

macro_rules! impl_curve {
    ($name:ident, $str:expr, $nid:ident) => {
        impl self::inner::PCurve for $name {
            fn nid() -> i32 {
                $nid
            }
            fn validate_group(group: boringssl::CRef<boringssl::EC_GROUP>) -> Result<(), ::Error> {
                let nid = group.ec_group_get_curve_name();
                if nid != $nid {
                    return Err(::Error::new(format!(
                        concat!("unexpected curve: got {}; want ", $str),
                        nid_name(nid).unwrap(),
                    )));
                }
                Ok(())
            }
        }

        impl Sealed for $name {}
        impl PCurve for $name {}
    };
}

impl_curve!(P256, "P-256", NID_P256);
impl_curve!(P384, "P-384", NID_P384);
impl_curve!(P521, "P-521", NID_P521);

/// A dynamic representation of a curve.
pub enum CurveKind {
    P256,
    P384,
    P521,
}

impl CurveKind {
    /// Get the `CurveKind` associated with a NID.
    pub fn from_nid(nid: i32) -> Result<CurveKind, Error> {
        match nid {
            self::NID_P256 => Ok(CurveKind::P256),
            self::NID_P384 => Ok(CurveKind::P384),
            self::NID_P521 => Ok(CurveKind::P521),
            _ => Err(Error::new(format!("unsupported curve: {}", nid_name(nid).unwrap()))),
        }
    }
}

// NOTE: Can only return an error due to an unknown NID
fn nid_name(nid: c_int) -> Result<Cow<'static, str>, BoringError> {
    Ok(boringssl::ec_curve_nid2nist(nid)?.to_string_lossy())
}
