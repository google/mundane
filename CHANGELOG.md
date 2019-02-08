<!-- Copyright 2018 Google LLC

Use of this source code is governed by an MIT-style
license that can be found in the LICENSE file or at
https://opensource.org/licenses/MIT. -->

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added
- Added `public::rsa` module which supports RSA-PSS signing.

### Changed
- In the `public` module, functions to parse and marshal DER-encoded
  public/private keys have been moved from bare functions to methods on the
  `DerPublicKey` and `DerPrivateKey` traits.
- In the `public::ec` module, functions to parse and marshal DER-encoded
  public/private keys as the `EcPubKeyAnyCurve` and `EcPrivKeyAnyCurve` types
  have been moved from bare functions to methods on those types.
- The `public::Signature::verify` method has been renamed to `is_valid` to make
  the meaning of its return value more self-evident.
- The `public::ec` module added experimental support for ECDSA-SHA512 under the
  `experimental-sha512-ec` feature.
