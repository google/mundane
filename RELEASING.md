<!-- Copyright 2018 Google LLC

Use of this source code is governed by an MIT-style
license that can be found in the LICENSE file or at
https://opensource.org/licenses/MIT. -->

Releasing Instructions
======================

This document describes steps to follow when releasing a new version of Mundane.

1. Update `Cargo.toml` with the new version number
2. Update `boringssl/boringssl` by running `git submodule foreach git pull
   origin master`
3. Update `boringssl/boringssl.rs`:
  - Run `boringssl/bindgen.sh <major> <minor> <patch>`
  - Run `git diff` to verify that all of the version numbers have been updated
    correctly (namely, the `link` attribute at the top of the file is of the
    form `#[link(name = crypto_X_Y_Z)]`, and every `link_name` attribute is of
    the form `#[link_name = "__RUST_MUNDANE_X_Y_Z_SYMBOL_NAME"]`, where `X.Y.Z`
    is the version number, and `SYMBOL_NAME` is the name of the symbol that the
    `link_name` attribute is attached to)
  - Run `boringssl/test_symbol_version_name.sh <major> <minor> <patch>` to
    verify that all of the version numbers have been updated correctly
4. Make sure `./test.sh` passes.
5. Update `CHANGELOG.md` - move any unreleased changes into a new section for
   the new version.
6. Dry run by running `cargo publish --dry-run --allow-dirty`.
7. Commit the changes.
8. Once the changes have been committed, publish by running `cargo publish`.