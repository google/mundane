<!-- Copyright 2018 Google LLC

Use of this source code is governed by an MIT-style
license that can be found in the LICENSE file or at
https://opensource.org/licenses/MIT. -->

Releasing Instructions
======================

This document describes steps to follow when releasing a new version of Mundane.

1. Update `boringssl/boringssl.rs`:
  - Update the `link` attribute at the top of the file to be of the form
    `#[link(name = crypto_x_y_z)]`, where the version to be released is x.y.z.
    where x.y.z is the vers
  - Update the `link_name` attributes - each attribute should be of the form
    `#[link_name = "__RUST_MUNDANE_X_Y_Z_SYMBOL_NAME"]`, where the version to be
    released is version X.Y.Z, and `SYMBOL_NAME` is the name of the symbol that
    the `link_name` attribute is attached to.
2. Run the `boringssl/test_symbol_conflict.sh` script, and ensure that it
   passes.
3. Make sure `cargo test --all-features` passes.
4. Update the version number in `Cargo.toml`.
5. Update `CHANGELOG.md` - move any unreleased changes into a new section for
   the new version.
6. Dry run by running `cargo publish --dry-run --allow-dirty`.
7. Commit the changes.
8. Once the changes have been committed, publish by running `cargo publish`.