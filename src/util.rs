// Copyright 2018 Google LLC
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

/// A trait that can be used to ensure that users of this crate can't implement
/// a trait.
///
/// See the [API Guidelines] for details.
///
/// [API Guidelines]: https://rust-lang-nursery.github.io/api-guidelines/future-proofing.html#sealed-traits-protect-against-downstream-implementations-c-sealed
pub trait Sealed {}

/// Expects that a `Result` is an error.
///
/// `should_fail` ensures that `result` is an error, and that the error's
/// `Debug` representation contains the string `expected_substr`. Otherwise, it
/// panics.
#[cfg(test)]
pub fn should_fail<O, E: ::std::fmt::Debug>(
    result: Result<O, E>,
    desc: &str,
    expected_substr: &str,
) {
    // Credit to agl@google.com for this implementation.
    match result {
        Ok(_) => panic!("{} unexpectedly succeeded", desc),
        Err(err) => {
            let err_str = format!("{:?}", err);
            err_str.find(expected_substr).unwrap_or_else(|| {
                panic!(
                    "{} resulted in error that doesn't include {:?}: {:?}",
                    desc, expected_substr, err_str
                )
            });
        }
    }
}
