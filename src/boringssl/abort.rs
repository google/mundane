// Copyright 2018 Google LLC
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

//! Macros and functions that abort instead of unwinding.
//!
//! Writing `unsafe` code which retains memory safety in the face of unwinding
//! is [notoriously
//! difficult](https://doc.rust-lang.org/nightly/nomicon/exception-safety.html).
//! This module provides panic-related macros and functions that abort rather
//! than unwind. These are used in place of unwinding-based macros and functions
//! so that we can avoid the high probability of us getting unwind-safe code
//! wrong.

use std::fmt::Debug;

macro_rules! assert_abort {
    ($cond:expr) => ({
        let cond = $cond;
        let cond_str = stringify!($cond);
        assert_abort!(cond, "{}", cond_str);
    });
    ($cond:expr,) => ({
        assert_abort!($cond);
    });
    ($cond:expr, $msg:expr, $($arg:tt)*) => ({
        if !($cond) {
            panic_abort!(concat!("assertion failed: ", $msg), $($arg)*);
        }
    });
}

macro_rules! assert_abort_eq {
    ($left:expr, $right:expr) => ({
        match (&$left, &$right) {
            (left_val, right_val) => {
                if !(*left_val == *right_val) {
                    panic_abort!(r#"assertion failed: `(left == right)`
  left: `{:?}`,
 right: `{:?}`"#, left_val, right_val)
                }
            }
        }
    });
    ($left:expr, $right:expr,) => ({
        assert_eq!($left, $right)
    });
    ($left:expr, $right:expr, $($arg:tt)+) => ({
        match (&($left), &($right)) {
            (left_val, right_val) => {
                if !(*left_val == *right_val) {
                    panic_abort!(r#"assertion failed: `(left == right)`
  left: `{:?}`,
 right: `{:?}`: {}"#, left_val, right_val,
                           format_args!($($arg)+))
                }
            }
        }
    });
}

#[allow(unused)]
macro_rules! unimplemented_abort {
    () => {{
        panic_abort!("not yet implemented")
    }};
}

macro_rules! unreachable_abort {
    () => {{
        panic_abort!("internal error: entered unreachable code")
    }};
}

macro_rules! panic_abort {
    () => ({
        panic_abort!("explicit panic")
    });
    ($msg:expr) => ({
        eprintln!("{}", $msg);
        ::std::process::abort();
    });
    ($msg:expr,) => ({
        panic_abort!($msg)
    });
    ($fmt:expr, $($arg:tt)+) => ({
        panic_abort!(format!($fmt, $($arg)+));
    });
}

// Redefine normal panic/assert macros so their use will cause a compiler error.

#[allow(unused)]
macro_rules! panic {
    ($($x:tt)*) => {
        compile_error!("use panic_abort! instead of panic! in boringssl module")
    };
}

#[allow(unused)]
macro_rules! assert {
    ($($x:tt)*) => {
        compile_error!("use assert_abort! instead of assert! in boringssl module")
    };
}

#[allow(unused)]
macro_rules! assert_eq {
    ($($x:tt)*) => {
        compile_error!("use assert_abort_eq! instead of assert_eq! in boringssl module")
    };
}

#[allow(unused)]
macro_rules! assert_ne {
    ($($x:tt)*) => {
        compile_error!("use assert_abort_ne! instead of assert_ne! in boringssl module")
    };
}

#[allow(unused)]
macro_rules! unimplemented {
    ($($x:tt)*) => {
        compile_error!("use unimplemented_abort! instead of unimplemented! in boringssl module")
    };
}

#[allow(unused)]
macro_rules! unreachable {
    ($($x:tt)*) => {
        compile_error!("use unreachable_abort! instead of unreachable! in boringssl module")
    };
}

// unwrap and expect

// TODO(joshlf): Is there a way (maybe with clippy) that we can cause warnings
// or errors if this module ever uses unwrap or expect?

pub trait UnwrapAbort {
    type Item;

    fn unwrap_abort(self) -> Self::Item;
    fn expect_abort(self, msg: &str) -> Self::Item;
}

// The implementations for Option and Result are adapted from the Rust standard library.
impl<T> UnwrapAbort for Option<T> {
    type Item = T;

    fn unwrap_abort(self) -> T {
        match self {
            Some(val) => val,
            None => panic_abort!("called `Option::unwrap_abort()` on a `None` value"),
        }
    }

    fn expect_abort(self, msg: &str) -> T {
        // This is a separate function to reduce the code size of alloc_expect itself
        #[inline(never)]
        #[cold]
        fn failed(msg: &str) -> ! {
            panic_abort!("{}", msg);
        }

        match self {
            Some(val) => val,
            None => failed(msg),
        }
    }
}

impl<T, E: Debug> UnwrapAbort for Result<T, E> {
    type Item = T;

    fn unwrap_abort(self) -> T {
        match self {
            Ok(val) => val,
            Err(err) => {
                result_unwrap_failed("called `Result::unwrap_abort()` on an `Err` value", err)
            }
        }
    }

    fn expect_abort(self, msg: &str) -> T {
        match self {
            Ok(val) => val,
            Err(err) => result_unwrap_failed(msg, err),
        }
    }
}

// This is a separate function to reduce the code size of alloc_{expect,unwrap}
#[inline(never)]
#[cold]
fn result_unwrap_failed<E: Debug>(msg: &str, err: E) -> ! {
    panic_abort!("{}: {:?}", msg, err)
}
