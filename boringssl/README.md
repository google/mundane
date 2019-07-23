<!-- Copyright 2018 Google LLC

Use of this source code is governed by an MIT-style
license that can be found in the LICENSE file or at
https://opensource.org/licenses/MIT. -->

# boringssl

This directory contains source code and Rust bindings for Google's
[BoringSSL](https://boringssl.googlesource.com/boringssl/) library.

## Versions

BoringSSL is vendored here, so each version of Mundane will depend on a
particular version of BoringSSL. Each new release will usually vendor the latest
version of BoringSSL in order to pick up bug fixes and improvements.

## Bindings

Rust bindings live in `boringssl.rs`. This file is included from the main
Mundane source code using a `#[path]` attribute.

These bindings are auto-generated using the `bindgen.sh` script, although some
manual intervention is required. In particular, after running `bindgen.sh`, each
public function must be annotated with a `#[link_name]` attribute (the reason
for these attributes is explained in the following section). For example, given
the following bindgen output:

```rust
extern "C" {
    pub fn CBS_init(cbs: *mut CBS, data: *const u8, len: usize);
}
```

We add a `#[link_name]` attribute as follows, where X.Y.Z is the current crate
version.

```rust
extern "C" {
    #[link_name = "__RUST_MUNDANE_X_Y_Z_CBS_init"]
    pub fn CBS_init(cbs: *mut CBS, data: *const u8, len: usize);
}
```

## Symbol Prefixing

Normally, the C build system does not allow multiple copies of the same codebase
to be linked together since the namespace for C symbols is global at link time.
In order to avoid this problem, we compile BoringSSL with a custom symbol prefix
specific to the crate version. This document describes the details of how this
works.

### Prefixing

Each BoringSSL symbol is given a prefix of `__RUST_MUNDANE_X_Y_Z_`, where the
current crate version number is X.Y.Z. This way, if two different versions of
the crate are present during a build, no C symbol will be defined under the same
name in both builds of BoringSSL.

### Two-phase build

BoringSSL's build system has built-in support for symbol prefixing. However, it
requires that the caller provide a list of symbols which need to be prefixed.
Since the set of symbols present is highly platform-dependent, a static list
would be very brittle and error-prone. Instead, we discover the symbols
dynamically at build time by doing a two-phase build.

In the first phase, we build BoringSSL as normal, with no symbol prefixing.
Then, the build script scrapes the list of symbols from the build artifacts.
Using this list, we run the build again - the second phase - this time using
BoringSSL's symbol prefixing feature. We use the artifacts from the second
build when performing the final Rust build.

### Library names

We instruct Rust to use the appropriate build artifacts using the linker path.
The linker path is used in a manner similar to the binary `$PATH` in Unix
systems. When a library is requested, the linker searches for a build artifact
of the appropriate name, stopping its search once it has found the appropriate
library. For example, given the argument `-l foo`, the linker would search for a
file called `libfoo.a`.

In order to ensure that the linker is able to find all copies of the BoringSSL
build artifacts, we give them unique names. If we didn't, only the first
artifact found in the filesystem would be used. Currently, we only link against
the `crypto` library, which, in the normal build system, is stored in
`libcrypto.a`. In order to make sure that all versions of this library are found
by the linker - one per version of the crate - we rename them just as we rename
symbols. For crate version x.y.z, we rename `libcrypto.a` to
`libcrypto_x_y_z.a`, and instruct the linker to look for the `crypto_x_y_z`
library.

### Testing

In order to test that symbol prefixing is working properly, use the
`test_symbol_conflicts.sh` script in this directory.
