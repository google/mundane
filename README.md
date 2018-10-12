<!-- Copyright 2018 Google LLC

Use of this source code is governed by an MIT-style
license that can be found in the LICENSE file or at
https://opensource.org/licenses/MIT. -->

# Mundane

Mundane is a Rust cryptography library backed by BoringSSL that is difficult
to misuse, ergonomic, and performant (in that order).

## Issues and Contributions

We use [GitHub issues](https://github.com/google/mundane/issues) for issue
tracking, and
[Gerrit](https://fuchsia-review.googlesource.com/admin/repos/mundane) for code
reviews. See `CONTRIBUTING.md` for more details.

## Dependencies

Mundane vendors a copy of the BoringSSL source, so BoringSSL does not need to be
installed locally in order to build. However, the BoringSSL build system has the
following dependencies:
- [CMake](https://cmake.org/download/) 2.8.11 or later
- Perl 5.6.1 or later. See [BoringSSL's build
  instructions](https://boringssl.googlesource.com/boringssl/+/master/BUILDING.md)
  for what to do if CMake fails to find Perl on your system.
- Either Make or [Ninja](https://ninja-build.org/). Ninja is preferable, as it
  makes compilation significantly faster; if both are present, Ninja will be
  used. On Windows, Ninja is required.
- A C compiler
- Go 1.11 or later
- To build the x86 and x86_64 assembly, your assembler must support AVX2
  instructions and `MOVBE`. If using GNU binutils, you must have 2.22 or later.

In order to avoid errors at link time due to conflicting symbols, we build
BoringSSL with a custom prefix for all of its symbols which is based on the name
and version of this crate. That way, even if multiple different versions of
Mundane are present in the same dependency graph, none of the symbols from one
version's BoringSSL will conflict with the symbols from another version's
BoringSSL.

## Supported platforms

Mundane supports being built on and for Linux and Mac. Windows support is under
development. Cross-compilation is not supported.

## License

Everything outside of the `boringssl/boringssl` directory is licensed under an
MIT license which can be found in the `LICENSE` file. Everything in the
`boringssl/boringssl` directory is licensed with a license that can be found in
the `boringssl/boringssl/LICENSE` file.

Disclaimer: Mundane is not an officially supported Google product.
