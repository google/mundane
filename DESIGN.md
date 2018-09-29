<!-- Copyright 2018 Google LLC

Use of this source code is governed by an MIT-style
license that can be found in the LICENSE file or at
https://opensource.org/licenses/MIT. -->

# Design of Mundane

Mundane has the following design goals, in this order:
- To be difficult to misuse
- To be ergonomic
- To be performant

This document describes both the overall philosophy, and also specific design
patterns used to achieve these goals

# Philosophy

Cryptography is famously subtle and easy to get wrong. And when cryptography is
done wrong, the results can be catastrophic.

Experience has shown that most programmers, not being familiar with the
subtleties of cryptography, will unknowingly misuse cryptographic libraries if
they are allowed. This is one example of a broader trend - that it's difficult
to get something right if getting it wrong doesn't affect whether your program
runs. It's the same reason that error handling code is so often buggy in
otherwise well-written programs. Misuse of cryptography, like buggy error
handling, is unlikely to show up in tests, and unlikely to affect the
correctness of a program under normal conditions. But unlike error handling,
most programmers aren't familiar with the requirements of using cryptography
securely, and getting it wrong can be absolutely fatal.

Given this realization, Mundane takes the approach of giving the programmer the
fewest degrees of freedom possible. Doing the right thing should be easy and
feel natural. Doing the wrong thing should feel difficult and ideally be
entirely impossible. This philosophy motivates the design patterns which are
explored in the next section.

# Design Patterns

## Do work for the user

Some cryptographic operations have setup phases, require generating random
values, computing key schedules, etc. While many cryptographic APIs split these
into multiple steps that must be performed by the user in the right order,
prefer APIs which perform all setup steps on behalf of the user. This reduces
the opportunities for the user to make a mistake.

For example, the scrypt password-based key derivation function takes a salt.
When generating a key from a new password, the salt should always be randomly
generated anew. Instead of taking the salt as an argument, as many cryptographic
APIs do, we generate the salt as part of the generation function -
`scrypt_generate` - so that the user is not given the opportunity to improperly
generate it.

As another example, while scrypt can be used as a general-purpose key derivation
function, we expose it specifically for password verification. Thus, instead of
having the API expose the ability to take a password and a salt and generate a
hash, leaving it up to the user to verify that the calculated hash matches the
expected one, our API takes a password, a salt, and a hash, computes the new
hash, checks it against the expected one, and returns a boolean. Not only does
this ensure that the comparison is not accidentally skipped, it also allows us
to ensure that the comparison is performed using a constant-time comparison
function, which is a subtle detail that is often overlooked by users.

## Types

All cryptographic operations have data associated with them. A hash function
takes a byte sequence and outputs a digest. A signature functions takes a
private key and a digest, and outputs a signature.

These types of data usually have strict definitions of what operations are valid
or secure to perform on them. The Rust type system provides a powerful mechanism
to enforce that users cannot use these cryptographic objects other than as
intended.

### Opaque types

The easiest way to restrict the set of allowed operations on a type is to make
it opaque - that is, to create a struct with private fields, and provide only
the minimum set of methods or trait implementations needed. For example, instead
of representing a SHA-256 digest as a `[u8; 32]`, we represent it as an opaque
struct, `Sha256Digest`, which has a private `[u8; 32]` field.

Given such an opaque type, we can be judicious about methods or trait
implementations to provide. For example, a SHA-256 digest should be comparable
for equality with other SHA-256 digests, and so `Sha256Digest` implements `Eq`
for itself. However, comparing with digests from other hash functions is not a
cryptographically meaningful operation, so it doesn't implement `Eq` for other
types of digests. Similarly, the `EcdsaSignature` type provides only a
constructor and a getter, as no other operations (including comparison between
signatures) are meaningful.

It will usually be necessary to allow the user to access a non-opaque
representation (such as a byte array for hash digests). However, it is
sufficient to only provide constructors and getters. For example, the `Digest`
trait provides a `from_bytes(bytes: [u8; Self::DIGEST_LEN]) -> Self`
constructor, and a `bytes(&self) -> [u8; Self::DIGEST_LEN]` getter, but does not
provide, for example, `bytes_mut(&mut self) -> &mut [u8; Self::DIGEST_LEN]`.

### Use distinct types even if they have the same operations

Sometimes, distinct cryptographic objects will have the same representations and
operations allowed on them. For example, both RIPEMD-160 and SHA-1 produce
20-byte digests. Even if this happens, distinct Rust types should still be used.
Since it is never valid to compare a RIPEMD-160 digest to a SHA-1 digest,
representing them with the same Rust type would allow operations that are not
valid. Representing them with distinct Rust types ensures that they are not
spuriously used together in an invalid or insecure way.

### Use the most restrictive type

At some point, it will be necessary to accept or provide a non-opaque
representation so that input can be gathered from the outside world or output to
it. When this happens, use the most restrictive type in order to avoid having
to perform validation at runtime.

For example, hash digests have a fixed length. Thus, their constructors accept
(and their getters produce) fixed-length byte arrays. If, instead,
variable-length byte slices were used, it would be necessary a) to document the
length requirement, b) to validate the length during construction, and panic if
it failed, and c) to promise to the user to always produce slices of a
particular length. By using fixed-length arrays, we allow the type system to
guarantee that input will always be valid - so we don't need to perform any
validation - and to guarantee that the output will always conform to what is
documented - so the user doesn't need to simply trust our documentation.

### Put as much as possible in the type system

If a distinction exists between two cryptographic objects, always try to encode
that distinction in the type system if possible (of course, don't go over board;
ergonomics and other considerations are important too).

For example, most cryptography libraries provide a single elliptic curve private
key type. However, elliptic curve keys have a curve parameter, and two keys over
different curves are not interchangable - they might as well be completely
different cryptosystems. Thus, we provide a `PCurve` trait which is implemented
by various curve types, and our private key type, `EcKey` is parametrized on
such a type - `EcKey<C: PCurve>`.

## Errors

Error return values from cryptographic functions are an infamous source of
vulnerabilities. As with any system, the error handling logic of a program is
often the last consideration of a programmer, and is rarely exercised in tests.
More so than most systems, however, failure to properly handle errors from
cryptographic functions can easily lead to catastrophic vulnerabilities.

In order to avoid an opportunity for error values to be misused, we follow
the following design guidelines:
- Always use the Rust `Result` type to report errors. This may be a no-brainer,
  but it means that, if the user wants to extract the return value from a
  function, they *must* handle errors (at the very least, by calling `unwrap` or
  `expect`, and thus panicking on failure). This contrasts with a language like
  C, in which failing to check status return codes is easy and a common source
  of bugs.
- Collapse the distinction between "verification failed" and "verification
  encountered an error." When verifying cryptographic objects like comparing
  digests, verifying signatures, etc, there can sometimes be errors that are not
  the same as a verification failure. For example, a verification routine might
  fail to allocate memory, or it might fail to parse an encoded signature.
  Instead of having a verification routine provide three possible return values
  (verification succeeded, verification failed, or error encountered) we
  collapse the last two into a single one - verification failed. That way, the
  user is never given the opportunity to try to make subtle error-handling
  decisions that might lead to them mistakenly accepting an invalid signature as
  valid.
- If an error requires particularly subtle error-handling, prefer panicking or
  aborting the process. When cryptographic operations fail in a way that would
  require reporting an error to the user (in other words, there's no valid
  non-error interpretation like in the case of signature verification), and
  handling that failure is particularly error-prone, it may be justified to make
  the function's API infallible, and instead panic or abort the process on
  error. BoringSSL famously does this when failing to read randomness (e.g.,
  from `/dev/urandom`), as this has historically been a source of
  vulnerabilities.

## Attributes

Rust has two attributes which will cause compiler warnings in user code if
elements of the Mundane API are misused.
- The `#[must_use]` attribute on a function causes a compiler warning if a user
  calls the function and discards the result. We put this attribute on all
  functions which return values, as it is always suspicious to call a
  side-effect-free function and ignore its result (most of our functions which
  return values are side-effect free). This is especially useful in cases like
  signature or hash verification, where failure to check the return value from a
  function could lead to a catastrophic vulnerability (the iOS [`goto fail` TLS
  verification
  bug](https://nakedsecurity.sophos.com/2014/02/24/anatomy-of-a-goto-fail-apples-ssl-bug-explained-plus-an-unofficial-patch/)
  is a famous example of this).

  Similarly, `#[must_use]` on a type will cause a compiler warning if a user
  ever calls a function which returns that type and discards the result.
- The `#[deprecated]` attribute causes a warning whenever an item is imported or
  used anywhere in code. We make liberal use of this attribute for our insecure,
  legacy-only operations like SHA-1. See `CONTRIBUTING.md` for more details.