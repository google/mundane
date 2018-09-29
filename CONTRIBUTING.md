<!-- Copyright 2018 Google LLC

Use of this source code is governed by an MIT-style
license that can be found in the LICENSE file or at
https://opensource.org/licenses/MIT. -->

# Contributing

## Code Guidelines

### Unsafe

`unsafe` is not allowed, except for in the `boringssl` module. We
`#[forbid(unsafe)]` in all other modules, so code that uses `unsafe` outside of
that module should fail to compile. For details on how to use `unsafe` in the
`boringssl` module, see the doc comment on that module.

### `#[must_use]`

The `#[must_use]` directive causes the compiler to emit a warning if code calls
a function but does not use its return value. It is a very useful lint against
failing to properly act on the result of cryptographic operations. A
`#[must_use]` directive should go on:
- All functions/methods (including in trait definitions) which return a value
  and are visible outside of the crate
- In the `boringssl` module:
  - All functions/methods (including in trait definitions) which return a value
    and are visible outside of the `boringssl` module or are exported from the
    `raw` or `wrapper` modules to the top-level `boringssl` module

`#[must_use]` may also be used on types, but should be evaluated on a
case-by-case basis. A few things to keep in mind:
- All functions defined in Mundane which return values have `#[must_use]` on
  them, so the case of a type returned by a function defined in Mundane is
  already covered.
- Unlike on functions, `#[must_use]` on types affects code other than the
  immediate caller since code outside of this crate may return types which are
  defined in this crate.

Thus, `#[must_use]` should only be used on a type when it's desired for
functions defined outside of this crate which return the type to have
`#[must_use]` behavior.

As a general rule of thumb, this should be restricted to types which could be
used to make security decisions. For example, digests and signatures should have
`#[must_use]`, while keys should not have it.

*TODO(joshlf): Re-evaluate this policy? Maybe we want to put `#[must_use]` on
more types?*

### Insecure

Some clients require access to insecure operations in order to interoperate with
legacy applications. While we provide these operations, we do so with a few
caveats:
- We only provide the bare minimum required. For example, while we provide
  HMAC-SHA1, we do not provide SHA-1 on its own, as it is not needed.
- We attempt to make it as difficult as possible for somebody to use an insecure
  operation unintentionally, as detailed in the next section.

#### Adding Insecure Operations

We use a number of mechanisms to make it less likely for somebody to use an
insecure operation unintentionally or without understanding the implications.
They are:
- Use of Rust's `#[deprecated]` attribute so that code which uses insecure
  operations will produce a compiler warning
- Naming of insecure types, functions, and methods with an "insecure" prefix so
  that their use will stand out in code, and their insecurity will stand out
  when reading their documentation
- Documentation comments that stress the operation's insecurity
- Placing all insecure operations in their own `insecure` module so that users
  are unlikely to accidentally come across an insecure operation while browsing
  other documentation
- Placing the `insecure` module behind a feature flag which is disabled by
  default

The whole is also more than the sum of the parts. Taken together, these
mechanisms serve to give an appropriate air of gravitas to insecure operations.
Users should feel uneasy - like they're wading into dangerous and subtle
territory (because they are!). They should be made to feel the gravity of the
situation, and to appreciate the importance of carefully considering whether
using an insecure operation is appropriate.

##### Deprecation

Rust provides the `#[deprecated]`
[attribute](https://doc.rust-lang.org/reference/attributes.html) which can be
placed on items including modules, types, functions, methods, and traits. If a
deprecated item is imported or used, it will cause a compiler warning (two,
actually - one for the import, and one for the use in code).

In Mundane, all insecure operations must be marked with a `#[deprecated]`
attribute with an appropriate message. This includes all items that a user could
ever interact with - types, functions, methods, etc. If it has a `pub` in front
of it, it needs a deprecation attribute. For example:

```rust
#[deprecated(note = "Foo is considered insecure")]
pub struct InsecureFooResult;

impl InsecureFooResult {
  #[deprecated(note = "Foo is considered insecure")]
  pub fn insecure_frobnicate(&self) { ... }
}

#[deprecated(note = "Foo is considered insecure")]
pub fn insecure_foo() -> InsecureFooResult { ... }
```

##### Naming

Every user-facing Rust item associated with an insecure operation carries an
"insecure" prefix on its name. For types and traits, this is of the form
`Insecure`, while for functions, methods, and modules, it's of the form
`insecure_`. See the example from the previous section for a demonstration of
this naming.

The justification for this is twofold. First, it makes it so that, while reading
documentation, it's unlikely for even a casual reader to miss that what they're
reading about is a special case that should be carefully considered. Second, it
makes it very obvious when reading or reviewing code that makes use of insecure
operations.

##### Documentation

Every documentation comment on an insecure operation should have the following
structure:

```rust
/// INSECURE: <summary of operation>
///
/// # Security
///
/// <operation> is considered insecure, and should only be used for compatibility
/// with legacy applications.
///
/// <further documentation if necessary>
```

As with naming, this serves to lessen the likelihood that a user will use an
insecure operation without realizing what they're doing.

##### Module Isolation

All insecure operations are exposed through a top-level `insecure` module, which
is itself marked with a deprecation attribute, and carries appropriate
module-level documentation.

Unfortunately, due to Rust's visibility rules, making this work involves a bit
of a dance. For reasons of practicality, insecure operations are defined
alongside their secure counterparts. For example, the `InsecureHmacSha1` type is
defined in the `hmac` module, and the `InsecureSha1Digest` type is defined in
the `hash` module. A programmer's first inclination might be to mark these as
`pub(crate)` and attempt to re-export them from the `insecure` module.
Unfortunately, Rust forbids this.

Instead, we take the somewhat circuitous approach of putting an insecure
operation inside of its own `pub(crate)` module (e.g.,
`hmac::insecure_hmac_sha1`). Inside of this module, the insecure operation can be
`pub` rather than `pub(crate)`. This, in turn, allows the `insecure` module to
re-export the item without running afoul of the compiler. It's an awkward dance,
but it makes it so that insecure operations can only be accessed through the
`insecure` module, which is a big win.

##### Feature Gating

By default, the `insecure` module is not present. The user must explicitly
enable the `insecure` feature in order to enable the module.

## Contributor License Agreement

Contributions to this project must be accompanied by a Contributor License
Agreement. You (or your employer) retain the copyright to your contribution;
this simply gives us permission to use and redistribute your contributions as
part of the project. Head over to <https://cla.developers.google.com/> to see
your current agreements on file or to sign a new one.

You generally only need to submit a CLA once, so if you've already submitted one
(even if it was for a different project), you probably don't need to do it
again.

## Code reviews

All submissions, including submissions by project members, require review. We
use GitHub pull requests for this purpose. Consult
[GitHub Help](https://help.github.com/articles/about-pull-requests/) for more
information on using pull requests.

## Community Guidelines

This project follows [Google's Open Source Community
Guidelines](https://opensource.google.com/conduct/).