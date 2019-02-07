// Copyright 2018 Google LLC
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

use std::marker::PhantomData;
use std::mem;
use std::ptr::NonNull;

/// A trait that can be used to ensure that users of the boringssl module can't
/// implement a trait.
///
/// See the [API Guidelines] for details.
///
/// [API Guidelines]: https://rust-lang-nursery.github.io/api-guidelines/future-proofing.html#sealed-traits-protect-against-downstream-implementations-c-sealed
pub trait Sealed {}

macro_rules! sealed {
    ($name:ident) => {
        impl ::boringssl::wrapper::Sealed for ::boringssl::raw::ffi::$name {}
    };
}

macro_rules! impl_traits {
    (@inner $name:ident, CNew => $fn:tt) => {
        c_new!($name, $fn);
    };
    (@inner $name:ident, CUpRef => $fn:tt) => {
        c_up_ref!($name, $fn);
    };
    (@inner $name:ident, CFree => $fn:tt) => {
        c_free!($name, $fn);
    };
    (@inner $name:ident, CInit => $fn:tt) => {
        c_init!($name, $fn);
    };
    (@inner $name:ident, CDestruct => $fn:tt) => {
        c_destruct!($name, $fn);
    };
    (@inner $name:ident, $trait:ident => $fn:tt) => {
        compile_error!(concat!("unrecognized trait ", stringify!($trait)));
    };
    ($name:ident, $($trait:ident => $fn:tt),*) => {
        sealed!($name);
        $(impl_traits!(@inner $name, $trait => $fn);)*
    };
}

/// A C object from the BoringSSL API which can be allocated and constructed.
pub unsafe trait CNew: Sealed {
    /// Returns a new, constructed, heap-allocated object, or NULL on failure.
    ///
    /// This should not be called directly; instead, use `new`.
    #[deprecated(note = "do not call new_raw directly; instead, call new")]
    unsafe fn new_raw() -> *mut Self;

    /// Returns a new, constructed, heap-allocated object, or `None` on failure.
    #[must_use]
    unsafe fn new() -> Option<NonNull<Self>> {
        #[allow(deprecated)]
        NonNull::new(Self::new_raw())
    }
}

macro_rules! c_new {
    ($name:ident, $new:ident) => {
        unsafe impl ::boringssl::wrapper::CNew for ::boringssl::raw::ffi::$name {
            unsafe fn new_raw() -> *mut Self {
                ::boringssl::raw::ffi::$new()
            }
        }
    };
}

/// A C object from the BoringSSL API which has a reference count that can be
/// increased.
pub unsafe trait CUpRef: Sealed {
    /// Increases an object's reference count.
    unsafe fn up_ref(slf: *mut Self);
}

macro_rules! c_up_ref {
    ($name:ident, $up_ref:ident) => {
        unsafe impl ::boringssl::wrapper::CUpRef for ::boringssl::raw::ffi::$name {
            unsafe fn up_ref(slf: *mut Self) {
                use boringssl::abort::UnwrapAbort;
                ::boringssl::raw::one_or_err(
                    stringify!($up_ref),
                    ::boringssl::raw::ffi::$up_ref(slf),
                )
                .unwrap_abort()
            }
        }
    };
}

/// A C object from the BoringSSL API which can be freed.
pub unsafe trait CFree: Sealed {
    /// Frees a heap-allocated object.
    ///
    /// If this is a reference-counted object, `free` decrements the reference
    /// count, and frees the object if it reaches zero. Otherwise, if this is
    /// not a reference-counted object, it frees it.
    unsafe fn free(slf: *mut Self);
}

macro_rules! c_free {
    ($name:ident, $free:ident) => {
        unsafe impl ::boringssl::wrapper::CFree for ::boringssl::raw::ffi::$name {
            unsafe fn free(slf: *mut Self) {
                ::boringssl::raw::ffi::$free(slf)
            }
        }
    };
}

/// A C object from the BoringSSL API which can be initialized.
pub unsafe trait CInit: Sealed {
    /// Initializes an uninitialized object.
    ///
    /// # Safety
    ///
    /// `init` must not be called on an initialized object.
    unsafe fn init(slf: *mut Self);
}

#[allow(unused)] // TODO: Remove once it's used in the 'raw' module
macro_rules! c_init {
    ($name:ident, $init:ident) => {
        unsafe impl ::boringssl::wrapper::CInit for ::boringssl::raw::ffi::$name {
            unsafe fn init(slf: *mut Self) {
                ::boringssl::raw::ffi::$init(slf)
            }
        }
    };
}

/// A C object from the BoringSSL API which can be destructed.
pub unsafe trait CDestruct: Sealed {
    /// Destructs an initialized object.
    ///
    /// # Safety
    ///
    /// `slf` must be an initialized object. After a call to `destruct`, `slf`
    /// is uninitialized.
    unsafe fn destruct(slf: *mut Self);
}

macro_rules! c_destruct {
    ($name:ident, _) => {
        unsafe impl ::boringssl::wrapper::CDestruct for ::boringssl::raw::ffi::$name {
            unsafe fn destruct(_slf: *mut Self) {}
        }
    };
    ($name:ident, $destruct:tt) => {
        unsafe impl ::boringssl::wrapper::CDestruct for ::boringssl::raw::ffi::$name {
            unsafe fn destruct(slf: *mut Self) {
                ::boringssl::raw::ffi::$destruct(slf)
            }
        }
    };
}

/// A wrapper around a pointer to a heap-allocated, constructed C object from
/// the BoringSSL API.
///
/// `CHeapWrapper` maintains the invariant that the object it references is
/// always allocated and constructed. This means that:
/// - If the object can be reference counted, `CHeapWrapper` implements `Clone`
///   by incrementing the reference count, and decrementing on `Drop`.
/// - If the object cannot be reference counted, `CHeapWrapper` does not
///   implement `Clone`, but will still free the object on `Drop`.
///
/// `CHeapWrapper`s are not thread-safe; they do not implement `Send` or `Sync`.
pub struct CHeapWrapper<C: CFree> {
    // NOTE: NonNull ensures that CHeapWrapper is !Send + !Sync. If this struct
    // is changed, make sure it's still !Send + !Sync.
    obj: NonNull<C>,
}

impl<C: CFree> CHeapWrapper<C> {
    /// Takes ownership of a constructed object.
    ///
    /// # Safety
    ///
    /// `obj` must point to an allocated, constructed object. The caller must
    /// ensure that, when the returned `CHeapWrapper` is dropped, it is safe to
    /// call `C::free` on `obj`. In most cases, this means that the caller
    /// should not free `obj`, and instead consider ownership of `obj` to have
    /// transferred to the new `CHeapWrapper`.
    ///
    /// The caller must also ensure that no pointers to the object will ever be
    /// used by other threads so long as this `CHeapWrapper` exists.
    #[must_use]
    pub unsafe fn new_from(obj: NonNull<C>) -> CHeapWrapper<C> {
        CHeapWrapper { obj }
    }

    #[must_use]
    pub fn as_mut(&mut self) -> *mut C {
        self.obj.as_ptr()
    }

    #[must_use]
    pub fn as_const(&self) -> *const C {
        self.obj.as_ptr()
    }

    /// Consumes this `CHeapWrapper` and return the underlying pointer.
    ///
    /// The object will not be freed. Instead, the caller takes logical
    /// ownership of the object.
    #[must_use]
    pub fn into_mut(self) -> *mut C {
        // NOTE: This method safe for the same reason that mem::forget is safe:
        // it's equivalent to sending it to a thread that goes to sleep forever
        // or creating a Rc cycle or some other silly-but-safe behavior.
        let ptr = self.obj.as_ptr();
        mem::forget(self);
        ptr
    }
}

impl<C: CNew + CFree> Default for CHeapWrapper<C> {
    fn default() -> CHeapWrapper<C> {
        // TODO(joshlf): In order for this to be safe, CNew must provide the
        // safety guarantee that it's always safe to call CNew::new and then
        // later to call CFree::free on that object (e.g., see the safety
        // comment on CStackWrapper::new).
        unsafe {
            use boringssl::abort::UnwrapAbort;
            let obj = C::new().expect_abort("could not allocate object");
            CHeapWrapper { obj }
        }
    }
}

impl<C: CUpRef + CFree> Clone for CHeapWrapper<C> {
    fn clone(&self) -> CHeapWrapper<C> {
        unsafe { C::up_ref(self.obj.as_ptr()) };
        CHeapWrapper { obj: self.obj }
    }
}

impl<C: CFree> Drop for CHeapWrapper<C> {
    fn drop(&mut self) {
        unsafe { C::free(self.obj.as_ptr()) };
    }
}

/// A wrapper around a pointer to a C object from the BoringSSL API.
///
/// Unlike `CHeapWrapper` or `CStackWrapper`, `CRef` does not own the pointed-to
/// object, but merely borrows it like a normal Rust reference. The only reason
/// to use `CRef<C>` instead of a `&C` is to make it so that access to the `C`
/// is unsafe, as `CRef` only exposes a raw pointer accessor for its object.
///
/// `CRef` maintains the invariant that the object it references is always
/// allocated and constructed, and that mutable access to the object is disabled
/// for the lifetime of the `CRef`.
pub struct CRef<'a, C> {
    // NOTE: NonNull ensures that CHeapWrapper is !Send + !Sync. If this struct
    // is changed, make sure it's still !Send + !Sync.
    obj: NonNull<C>,
    // Make sure CRef has the lifetime 'a.
    _lifetime: PhantomData<&'a ()>,
}

impl<'a, C> CRef<'a, C> {
    /// Creates a new `CRef` from a raw pointer.
    ///
    /// # Safety
    ///
    /// `obj` must point to an allocated, constructed object. The caller must
    /// ensure that, for the lifetime, `'a`, `obj` will continue to point to the
    /// same allocated, constructed object, and that mutable access to the
    /// object will be disallowed.
    ///
    /// The caller must also ensure that no other pointers to the object will
    /// ever be sent to other threads so long as this `CRef` exists.
    #[must_use]
    pub unsafe fn new(obj: NonNull<C>) -> CRef<'a, C> {
        CRef { obj, _lifetime: PhantomData }
    }

    #[must_use]
    pub fn as_const(&self) -> *const C {
        self.obj.as_ptr()
    }
}

/// A wrapper around a constructed C object from the BoringSSL API.
///
/// `CStackWrapper` maintains the invariant that the object it contains is
/// always constructed. The object is destructed on `Drop`.
///
/// `CStackWrapper`s are not thread-safe; they do not implement `Send` or
/// `Sync`.
pub struct CStackWrapper<C: CDestruct> {
    obj: C,
    // Make sure CStackWrapper doesn't implement Send or Sync regardless of C.
    _no_sync: PhantomData<*mut ()>,
}

impl<C: CDestruct> CStackWrapper<C> {
    /// Constructs a new `CStackWrapper`.
    ///
    /// # Safety
    ///
    /// `obj` must be constructed, and it must be safe for `C::destruct` to be
    /// called on `obj` when this `CStackWrapper` is dropped.
    #[must_use]
    pub unsafe fn new(obj: C) -> CStackWrapper<C> {
        CStackWrapper { obj, _no_sync: PhantomData }
    }

    #[must_use]
    pub fn as_c_ref(&mut self) -> CRef<C> {
        unsafe { CRef::new(NonNull::new_unchecked(&mut self.obj as *mut C)) }
    }

    #[must_use]
    pub fn as_mut(&mut self) -> *mut C {
        &mut self.obj
    }

    #[must_use]
    pub fn as_const(&self) -> *const C {
        &self.obj
    }
}

impl<C: CInit + CDestruct> Default for CStackWrapper<C> {
    // TODO(joshlf): In order for this to be safe, CInit must provide the safety
    // guarantee that it's always safe to call CInit::init and then later to
    // call CDestruct::destruct on that object (e.g., see the safety comment on
    // CStackWrapper::new).
    fn default() -> CStackWrapper<C> {
        unsafe {
            let mut obj: C = mem::uninitialized();
            C::init(&mut obj);
            CStackWrapper { obj, _no_sync: PhantomData }
        }
    }
}

impl<C: CDestruct> Drop for CStackWrapper<C> {
    fn drop(&mut self) {
        unsafe { C::destruct(&mut self.obj) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boringssl::EC_KEY;

    #[test]
    fn test_heap_wrapper_into_mut() {
        // Test that CHeapWrapper::into_mut doesn't free the pointer. If it
        // does, then EC_KEY::free is likely (though not guaranteed) to abort
        // when it finds the refcount at 0.
        let key = CHeapWrapper::<EC_KEY>::default();
        unsafe { EC_KEY::free(key.into_mut()) };
    }
}
