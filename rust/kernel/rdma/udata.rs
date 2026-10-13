// SPDX-License-Identifier: GPL-2.0

//! Bounded userspace request and response buffers for provider callbacks.
//!
//! C header: [`include/rdma/uverbs_ioctl.h`](srctree/include/rdma/uverbs_ioctl.h)

use super::{
    UserContextOperations,
    UserContexts, //
};
use crate::{
    bindings,
    error::{
        code::EINVAL,
        to_result,
        Result, //
    },
    types::ForeignOwnable,
    uaccess::{
        UserPtr,
        UserSlice,
        UserSliceWriter, //
    }, //
};
use core::{
    marker::PhantomData,
    ptr::NonNull, //
};

/// The driver data supplied by a userspace verbs call for provider `T`.
///
/// Splitting the descriptor transfers its input and output to separate bounded accessors.
/// Accessing either buffer may sleep and uses the current task's userspace address space.
/// The provider parameter keeps calls to the RDMA core in the provider's crate, including
/// when the core is built as a module.
pub struct UserData<'a, T> {
    input: UserInput<'a, T>,
    output: UserSliceWriter,
}

impl<T: UserContextOperations> UserData<'_, T> {
    /// Borrows the initialized private context attached to this userspace call.
    ///
    /// # Safety
    ///
    /// The context must belong to [`UserContexts::<T>`] and its creation callback must have
    /// completed. This must not be called from context creation or after disassociation. The
    /// original uverbs bundle must retain that context and exclude release for this borrow.
    #[inline]
    pub unsafe fn context(&self) -> Result<<T::Context as ForeignOwnable>::Borrowed<'_>> {
        // SAFETY: The descriptor invariant retains its original bundle. The caller supplies
        // the additional initialized-context contract required to borrow its foreign owner.
        unsafe {
            let attrs = crate::container_of!(
                self.input.data.as_ptr(),
                bindings::uverbs_attr_bundle,
                __bindgen_anon_1.__bindgen_anon_1.driver_udata
            );
            let context = (*attrs).__bindgen_anon_1.__bindgen_anon_1.context;
            if context.is_null() {
                return Err(EINVAL);
            }
            Ok(UserContexts::<T>::data(context))
        }
    }
}

/// Driver data accompanied by a successfully initialized userspace context.
///
/// Unlike context creation, callbacks receiving this value may safely borrow the provider's
/// context owner.
///
/// # Invariants
///
/// The core retains the initialized context and excludes release and disassociation for
/// `'a`. Its provider is `T`, and `data` retains a borrow of the original uverbs bundle.
pub struct ContextData<'a, T: UserContextOperations> {
    data: UserData<'a, T>,
    context: NonNull<bindings::ib_ucontext>,
}

impl<'a, T: UserContextOperations> ContextData<'a, T> {
    /// Borrows an optional original uverbs descriptor and its initialized context.
    ///
    /// # Safety
    ///
    /// The requirements of [`UserData::from_raw`] apply. A present context must belong to
    /// [`UserContexts::<T>`], have completed creation, and remain alive with release attempts
    /// and disassociation excluded for `'a`. This must not be used during context creation.
    pub unsafe fn from_raw(data: *mut bindings::ib_udata) -> Result<Option<Self>> {
        // SAFETY: The caller retains the original descriptor and containing bundle.
        let Some(data) = (unsafe { UserData::from_raw(data) }) else {
            return Ok(None);
        };
        // SAFETY: The descriptor is a member of the original, live uverbs bundle.
        let context = unsafe {
            let attrs = crate::container_of!(
                data.input.data.as_ptr(),
                bindings::uverbs_attr_bundle,
                __bindgen_anon_1.__bindgen_anon_1.driver_udata
            );
            (*attrs).__bindgen_anon_1.__bindgen_anon_1.context
        };
        // INVARIANT: The caller retains the initialized context and its bundle for 'a.
        Ok(Some(Self {
            data,
            context: NonNull::new(context).ok_or(EINVAL)?,
        }))
    }

    /// Separates the context borrow from the consumable userspace buffers.
    #[inline]
    pub fn split(
        self,
    ) -> (
        <T::Context as ForeignOwnable>::Borrowed<'a>,
        UserData<'a, T>,
    ) {
        // SAFETY: Construction guarantees that the core retains the initialized context and
        // excludes release for 'a. Neither returned value owns or releases that core lifetime.
        (
            unsafe { UserContexts::<T>::data(self.context.as_ptr()) },
            self.data,
        )
    }
}

impl<'a, T> UserData<'a, T> {
    /// Borrows an optional driver-data descriptor from a provider callback.
    ///
    /// A null pointer denotes a kernel caller and returns `None`.
    ///
    /// # Safety
    ///
    /// A non-null `data` must be the initialized `driver_udata` member of a live
    /// `uverbs_attr_bundle` for provider `T`. Its metadata and containing bundle must remain
    /// valid and unchanged for `'a`. When either buffer is nonempty, the uverbs disassociation
    /// SRCU lock must be held. An empty cleanup descriptor may instead be retained by the
    /// core's destruction lock. A standalone `ib_udata` does not suffice: context access and
    /// core error reporting use the containing bundle. User bytes may change at any time.
    pub unsafe fn from_raw(data: *mut bindings::ib_udata) -> Option<Self> {
        let data = NonNull::new(data)?;
        // SAFETY: The caller provides initialized, stable descriptor metadata. User pointers
        // are not dereferenced here; the output writer checks them when accessed.
        let output = unsafe {
            UserSlice::new(
                UserPtr::from_ptr((*data.as_ptr()).outbuf),
                (*data.as_ptr()).outlen,
            )
            .writer()
        };
        Some(Self {
            // INVARIANT: The caller retains the original descriptor and its uverbs bundle.
            input: UserInput {
                data,
                _borrow: PhantomData,
                _provider: PhantomData,
            },
            output,
        })
    }

    /// Returns whether the caller supplied a non-null output buffer.
    ///
    /// This reports the descriptor's address independently of its length. Providers with a
    /// legacy null-buffer sentinel may still validate the length before omitting their reply.
    #[inline]
    pub fn has_output_buffer(&self) -> bool {
        // SAFETY: The input invariant retains the descriptor's immutable metadata.
        unsafe { !(*self.input.data.as_ptr()).outbuf.is_null() }
    }

    /// Consumes this descriptor, yielding a request reader and response writer.
    #[inline]
    pub fn split(self) -> (UserInput<'a, T>, UserSliceWriter) {
        (self.input, self.output)
    }
}

/// A userspace provider request which can be copied and validated once.
///
/// # Invariants
///
/// `data` points to the initialized driver-data member of a live uverbs bundle belonging to
/// `T`. The descriptor and bundle remain stable for `'a`. Nonempty buffers require the
/// disassociation SRCU lock; empty cleanup descriptors do not enter core error reporting.
pub struct UserInput<'a, T> {
    data: NonNull<bindings::ib_udata>,
    _borrow: PhantomData<&'a bindings::ib_udata>,
    _provider: PhantomData<T>,
}

impl<T> UserInput<'_, T> {
    /// Returns the size of the request supplied by userspace.
    #[inline]
    pub fn len(&self) -> usize {
        // SAFETY: The invariant keeps initialized descriptor metadata stable.
        unsafe { (*self.data.as_ptr()).inlen }
    }

    /// Returns whether userspace supplied an empty request.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Copies the request into initialized bytes, consuming this reader.
    ///
    /// Requires at least `minimum` input bytes. If the input is shorter than `request`, the
    /// remaining destination bytes are zeroed. Bytes beyond the destination length in a longer
    /// input must all be zero, otherwise this returns `EOPNOTSUPP`. Inaccessible input returns
    /// `EFAULT`. The destination may have changed on failure.
    ///
    /// Decode and validate the copied bytes rather than reading userspace again. This method
    /// does not provide an atomic snapshot against concurrent userspace writes.
    pub fn read(self, request: &mut [u8], minimum: usize) -> Result {
        if minimum > request.len() {
            return Err(EINVAL);
        }
        // Automatic object cleanup supplies empty buffers without the command SRCU guard.
        // Handle them locally: the core's diagnostic helpers require a live command bundle.
        if self.is_empty() {
            if minimum != 0 {
                return Err(EINVAL);
            }
            request.fill(0);
            return Ok(());
        }
        // SAFETY: The invariant retains the original uverbs bundle, including the metadata
        // used for error reporting. The destination is writable for its entire supplied size;
        // every byte pattern is valid, and the core bounds the copy and checks extension bytes.
        to_result(unsafe {
            bindings::_ib_copy_validate_udata_in(
                self.data.as_ptr(),
                request.as_mut_ptr().cast(),
                request.len(),
                minimum,
            )
        })
    }
}

#[cfg(all(
    CONFIG_RUST_KUNIT_TESTS,
    CONFIG_INFINIBAND = "y",
    CONFIG_INFINIBAND_USER_ACCESS_CORE
))]
#[crate::macros::kunit_tests(rust_rdma_cleanup_data)]
mod tests {
    use super::*;

    #[test]
    fn empty_cleanup_input_avoids_command_diagnostics() {
        let mut bundle = bindings::uverbs_attr_bundle::default();
        // SAFETY: The zeroed bundle owns initialized, empty driver-data fields.
        let raw = unsafe { &raw mut bundle.__bindgen_anon_1.__bindgen_anon_1.driver_udata };
        let mut output = [0xa5; 4];
        // SAFETY: The bundle and empty descriptor remain live without a command SRCU guard.
        let data = unsafe { UserData::<()>::from_raw(raw) }.unwrap();
        assert_eq!(data.split().0.read(&mut output, 1), Err(EINVAL));
        assert_eq!(output, [0xa5; 4]);
        // SAFETY: The same stable, empty cleanup descriptor is borrowed again.
        let data = unsafe { UserData::<()>::from_raw(raw) }.unwrap();
        assert_eq!(data.split().0.read(&mut output, 0), Ok(()));
        assert_eq!(output, [0; 4]);
    }
}
