// SPDX-License-Identifier: GPL-2.0

//! Output buffers for sysfs attributes.

use crate::prelude::*;
use core::{
    fmt,
    marker::PhantomData,
    ptr, //
};

/// A bounded, write-only attribute output buffer.
///
/// Writes preserve arbitrary bytes. Formatting is also available through [`fmt::Write`].
/// One byte is reserved for the terminating NUL and is not included in the returned length.
/// An individual write that does not fit returns `ENOSPC` without changing the output.
///
/// # Invariants
///
/// `start` points to `capacity + 1` exclusively writable bytes for `'a`, and `length` does not
/// exceed `capacity`. Only the first `length` bytes are assumed initialized.
pub struct Buffer<'a> {
    start: *mut u8,
    capacity: usize,
    length: usize,
    _exclusive: PhantomData<&'a mut [u8]>,
}

impl<'a> Buffer<'a> {
    /// Borrows storage supplied to a sysfs show callback.
    ///
    /// # Safety
    ///
    /// `start` must point to `size` exclusively writable bytes valid for `'a`, and `size` must
    /// be nonzero. The bytes need not be initialized.
    #[inline]
    #[cfg_attr(not(any(CONFIG_INFINIBAND, CONFIG_RUST_KUNIT_TESTS)), allow(dead_code))]
    pub(crate) unsafe fn new(start: *mut u8, size: usize) -> Self {
        // INVARIANT: The caller provides exclusive storage, with one byte reserved for NUL.
        Self {
            start,
            capacity: size - 1,
            length: 0,
            _exclusive: PhantomData,
        }
    }

    /// Appends bytes without UTF-8 conversion or escaping.
    #[inline]
    pub fn write_bytes(&mut self, bytes: &[u8]) -> Result {
        if bytes.len() > self.capacity - self.length {
            return Err(ENOSPC);
        }
        if !bytes.is_empty() {
            // SAFETY: The invariant and check provide exclusive space for the complete copy.
            // The source cannot overlap this exclusively borrowed output storage.
            unsafe {
                ptr::copy_nonoverlapping(bytes.as_ptr(), self.start.add(self.length), bytes.len());
            }
            self.length += bytes.len();
        }
        Ok(())
    }

    /// Terminates the output and returns its length, excluding the NUL.
    #[inline]
    #[cfg_attr(not(any(CONFIG_INFINIBAND, CONFIG_RUST_KUNIT_TESTS)), allow(dead_code))]
    pub(crate) fn finish(self) -> usize {
        // SAFETY: The invariant reserves this byte, including when the output is full.
        unsafe { self.start.add(self.length).write(0) };
        self.length
    }
}

impl fmt::Write for Buffer<'_> {
    #[inline]
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.write_bytes(value.as_bytes()).map_err(|_| fmt::Error)
    }
}

#[cfg(CONFIG_RUST_KUNIT_TESTS)]
#[crate::macros::kunit_tests(rust_sysfs_buffer)]
mod tests {
    use super::*;

    #[test]
    fn bounds_and_bytes() -> Result {
        let mut storage = [0xa5; 8];
        // SAFETY: The middle six bytes remain exclusively available until finish consumes it.
        let mut output = unsafe { Buffer::new(storage.as_mut_ptr().add(1), 6) };
        output.write_bytes(&[0xff, 0x80])?;
        assert_eq!(output.write_bytes(b"long"), Err(ENOSPC));
        output.write_bytes(b"abc")?;
        output.write_bytes(b"")?;
        assert_eq!(output.write_bytes(b"!"), Err(ENOSPC));
        assert_eq!(output.finish(), 5);
        assert_eq!(storage, [0xa5, 0xff, 0x80, b'a', b'b', b'c', 0, 0xa5]);
        Ok(())
    }

    #[test]
    fn empty_output_and_formatting() -> Result {
        use core::fmt::Write;

        let mut storage = [0xa5; 8];
        // SAFETY: The first byte is exclusively available until finish consumes the buffer.
        let mut output = unsafe { Buffer::new(storage.as_mut_ptr(), 1) };
        assert_eq!(output.write_bytes(b"!"), Err(ENOSPC));
        assert_eq!(output.finish(), 0);
        assert_eq!(storage, [0, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5]);

        // SAFETY: The full array is exclusively available until finish consumes the buffer.
        let mut output = unsafe { Buffer::new(storage.as_mut_ptr(), storage.len()) };
        writeln!(output, "{:04x}", 0x2a).map_err(|_| ENOSPC)?;
        assert_eq!(output.finish(), 5);
        assert_eq!(&storage[..6], b"002a\n\0");
        Ok(())
    }
}
