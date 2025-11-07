// Licensed under the Apache-2.0 license

//! Memory management abstraction

use crate::error::{OsalError, OsalResult};

#[cfg(feature = "std")]
use std::alloc::Layout;

/// Memory buffer abstraction
pub struct Buffer {
    data: *mut u8,
    size: usize,
    capacity: usize,
}

impl Buffer {
    /// Create a new buffer with specified capacity
    pub fn new(capacity: usize) -> OsalResult<Self> {
        let allocator = get_allocator();
        let data = allocator.alloc(capacity)?;
        Ok(Self {
            data,
            size: 0,
            capacity,
        })
    }

    /// Create buffer from existing data
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// - `data` is a valid pointer to allocated memory of at least `capacity` bytes
    /// - The memory is properly aligned for u8 access
    /// - The caller has exclusive ownership of the memory
    /// - The memory will not be freed by other code while this Buffer exists
    pub unsafe fn from_raw(data: *mut u8, size: usize, capacity: usize) -> Self {
        Self {
            data,
            size,
            capacity,
        }
    }

    /// Get buffer data as slice
    pub fn as_slice(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.data, self.size) }
    }

    /// Get buffer data as mutable slice
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.data, self.size) }
    }

    /// Get buffer capacity
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Get current buffer size
    pub fn len(&self) -> usize {
        self.size
    }

    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// Set buffer size (must be <= capacity)
    pub fn set_len(&mut self, new_len: usize) -> OsalResult<()> {
        if new_len > self.capacity {
            return Err(OsalError::InvalidParameter);
        }
        self.size = new_len;
        Ok(())
    }

    /// Clear buffer (set size to 0)
    pub fn clear(&mut self) {
        self.size = 0;
    }

    /// Resize buffer
    pub fn resize(&mut self, new_capacity: usize) -> OsalResult<()> {
        if new_capacity < self.size {
            return Err(OsalError::InvalidParameter);
        }

        let allocator = get_allocator();
        let new_data = allocator.alloc(new_capacity)?;

        // Copy existing data
        if self.size > 0 {
            unsafe {
                core::ptr::copy_nonoverlapping(self.data, new_data, self.size);
            }
        }

        // Free old data
        if !self.data.is_null() {
            unsafe {
                allocator.dealloc(self.data, self.capacity);
            }
        }

        self.data = new_data;
        self.capacity = new_capacity;
        Ok(())
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        if !self.data.is_null() {
            let allocator = get_allocator();
            unsafe {
                allocator.dealloc(self.data, self.capacity);
            }
        }
    }
}

unsafe impl Send for Buffer {}
unsafe impl Sync for Buffer {}

/// Memory allocator trait
pub trait Allocator: Send + Sync {
    /// Allocate memory
    fn alloc(&self, size: usize) -> OsalResult<*mut u8>;

    /// Deallocate memory
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// - `ptr` was allocated by the same allocator
    /// - `size` matches the original allocation size
    /// - `ptr` is not used after this call
    unsafe fn dealloc(&self, ptr: *mut u8, size: usize);

    /// Reallocate memory
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// - `ptr` was allocated by the same allocator (or is null)
    /// - `old_size` matches the original allocation size
    /// - `ptr` is not used after this call unless the function returns an error
    unsafe fn realloc(
        &self,
        ptr: *mut u8,
        old_size: usize,
        new_size: usize,
    ) -> OsalResult<*mut u8> {
        let new_ptr = self.alloc(new_size)?;
        if !ptr.is_null() {
            let copy_size = core::cmp::min(old_size, new_size);
            core::ptr::copy_nonoverlapping(ptr, new_ptr, copy_size);
            self.dealloc(ptr, old_size);
        }
        Ok(new_ptr)
    }
}

/// Standard library allocator implementation
#[cfg(feature = "std")]
pub struct StdAllocator;

#[cfg(feature = "std")]
impl Allocator for StdAllocator {
    fn alloc(&self, size: usize) -> OsalResult<*mut u8> {
        if size == 0 {
            return Ok(core::ptr::null_mut());
        }

        let layout = Layout::from_size_align(size, 8).map_err(|_| OsalError::InvalidParameter)?;

        let ptr = unsafe { std::alloc::alloc(layout) };
        if ptr.is_null() {
            Err(OsalError::OutOfMemory)
        } else {
            Ok(ptr)
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, size: usize) {
        if !ptr.is_null() && size > 0 {
            let layout = Layout::from_size_align_unchecked(size, 8);
            std::alloc::dealloc(ptr, layout);
        }
    }
}

/// Simple fixed-size pool allocator for no_std environments
#[cfg(not(feature = "std"))]
pub struct PoolAllocator {
    pool: *mut u8,
    size: usize,
    offset: core::sync::atomic::AtomicUsize,
}

#[cfg(not(feature = "std"))]
impl PoolAllocator {
    pub fn new(pool: *mut u8, size: usize) -> Self {
        Self {
            pool,
            size,
            offset: core::sync::atomic::AtomicUsize::new(0),
        }
    }
}

#[cfg(not(feature = "std"))]
impl Allocator for PoolAllocator {
    fn alloc(&self, size: usize) -> OsalResult<*mut u8> {
        if size == 0 {
            return Ok(core::ptr::null_mut());
        }

        let aligned_size = (size + 7) & !7; // 8-byte alignment
        let current = self.offset.load(core::sync::atomic::Ordering::SeqCst);
        let new_offset = current + aligned_size;

        if new_offset > self.size {
            return Err(OsalError::OutOfMemory);
        }

        match self.offset.compare_exchange(
            current,
            new_offset,
            core::sync::atomic::Ordering::SeqCst,
            core::sync::atomic::Ordering::SeqCst,
        ) {
            Ok(_) => {
                let ptr = unsafe { self.pool.add(current) };
                Ok(ptr)
            }
            Err(_) => self.alloc(size), // Retry
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _size: usize) {
        // Simple pool allocator doesn't support individual deallocation
        // In a real implementation, you might use a more sophisticated algorithm
    }
}

static mut ALLOCATOR: Option<&'static dyn Allocator> = None;

/// Initialize memory subsystem
pub fn init(_pool_size: usize) -> OsalResult<()> {
    #[cfg(feature = "std")]
    {
        static STD_ALLOCATOR: StdAllocator = StdAllocator;
        unsafe {
            ALLOCATOR = Some(&STD_ALLOCATOR as &dyn Allocator);
        }
    }

    #[cfg(not(feature = "std"))]
    {
        // In a real no_std implementation, you would set up your custom allocator here
        // For now, we'll just return an error
        return Err(OsalError::ResourceUnavailable);
    }

    Ok(())
}

/// Cleanup memory subsystem
pub fn cleanup() -> OsalResult<()> {
    unsafe {
        ALLOCATOR = None;
    }
    Ok(())
}

/// Get the current allocator
fn get_allocator() -> &'static dyn Allocator {
    unsafe { ALLOCATOR.expect("Memory subsystem not initialized") }
}

/// Allocate memory using the current allocator
pub fn alloc(size: usize) -> OsalResult<*mut u8> {
    get_allocator().alloc(size)
}

/// Deallocate memory using the current allocator
///
/// # Safety
///
/// The caller must ensure that:
/// - `ptr` was allocated by the current allocator
/// - `size` matches the original allocation size
/// - `ptr` is not used after this call
pub unsafe fn dealloc(ptr: *mut u8, size: usize) {
    get_allocator().dealloc(ptr, size);
}

/// Allocate and zero memory
pub fn alloc_zeroed(size: usize) -> OsalResult<*mut u8> {
    let ptr = alloc(size)?;
    unsafe {
        core::ptr::write_bytes(ptr, 0, size);
    }
    Ok(ptr)
}
