// Licensed under the Apache-2.0 license

//! Thread abstraction

use crate::error::{OsalError, OsalResult};

#[cfg(feature = "std")]
use std::thread as std_thread;

/// Thread ID type  
pub type ThreadId = u32;

/// Thread handle
pub struct ThreadHandle {
    #[cfg(feature = "std")]
    inner: Option<std_thread::JoinHandle<()>>,
    #[cfg(not(feature = "std"))]
    id: u32,
}

impl ThreadHandle {
    #[cfg(feature = "std")]
    pub fn join(mut self) -> OsalResult<()> {
        if let Some(handle) = self.inner.take() {
            handle
                .join()
                .map_err(|_| OsalError::Other("Thread join failed"))?;
        }
        Ok(())
    }

    #[cfg(not(feature = "std"))]
    pub fn join(self) -> OsalResult<()> {
        // In no_std, you would implement platform-specific thread joining
        Err(OsalError::ResourceUnavailable)
    }
}

/// Thread builder
pub struct ThreadBuilder {
    name: Option<&'static str>,
    stack_size: Option<usize>,
}

impl ThreadBuilder {
    pub fn new() -> Self {
        Self {
            name: None,
            stack_size: None,
        }
    }

    pub fn name(mut self, name: &'static str) -> Self {
        self.name = Some(name);
        self
    }

    pub fn stack_size(mut self, size: usize) -> Self {
        self.stack_size = Some(size);
        self
    }

    #[cfg(feature = "std")]
    pub fn spawn<F>(self, f: F) -> OsalResult<ThreadHandle>
    where
        F: FnOnce() + Send + 'static,
    {
        let mut builder = std_thread::Builder::new();

        if let Some(name) = self.name {
            builder = builder.name(name.to_string());
        }

        if let Some(stack_size) = self.stack_size {
            builder = builder.stack_size(stack_size);
        }

        let handle = builder
            .spawn(f)
            .map_err(|_| OsalError::ResourceUnavailable)?;

        Ok(ThreadHandle {
            inner: Some(handle),
        })
    }

    #[cfg(feature = "std")]
    pub fn spawn_box(self, f: Box<dyn FnOnce() + Send + 'static>) -> OsalResult<ThreadHandle> {
        let mut builder = std_thread::Builder::new();

        if let Some(name) = self.name {
            builder = builder.name(name.to_string());
        }

        if let Some(stack_size) = self.stack_size {
            builder = builder.stack_size(stack_size);
        }

        let handle = builder
            .spawn(f)
            .map_err(|_| OsalError::ResourceUnavailable)?;

        Ok(ThreadHandle {
            inner: Some(handle),
        })
    }

    #[cfg(not(feature = "std"))]
    pub fn spawn<F>(self, _f: F) -> OsalResult<ThreadHandle>
    where
        F: FnOnce() + Send + 'static,
    {
        // In no_std, you would implement platform-specific thread creation
        Err(OsalError::ResourceUnavailable)
    }
}

impl Default for ThreadBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Thread abstraction trait
pub trait Thread: Send + Sync {
    fn spawn(&self, f: Box<dyn FnOnce() + Send + 'static>) -> OsalResult<ThreadHandle>;
    fn current_id(&self) -> ThreadId;
    fn yield_now(&self);
}

/// Standard library thread implementation
#[cfg(feature = "std")]
pub struct StdThread;

#[cfg(feature = "std")]
impl Thread for StdThread {
    fn spawn(&self, f: Box<dyn FnOnce() + Send + 'static>) -> OsalResult<ThreadHandle> {
        ThreadBuilder::new().spawn_box(f)
    }

    fn current_id(&self) -> u32 {
        // Convert thread ID to u32 (this is a simplification)
        let id = std_thread::current().id();
        // This is a hack to convert ThreadId to u32
        format!("{:?}", id)
            .chars()
            .filter(|c| c.is_ascii_digit())
            .collect::<String>()
            .parse()
            .unwrap_or(0)
    }

    fn yield_now(&self) {
        std_thread::yield_now();
    }
}

static mut THREAD_IMPL: Option<&'static dyn Thread> = None;

/// Initialize thread subsystem
pub fn init(_max_threads: usize, _default_stack_size: usize) -> OsalResult<()> {
    #[cfg(feature = "std")]
    {
        static STD_THREAD: StdThread = StdThread;
        unsafe {
            THREAD_IMPL = Some(&STD_THREAD as &dyn Thread);
        }
    }

    #[cfg(not(feature = "std"))]
    {
        // In no_std, you would initialize your thread system here
        return Err(OsalError::ResourceUnavailable);
    }

    Ok(())
}

/// Cleanup thread subsystem
pub fn cleanup() -> OsalResult<()> {
    unsafe {
        THREAD_IMPL = None;
    }
    Ok(())
}

/// Get current thread implementation
fn get_thread() -> &'static dyn Thread {
    unsafe { THREAD_IMPL.expect("Thread subsystem not initialized") }
}

/// Spawn a new thread
pub fn spawn<F>(f: F) -> OsalResult<ThreadHandle>
where
    F: FnOnce() + Send + 'static,
{
    get_thread().spawn(Box::new(f))
}

/// Get current thread ID
pub fn current_id() -> u32 {
    get_thread().current_id()
}

/// Yield execution to other threads
pub fn yield_now() {
    get_thread().yield_now();
}
