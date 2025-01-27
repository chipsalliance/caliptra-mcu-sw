use futures::future::Future;
use futures::task::noop_waker;
use libtock_platform::Syscalls;
use std::pin::Pin;
use std::task::Context;
use std::thread::sleep;
use std::time::Duration;

/// Waits for a syscall future to complete, polling it in a loop.
///
/// # Arguments
/// - `future`: The syscall future to be polled.
///
/// # Returns
/// - The result of the completed future.
pub fn wait_for_future_ready<F, T>(future: F) -> T
where
    F: Future<Output = T> + Unpin,
{
    // Pin the future to make it immovable
    let mut future = Pin::new(Box::new(future));

    // Set up a noop waker to drive the future
    let waker = noop_waker();
    let mut context = Context::from_waker(&waker);

    // Poll the future in a loop
    loop {
        match future.as_mut().poll(&mut context) {
            std::task::Poll::Pending => {
                crate::fake::Syscalls::yield_no_wait();
                sleep(Duration::from_millis(10));
            }
            std::task::Poll::Ready(result) => {
                return result;
            }
        }
    }
}
