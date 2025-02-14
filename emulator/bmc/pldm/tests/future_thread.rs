use std::thread;
use std::sync::{Arc, Mutex};
use std::future::Future;
use std::pin::Pin;
use futures::future::poll_fn;
use std::time::Duration;
use std::thread::JoinHandle;

/// A struct to manage running a Future inside a separate thread
pub struct FutureThread<T> {
    handle: Option<JoinHandle<()>>,
    result: Arc<Mutex<Option<T>>>,
}

impl<T> FutureThread<T> {
    /// Spawns a new thread that runs the given future
    pub fn spawn<F>(future: F) -> Self
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let result = Arc::new(Mutex::new(None));
        let result_clone = Arc::clone(&result);
        let handle = thread::spawn(move || {
            result_clone.lock().unwrap().replace(futures::executor::block_on(async {
                poll_future(future).await
            }));
        });

        Self {
            handle: Some(handle),
            result
        }
    }

    pub fn get_output(self) -> Result<T,()> {
        self.handle.unwrap().join().map_err(|_| ())?;
        self.result.lock().unwrap().take().ok_or(())
    }
}

fn poll_future<F: Future>(mut fut: F) -> impl Future<Output = F::Output> {
    poll_fn(move |cx| {
        let pinned_fut = unsafe { Pin::new_unchecked(&mut fut) };
        pinned_fut.poll(cx)
    })
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_future_thread() {
        let future = async {
            std::thread::sleep(Duration::from_secs(1));
            42
        };

        let future_thread = FutureThread::spawn(future);
        assert!(future_thread.get_output().unwrap() == 42);
        
    }
}