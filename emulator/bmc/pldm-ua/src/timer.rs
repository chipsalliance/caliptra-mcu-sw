// Licensed under the Apache-2.0 license

use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// A oneshot timer that executes a callback after a specified duration.
pub struct Timer {
    cancel_tx: Option<mpsc::Sender<()>>,
}

impl Default for Timer {
    fn default() -> Self {
        Self::new()
    }
}

impl Timer {
    /// Creates a new `Timer` instance.
    ///
    /// The timer starts in an idle state and must be scheduled using `schedule()`.
    ///
    /// # Returns
    /// A new instance of `Timer`.
    pub fn new() -> Self {
        Self { cancel_tx: None }
    }

    /// Schedules a callback to be executed after the specified duration.
    ///
    /// If a timer is already running, it is **cancelled** before scheduling a new one.
    ///
    /// # Parameters
    /// - `duration`: The duration after which the callback should be executed.
    /// - `context`: Shared data passed to the callback.
    /// - `callback`: A function that executes when the timer fires.
    pub fn schedule<F, G>(&mut self, duration: Duration, context: G, callback: F)
    where
        F: FnOnce(G) + Send + 'static,
        G: Send + 'static,
    {
        // Cancel any running timer before scheduling a new one
        self.cancel();

        let (tx, rx) = mpsc::channel();
        self.cancel_tx = Some(tx);

        thread::spawn(move || {
            let result = rx.recv_timeout(duration);
            if result.is_err() {
                // Timer expired, execute callback
                callback(context);
            }
            // Otherwise, the timer was cancelled
            // and we do nothing.
        });
    }

    /// Cancels the currently running timer, if any.
    /// This prevents the scheduled callback from executing.
    pub fn cancel(&mut self) {
        if let Some(tx) = self.cancel_tx.take() {
            let _ = tx.send(()); // Send cancel signal
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    #[test]
    fn test_timer_executes_successfully() {
        let mut timer = Timer::new();
        let shared_data = Arc::new(Mutex::new(0));
        let shared_data_clone = shared_data.clone();

        timer.schedule(Duration::from_millis(100), shared_data_clone, |context| {
            let mut data = context.lock().unwrap();
            *data += 1;
        });

        // Wait for timer to execute
        thread::sleep(Duration::from_millis(200));

        assert_eq!(
            *shared_data.lock().unwrap(),
            1,
            "Timer callback should have executed"
        );
    }

    #[test]
    fn test_timer_is_cancelled() {
        let mut timer = Timer::new();
        let shared_data = Arc::new(Mutex::new(0));
        let shared_data_clone = shared_data.clone();

        timer.schedule(Duration::from_millis(100), shared_data_clone, |context| {
            let mut data = context.lock().unwrap();
            *data += 1;
        });

        // Cancel the timer before it executes
        thread::sleep(Duration::from_millis(50));
        timer.cancel();

        // Wait to ensure the timer had time to fire
        thread::sleep(Duration::from_millis(150));

        assert_eq!(
            *shared_data.lock().unwrap(),
            0,
            "Timer callback should NOT have executed"
        );
    }

    #[test]
    fn test_multiple_timers_can_be_scheduled() {
        let mut timer1 = Timer::new();
        let mut timer2 = Timer::new();
        let shared_data = Arc::new(Mutex::new(0));

        let shared_data_clone1 = shared_data.clone();
        let shared_data_clone2 = shared_data.clone();

        let start_time = Instant::now();

        timer1.schedule(Duration::from_millis(100), shared_data_clone1, |context| {
            let mut data = context.lock().unwrap();
            *data += 1;
        });

        timer2.schedule(Duration::from_millis(200), shared_data_clone2, |context| {
            let mut data = context.lock().unwrap();
            *data += 2;
        });

        // Wait for both timers to execute
        thread::sleep(Duration::from_millis(300));

        let elapsed = start_time.elapsed();
        assert!(
            elapsed >= Duration::from_millis(200),
            "Both timers should have executed"
        );

        assert_eq!(
            *shared_data.lock().unwrap(),
            3,
            "Both timer callbacks should have executed correctly"
        );
    }

    #[test]
    fn test_timer_interval_is_correct() {
        let mut timer = Timer::new();
        let start_time = Arc::new(Mutex::new(None)); // Shared state to store the start time
        let start_time_clone = start_time.clone();

        let duration = Duration::from_millis(200);

        timer.schedule(duration, start_time_clone, |context| {
            let mut start = context.lock().unwrap();
            *start = Some(Instant::now());
        });

        let global_start = Instant::now();

        // Wait a bit longer than the timer duration
        thread::sleep(duration + Duration::from_millis(50));

        let elapsed = start_time.lock().unwrap();

        assert!(
            elapsed.is_some(),
            "Timer callback should have been executed"
        );

        let elapsed_time = elapsed.unwrap().duration_since(global_start);

        // Allow a small margin due to OS scheduling delays
        let tolerance = Duration::from_millis(20);

        assert!(
            elapsed_time >= duration && elapsed_time <= duration + tolerance,
            "Expected execution time: ~{:?}, but got: {:?}",
            duration,
            elapsed_time
        );
    }

    #[test]
    fn test_rescheduling_cancels_previous_timer() {
        let mut timer = Timer::new();
        let shared_data = Arc::new(Mutex::new(0));

        let shared_data_clone1 = shared_data.clone();
        timer.schedule(Duration::from_millis(500), shared_data_clone1, |context| {
            let mut data = context.lock().unwrap();
            *data += 1;
        });

        thread::sleep(Duration::from_millis(200)); // Wait before rescheduling

        let shared_data_clone2 = shared_data.clone();
        timer.schedule(Duration::from_millis(300), shared_data_clone2, |context| {
            let mut data = context.lock().unwrap();
            *data += 10;
        });

        // Wait enough time for the second timer to fire
        thread::sleep(Duration::from_millis(400));

        // The first timer should have been cancelled, so `shared_data` should be 10, not 11.
        assert_eq!(
            *shared_data.lock().unwrap(),
            10,
            "First timer should have been cancelled"
        );
    }
}
