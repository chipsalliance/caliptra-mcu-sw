// Licensed under the Apache-2.0 license

use crate::AsyncAlarm;
use arrayvec::ArrayVec;
use libapi_caliptra::crypto::hash::{HashAlgoType, HashContext};
use libtock_platform::Syscalls;
use romtime::{println, test_exit};

const NUM_ITERATIONS: usize = 15;
const NUM_TEST_DATA: usize = 8;

pub async fn test_caliptra_sha384_profiling<S: Syscalls>() {
    println!("Starting Caliptra SHA384 Performance Profiling Test");

    // Define test sizes from 128 bytes to 5KB using ArrayVec
    // let test_sizes: ArrayVec<usize, NUM_TEST_DATA> = ArrayVec::from([
    //     128, 256, 512, 1024, 2048, 3072, 4096, 5120, // 5120 = 5KB
    // ]);
    let test_sizes: ArrayVec<usize, NUM_TEST_DATA> =
        ArrayVec::from([5120, 4096, 3072, 2048, 1024, 512, 256, 128]);

    let num_iterations = NUM_ITERATIONS; // Number of iterations per size for averaging

    println!(
        "Testing SHA384 performance for sizes: {:?} bytes",
        test_sizes.as_slice()
    );
    println!("Number of iterations per size: {}", num_iterations);

    let frequency = AsyncAlarm::<S>::get_frequency().unwrap().0 as u64;
    println!("Timer frequency: {} Hz", frequency);

    // Storage for all test results
    let mut all_results: ArrayVec<
        (
            usize,
            ArrayVec<u64, NUM_ITERATIONS>,
            ArrayVec<u64, NUM_ITERATIONS>,
            ArrayVec<u64, NUM_ITERATIONS>,
            ArrayVec<u64, NUM_ITERATIONS>,
        ),
        8,
    > = ArrayVec::new();

    // Pre-allocate maximum buffer size (5KB) using ArrayVec
    let mut test_data: ArrayVec<u8, 5120> = ArrayVec::new();
    // Fill with pattern
    for i in 0..5120 {
        test_data.push((i % 256) as u8);
    }

    for &size in &test_sizes {
        println!("\n--- Testing buffer size: {} bytes ---", size);
        if size < 1024 {
            println!(
                "  Strategy: All {} bytes passed to init(), empty update()",
                size
            );
        } else {
            let remaining_bytes = size - 1024;
            println!(
                "  Strategy: First 1024 bytes to init(), remaining {} bytes to update()",
                remaining_bytes
            );
        }

        // Use slice of the pre-allocated buffer for this size
        let data_slice = &test_data.as_slice()[..size];

        // Storage for this size's iterations (total, init, update, finalize times)
        let mut iteration_total_times: ArrayVec<u64, NUM_ITERATIONS> = ArrayVec::new();
        let mut iteration_init_times: ArrayVec<u64, NUM_ITERATIONS> = ArrayVec::new();
        let mut iteration_update_times: ArrayVec<u64, NUM_ITERATIONS> = ArrayVec::new();
        let mut iteration_finalize_times: ArrayVec<u64, NUM_ITERATIONS> = ArrayVec::new();

        for iteration in 0..num_iterations {
            println!("  Iteration {}/{}", iteration + 1, num_iterations);

            let mut hash_context = HashContext::new();
            let mut hash = [0u8; 48]; // SHA384 produces 48-byte hash

            // Measure initialization time
            let init_start = AsyncAlarm::<S>::get_ticks().unwrap() as u64;

            if size < 1024 {
                // For smaller data sizes, pass all data to init
                let _ = hash_context
                    .init(HashAlgoType::SHA384, Some(data_slice))
                    .await
                    .map_err(|e| {
                        println!("Failed to initialize hash context: {:?}", e);
                        test_exit(1);
                    });
            } else {
                // For larger data sizes, pass first 1024 bytes to init
                let init_data = &data_slice[..1024];
                let _ = hash_context
                    .init(HashAlgoType::SHA384, Some(init_data))
                    .await
                    .map_err(|e| {
                        println!("Failed to initialize hash context: {:?}", e);
                        test_exit(1);
                    });
            }

            let init_end = AsyncAlarm::<S>::get_ticks().unwrap() as u64;
            let init_time = init_end.wrapping_sub(init_start);

            // Measure update time
            let update_start = AsyncAlarm::<S>::get_ticks().unwrap() as u64;

            if size < 1024 {
                // For smaller sizes, no additional data to update (already passed to init)
                // Just call update with empty slice to maintain timing consistency
                let _ = hash_context.update(&[]).await.map_err(|e| {
                    println!("Failed to update hash context: {:?}", e);
                    test_exit(1);
                });
            } else {
                // For larger sizes, pass remaining data (after first 1024 bytes) to update
                let remaining_data = &data_slice[1024..];
                let _ = hash_context.update(remaining_data).await.map_err(|e| {
                    println!("Failed to update hash context: {:?}", e);
                    test_exit(1);
                });
            }

            let update_end = AsyncAlarm::<S>::get_ticks().unwrap() as u64;
            let update_time = update_end.wrapping_sub(update_start);

            // Measure finalize time
            let finalize_start = AsyncAlarm::<S>::get_ticks().unwrap() as u64;
            let _ = hash_context.finalize(&mut hash).await.map_err(|e| {
                println!("Failed to finalize hash: {:?}", e);
                test_exit(1);
            });
            let finalize_end = AsyncAlarm::<S>::get_ticks().unwrap() as u64;
            let finalize_time = finalize_end.wrapping_sub(finalize_start);

            let iteration_ticks = init_time + update_time + finalize_time;

            // Store iteration timing data
            iteration_total_times.push(iteration_ticks);
            iteration_init_times.push(init_time);
            iteration_update_times.push(update_time);
            iteration_finalize_times.push(finalize_time);

            // Convert to milliseconds for this iteration (for immediate feedback)
            let iteration_ms = iteration_ticks.saturating_div(frequency / 1000);
            let init_ms = init_time.saturating_div(frequency / 1000);
            let update_ms = update_time.saturating_div(frequency / 1000);
            let finalize_ms = finalize_time.saturating_div(frequency / 1000);

            println!(
                "    Total: {} ms, Init: {} ms, Update: {} ms, Finalize: {} ms",
                iteration_ms, init_ms, update_ms, finalize_ms
            );
        }

        // Store results for this size
        all_results.push((
            size,
            iteration_total_times,
            iteration_init_times,
            iteration_update_times,
            iteration_finalize_times,
        ));
    }

    // Print all results at the end
    println!("\n");
    println!("===============================================");
    println!("SHA384 PERFORMANCE PROFILING SUMMARY");
    println!("===============================================");
    println!("Timer frequency: {} Hz", frequency);
    println!("Number of iterations per size: {}", num_iterations);
    println!();

    for (size, total_times, init_times, update_times, finalize_times) in &all_results {
        println!("BUFFER SIZE: {} bytes", size);
        println!("----------------------------------------");

        // Print all individual iteration times
        println!("Individual iteration times (ms):");
        for i in 0..num_iterations {
            let total = total_times[i];
            let init = init_times[i];
            let update = update_times[i];
            let finalize = finalize_times[i];

            let total_ms = total.saturating_div(frequency / 1000);
            let init_ms = init.saturating_div(frequency / 1000);
            let update_ms = update.saturating_div(frequency / 1000);
            let finalize_ms = finalize.saturating_div(frequency / 1000);
            println!(
                "  Iter {}: Total={} ms, Init={} ms, Update={} ms, Finalize={} ms",
                i + 1,
                total_ms,
                init_ms,
                update_ms,
                finalize_ms
            );
        }

        // Calculate averages and statistics
        let total_sum: u64 = total_times.iter().sum();
        let init_sum: u64 = init_times.iter().sum();
        let update_sum: u64 = update_times.iter().sum();
        let finalize_sum: u64 = finalize_times.iter().sum();

        let avg_total_ticks = total_sum / num_iterations as u64;
        let avg_init_ticks = init_sum / num_iterations as u64;
        let avg_update_ticks = update_sum / num_iterations as u64;
        let avg_finalize_ticks = finalize_sum / num_iterations as u64;

        // Convert to milliseconds
        let avg_total_ms = avg_total_ticks.saturating_div(frequency / 1000);
        let avg_init_ms = avg_init_ticks.saturating_div(frequency / 1000);
        let avg_update_ms = avg_update_ticks.saturating_div(frequency / 1000);
        let avg_finalize_ms = avg_finalize_ticks.saturating_div(frequency / 1000);

        // Calculate throughput in bytes per second
        let throughput_bps = if avg_total_ms > 0 {
            (*size as u64 * 1000) / avg_total_ms
        } else {
            0
        };

        // Calculate throughput in MB/s
        let throughput_mbps = throughput_bps / (1024 * 1024);

        println!("\nAVERAGE RESULTS:");
        println!(
            "  Total time: {} ms ({} ticks)",
            avg_total_ms, avg_total_ticks
        );
        println!(
            "  Init time:  {} ms ({} ticks)",
            avg_init_ms, avg_init_ticks
        );
        println!(
            "  Update time: {} ms ({} ticks)",
            avg_update_ms, avg_update_ticks
        );
        println!(
            "  Finalize time: {} ms ({} ticks)",
            avg_finalize_ms, avg_finalize_ticks
        );
        println!(
            "  Throughput: {} bytes/sec ({} MB/sec)",
            throughput_bps, throughput_mbps
        );

        // Calculate time per byte
        let time_per_byte_ns = if *size > 0 {
            (avg_total_ms * 1_000_000) / *size as u64 // nanoseconds per byte
        } else {
            0
        };
        println!("  Time per byte: {} ns", time_per_byte_ns);

        // Calculate min and max for variance analysis
        let min_total = *total_times.iter().min().unwrap_or(&0);
        let max_total = *total_times.iter().max().unwrap_or(&0);
        let min_total_ms = min_total.saturating_div(frequency / 1000);
        let max_total_ms = max_total.saturating_div(frequency / 1000);

        println!(
            "  Min total time: {} ms ({} ticks)",
            min_total_ms, min_total
        );
        println!(
            "  Max total time: {} ms ({} ticks)",
            max_total_ms, max_total
        );
        println!(
            "  Variance: {} ms",
            max_total_ms.saturating_sub(min_total_ms)
        );
        println!();
    }

    println!("\nSHA384 Performance Profiling Test Completed Successfully");
}
