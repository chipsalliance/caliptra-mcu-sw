// Licensed under the Apache-2.0 license

#[cfg(not(feature = "defmt-transport"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __userlog_log {
    ($level:ident, $writer:expr, $fmt:literal $(, $arg:expr)* $(,)?) => {{
        let _ = ::core::writeln!($writer, $fmt $(, $arg)*);
    }};
}

#[cfg(all(feature = "defmt-transport", target_arch = "riscv32"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __userlog_log {
    (trace, $writer:expr, $fmt:literal $(, $arg:expr)* $(,)?) => {{
        let _ = &mut $writer;
        $crate::defmt::trace!($fmt $(, $arg)*);
    }};
    (debug, $writer:expr, $fmt:literal $(, $arg:expr)* $(,)?) => {{
        let _ = &mut $writer;
        $crate::defmt::debug!($fmt $(, $arg)*);
    }};
    (info, $writer:expr, $fmt:literal $(, $arg:expr)* $(,)?) => {{
        let _ = &mut $writer;
        $crate::defmt::info!($fmt $(, $arg)*);
    }};
    (warn, $writer:expr, $fmt:literal $(, $arg:expr)* $(,)?) => {{
        let _ = &mut $writer;
        $crate::defmt::warn!($fmt $(, $arg)*);
    }};
    (error, $writer:expr, $fmt:literal $(, $arg:expr)* $(,)?) => {{
        let _ = &mut $writer;
        $crate::defmt::error!($fmt $(, $arg)*);
    }};
}

#[cfg(all(feature = "defmt-transport", not(target_arch = "riscv32")))]
#[macro_export]
#[doc(hidden)]
macro_rules! __userlog_log {
    ($level:ident, $writer:expr, $fmt:literal $(, $arg:expr)* $(,)?) => {{
        let _ = &mut $writer;
    }};
}

#[macro_export]
macro_rules! log_trace {
    ($writer:expr, $fmt:literal $(, $arg:expr)* $(,)?) => {{
        $crate::__userlog_log!(trace, $writer, $fmt $(, $arg)*);
    }};
}

#[macro_export]
macro_rules! log_debug {
    ($writer:expr, $fmt:literal $(, $arg:expr)* $(,)?) => {{
        $crate::__userlog_log!(debug, $writer, $fmt $(, $arg)*);
    }};
}

#[macro_export]
macro_rules! log_info {
    ($writer:expr, $fmt:literal $(, $arg:expr)* $(,)?) => {{
        $crate::__userlog_log!(info, $writer, $fmt $(, $arg)*);
    }};
}

#[macro_export]
macro_rules! log_warn {
    ($writer:expr, $fmt:literal $(, $arg:expr)* $(,)?) => {{
        $crate::__userlog_log!(warn, $writer, $fmt $(, $arg)*);
    }};
}

#[macro_export]
macro_rules! log_error {
    ($writer:expr, $fmt:literal $(, $arg:expr)* $(,)?) => {{
        $crate::__userlog_log!(error, $writer, $fmt $(, $arg)*);
    }};
}
