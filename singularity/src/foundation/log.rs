//! Leveled kernel logging macros for the Singularity driver.
//!
//! Provides level-filtered logging wrapping `wdk::println!` without heap allocations.
//! Hot-path trace and debug logs are stripped at compile-time in release builds
//! (`#[cfg(not(debug_assertions))]`), eliminating lock contention and DbgPrint overhead.

#[macro_export]
macro_rules! driver_error {
    ($($arg:tt)*) => {
        $crate::println!("[Singularity][ERROR] {}", format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! driver_warn {
    ($($arg:tt)*) => {
        $crate::println!("[Singularity][WARN]  {}", format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! driver_info {
    ($($arg:tt)*) => {
        $crate::println!("[Singularity][INFO]  {}", format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! driver_debug {
    ($($arg:tt)*) => {
        #[cfg(debug_assertions)]
        $crate::println!("[Singularity][DEBUG] {}", format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! driver_trace {
    ($($arg:tt)*) => {
        #[cfg(debug_assertions)]
        $crate::println!("[Singularity][TRACE] {}", format_args!($($arg)*))
    };
}
