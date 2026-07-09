// Licensed under the Apache-2.0 license

//! Platform-independent placeholder for `caliptra-mcu-libtock_console`.
//!
//! Only the `Console::<S>::writer()` surface used by the SPDM stack's
//! `debug-trace` feature is provided. The returned writer implements
//! `core::fmt::Write` by discarding output (no platform console here).

#![no_std]
#![forbid(unsafe_code)]

use core::marker::PhantomData;

/// Placeholder console generic over a syscall type `S`.
pub struct Console<S>(PhantomData<S>);

impl<S> Console<S> {
    /// Returns a `core::fmt::Write` sink. In this placeholder the sink
    /// discards all bytes.
    pub fn writer() -> ConsoleWriter<S> {
        ConsoleWriter(PhantomData)
    }
}

/// Writer returned by [`Console::writer`]; discards all output.
pub struct ConsoleWriter<S>(PhantomData<S>);

impl<S> core::fmt::Write for ConsoleWriter<S> {
    fn write_str(&mut self, _s: &str) -> core::fmt::Result {
        Ok(())
    }
}
