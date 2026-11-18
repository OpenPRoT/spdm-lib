// Copyright 2025
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
