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

//! `spdm-traits` — Core trait definitions for the SPDM stack.
//!
//! This crate provides the foundational abstractions used by the SPDM stack
//! implementation. It is intentionally kept minimal and dependency-free
//! (beyond `core`) so that platform-specific implementations can depend on
//! it without pulling in the full stack.
//!
//! # Modules
//!
//! * [`io`] — Transport I/O traits and message-kind discriminator
//!   ([`SpdmPalIo`], [`SpdmPalIoTransport`], [`SpdmPalIoKind`]).
//! * [`pal`] — Platform Abstraction Layer traits for platform-specific
//!   cryptographic and hardware operations.
//! * [`transport`] — Byte-oriented PAL transport trait.
//!
//! Error type: this crate uses [`spdm_errors::PalErrorCode`] directly via
//! the re-exports below. There is no SPDM-specific error alias —
//! every runtime userspace API shares one error type.
#![no_std]

mod alloc;
mod cert;
mod hash;
mod io;
mod measurements;
mod pal;
mod rng;
mod session_crypto;
mod transport;
mod vendor_defined;

pub use alloc::*;
pub use cert::*;
pub use hash::*;
pub use io::*;
pub use measurements::*;
pub use pal::*;
pub use rng::*;
pub use session_crypto::*;
pub use transport::*;
pub use vendor_defined::*;

// Re-export the workspace-wide error type/alias for convenience: users
// of this crate get them transitively without needing `mcu-error` as a
// direct dependency.
pub use spdm_errors::{PalErrorCode, PalResult};
