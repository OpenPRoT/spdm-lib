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

//! `spdm-mcu-pal` — Caliptra-MCU Platform Abstraction Layer for the
//! SPDM-Lite stack.
//!
//! This crate provides the concrete implementations of the
//! [`SpdmPal`](spdm_traits::SpdmPal) super-trait family
//! (allocation, hashing, framed I/O) that the
//! [`spdm-stack`](../../stack) consumes as its single point
//! of platform binding.
//!
//! # Modules
//!
//! * [`alloc`] — Bitmap allocator and the [`SpdmPalAlloc`] impl
//!   that hands out [`SpdmBox`] / [`BitmapBytes`] from a
//!   caller-supplied scratch region.
//! * [`hash`] — [`SpdmPalHash`] impl and the running-hash bridge
//!   into [`spdm_crypto`].
//! * [`io`] — [`SpdmPalIo`] / [`SpdmPalIoTransport`] impls bridging
//!   the higher-level framed-message API onto the byte-oriented
//!   [`SpdmPalTransport`](spdm_traits::SpdmPalTransport).
//! * [`pal`] — The [`PlatformSpdmPal`] aggregate that ties allocator,
//!   hash, and transport together.
//!
//! # Re-exports
//!
//! * The whole [`alloc`] / [`pal`] surface is re-exported at the
//!   crate root so consumers write `use spdm_mcu_pal::*`.
//! * [`spdm_codec`] is re-exported as [`codec`] so the stack
//!   and downstream code share one wire-codec version.

#![no_std]

mod alloc;
pub mod cert;
mod hash;
mod io;
pub mod measurements;
mod pal;
mod session_crypto;

pub use self::alloc::*;
pub use measurements::MeasurementProvider;
pub use pal::*;

pub use spdm_codec as codec;

use spdm_traits::*;
