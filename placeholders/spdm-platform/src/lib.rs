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

//! Platform-independent placeholder for the kernel/syscall `ErrorCode`.
//!
//! Replaces `caliptra-mcu-libtock_platform`. Only the `ErrorCode` enum
//! surface consumed by the SPDM-Lib crates is provided; values mirror the
//! libtock-rs error codes so numeric meaning is preserved.

#![no_std]
#![forbid(unsafe_code)]

/// Syscall/driver error code (mirrors libtock-rs `ErrorCode`).
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u16)]
pub enum ErrorCode {
    Fail = 1,
    Busy = 2,
    Already = 3,
    Off = 4,
    Reserve = 5,
    Invalid = 6,
    Size = 7,
    Cancel = 8,
    NoMem = 9,
    NoSupport = 10,
    NoDevice = 11,
    Uninstalled = 12,
    NoAck = 13,
    BadRVal = 1024,
}
