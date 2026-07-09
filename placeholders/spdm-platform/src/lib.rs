// Licensed under the Apache-2.0 license

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
