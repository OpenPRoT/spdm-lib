// Licensed under the Apache-2.0 license

//! Unified error type for the SPDM-Lib stack.
//!
//! Platform-independent placeholder for `mcu-error`. Same 32-bit
//! `(domain, subdomain, code)` layout so every crate keeps returning
//! `McuResult<T>`; the only platform touchpoint (the kernel `ErrorCode`
//! boundary translation) is routed through the `spdm-platform` placeholder.

#![no_std]
#![forbid(unsafe_code)]

/// Unified error code. See module docs for the bit layout.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
#[repr(transparent)]
pub struct McuErrorCode(pub u32);

/// Convenience alias for `core::result::Result<T, McuErrorCode>`.
pub type McuResult<T> = core::result::Result<T, McuErrorCode>;

impl McuErrorCode {
    /// Constructs an error code from `(domain, subdomain, code)`.
    #[inline]
    pub const fn new(domain: u8, subdomain: u8, code: u16) -> Self {
        Self(((domain as u32) << 24) | ((subdomain as u32) << 16) | code as u32)
    }

    /// Domain byte (bits 31..24).
    #[inline]
    pub const fn domain(self) -> u8 {
        (self.0 >> 24) as u8
    }

    /// Subdomain byte (bits 23..16).
    #[inline]
    pub const fn subdomain(self) -> u8 {
        (self.0 >> 16) as u8
    }

    /// Code (bits 15..0).
    #[inline]
    pub const fn code(self) -> u16 {
        self.0 as u16
    }

    /// Raw 32-bit representation.
    #[inline]
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Wraps a kernel/syscall error (the single boundary translation).
    #[inline]
    pub const fn kernel(e: u16) -> Self {
        Self::new(domain::KERNEL, 0, e)
    }

    /// `true` if this error came from the kernel-syscall boundary.
    #[inline]
    pub const fn is_kernel(self) -> bool {
        self.domain() == domain::KERNEL
    }

    /// Recovers the kernel `ErrorCode` raw value if this is a passthrough.
    #[inline]
    pub const fn as_kernel(self) -> Option<u16> {
        if self.is_kernel() {
            Some(self.code())
        } else {
            None
        }
    }
}

/// Top-level domain registry (the high byte of every [`McuErrorCode`]).
pub mod domain {
    /// Reserved — `0x00` never appears in `Err` (`McuErrorCode(0)` is the niche).
    pub const RESERVED: u8 = 0x00;

    /// Kernel/syscall passthrough.
    pub const KERNEL: u8 = 0x01;

    /// SPDM protocol (DMTF DSP0274).
    pub const SPDM: u8 = 0x03;

    /// PLDM protocol (DMTF DSP0240).
    pub const PLDM: u8 = 0x04;

    /// MCU↔Caliptra mailbox protocol.
    pub const MAILBOX: u8 = 0x06;

    /// Memory / allocator failures.
    pub const MEMORY: u8 = 0x10;

    /// Internal invariants — these indicate bugs.
    pub const INTERNAL: u8 = 0xFF;
}

/// Truly cross-cutting error codes — meaning doesn't depend on caller.
pub mod codes {
    use super::{domain, McuErrorCode};

    /// The allocator pool was exhausted.
    pub const OUT_OF_MEMORY: McuErrorCode = McuErrorCode::new(domain::MEMORY, 0, 0x0001);

    /// An allocation request had an unsupported alignment requirement.
    pub const BAD_ALIGNMENT: McuErrorCode = McuErrorCode::new(domain::MEMORY, 0, 0x0002);

    /// A program invariant was violated — this indicates a bug.
    pub const INTERNAL_BUG: McuErrorCode = McuErrorCode::new(domain::INTERNAL, 0, 0x0001);

    /// Code path is a stub / placeholder.
    pub const NOT_IMPLEMENTED: McuErrorCode = McuErrorCode::new(domain::INTERNAL, 0, 0x0002);

    /// A non-local invariant (e.g. unexpected state) was hit.
    pub const INVARIANT: McuErrorCode = McuErrorCode::new(domain::INTERNAL, 0, 0x0003);

    /// Mailbox was busy (transient — caller should retry).
    pub const MAILBOX_BUSY: McuErrorCode = McuErrorCode::new(domain::MAILBOX, 0, 0x0001);
}

// ----- Boundary translations -------------------------------------------------

impl From<spdm_platform::ErrorCode> for McuErrorCode {
    #[inline]
    fn from(e: spdm_platform::ErrorCode) -> Self {
        McuErrorCode::kernel(e as u16)
    }
}

impl From<McuErrorCode> for u32 {
    #[inline]
    fn from(e: McuErrorCode) -> u32 {
        e.0
    }
}

impl core::fmt::LowerHex for McuErrorCode {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::LowerHex::fmt(&self.0, f)
    }
}

impl core::fmt::UpperHex for McuErrorCode {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::UpperHex::fmt(&self.0, f)
    }
}
