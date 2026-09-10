// Licensed under the Apache-2.0 license

//! Error vocabulary for the SPDM-Lite stack — the error type itself plus
//! the subdomain registry built on it.
//!
//! This crate is **library-owned API, not a platform interface**: every trait
//! signature in spdm-lib returns [`PalResult<T>`], so both the library and its
//! consumers depend on this crate directly. It has no dependencies of its own.
//!
//! # Error type
//!
//! [`PalErrorCode`] is a 32-bit `(domain, subdomain, code)` triple. The
//! [`domain`] module is the top-level registry; [`codes`] holds the
//! cross-cutting constants whose meaning doesn't depend on the caller.
//!
//! Consumers integrating a syscall or driver layer map their own error values
//! in through [`PalErrorCode::kernel`] and recover them with
//! [`PalErrorCode::as_kernel`]; spdm-lib itself never interprets the payload.
//!
//! # Subdomain registry
//!
//! Every SPDM-Lite crate that produces errors picks a [subdomain
//! byte](#subdomains) from this central registry, then defines its
//! own concrete [`PalErrorCode`] constants in its own `errors` module
//! using `PalErrorCode::new(domain::SPDM, SUBDOMAIN_*, code)`.
//!
//! Centralizing **just the subdomain bytes** here gives:
//!
//! * Collision detection — one file lists every subdomain assigned
//!   under [`domain::SPDM`].
//! * Bit-layout conventions — the SPDM wire-byte encoding lives next
//!   to the subdomain bytes (see [`spdm_wire`] / [`as_spdm_wire`]).
//! * Cross-crate classifier helpers ([`is_spdm_wire`],
//!   [`is_mctp_error`], …) so a logger or error-PDU encoder can
//!   inspect any [`PalErrorCode`] without depending on every owning
//!   crate.
//!
//! Specific error constants (e.g. `SPDM_INVALID_REQUEST`,
//! `MCTP_BUFFER_TOO_SMALL`) stay in the crate that produces them.

#![no_std]
#![forbid(unsafe_code)]

// ----- Error type ------------------------------------------------------------

/// Unified error code. See module docs for the bit layout.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
#[repr(transparent)]
pub struct PalErrorCode(pub u32);

/// Convenience alias for `core::result::Result<T, PalErrorCode>`.
pub type PalResult<T> = core::result::Result<T, PalErrorCode>;

impl PalErrorCode {
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

    /// Wraps a consumer-supplied kernel/syscall error value.
    ///
    /// This is the seam for platform integration: spdm-lib stores the raw
    /// value and never interprets it. Recover it with [`Self::as_kernel`].
    #[inline]
    pub const fn kernel(e: u16) -> Self {
        Self::new(domain::KERNEL, 0, e)
    }

    /// `true` if this error came from the kernel-syscall boundary.
    #[inline]
    pub const fn is_kernel(self) -> bool {
        self.domain() == domain::KERNEL
    }

    /// Recovers the kernel error raw value if this is a passthrough.
    #[inline]
    pub const fn as_kernel(self) -> Option<u16> {
        if self.is_kernel() {
            Some(self.code())
        } else {
            None
        }
    }
}

/// Top-level domain registry (the high byte of every [`PalErrorCode`]).
pub mod domain {
    /// Reserved — `0x00` never appears in `Err` (`PalErrorCode(0)` is the niche).
    pub const RESERVED: u8 = 0x00;

    /// Kernel/syscall passthrough.
    pub const KERNEL: u8 = 0x01;

    /// SPDM protocol (DMTF DSP0274).
    pub const SPDM: u8 = 0x03;

    /// PLDM protocol (DMTF DSP0240).
    pub const PLDM: u8 = 0x04;

    /// Consumer mailbox / IPC protocol.
    pub const MAILBOX: u8 = 0x06;

    /// Memory / allocator failures.
    pub const MEMORY: u8 = 0x10;

    /// Internal invariants — these indicate bugs.
    pub const INTERNAL: u8 = 0xFF;
}

/// Truly cross-cutting error codes — meaning doesn't depend on caller.
pub mod codes {
    use super::{domain, PalErrorCode};

    /// The allocator pool was exhausted.
    pub const OUT_OF_MEMORY: PalErrorCode = PalErrorCode::new(domain::MEMORY, 0, 0x0001);

    /// An allocation request had an unsupported alignment requirement.
    pub const BAD_ALIGNMENT: PalErrorCode = PalErrorCode::new(domain::MEMORY, 0, 0x0002);

    /// A program invariant was violated — this indicates a bug.
    pub const INTERNAL_BUG: PalErrorCode = PalErrorCode::new(domain::INTERNAL, 0, 0x0001);

    /// Code path is a stub / placeholder.
    pub const NOT_IMPLEMENTED: PalErrorCode = PalErrorCode::new(domain::INTERNAL, 0, 0x0002);

    /// A non-local invariant (e.g. unexpected state) was hit.
    pub const INVARIANT: PalErrorCode = PalErrorCode::new(domain::INTERNAL, 0, 0x0003);

    /// Mailbox was busy (transient — caller should retry).
    pub const MAILBOX_BUSY: PalErrorCode = PalErrorCode::new(domain::MAILBOX, 0, 0x0001);
}

impl From<PalErrorCode> for u32 {
    #[inline]
    fn from(e: PalErrorCode) -> u32 {
        e.0
    }
}

impl core::fmt::LowerHex for PalErrorCode {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::LowerHex::fmt(&self.0, f)
    }
}

impl core::fmt::UpperHex for PalErrorCode {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::UpperHex::fmt(&self.0, f)
    }
}

// ----- Subdomain registry under [`domain::SPDM`] -----------------------------

/// spdm-lib stack / codec local errors (never appear on the wire).
///
/// Used by:
/// * `spdm-codec` for parser/encoder failures
/// * `spdm-stack` for dispatch/state-machine errors
pub const SUBDOMAIN_LOCAL: u8 = 0x00;

/// SPDM wire errors per DSP0274 §10.10.2.
///
/// The low byte of the resulting [`PalErrorCode::code`] carries the
/// spec-defined SPDM error byte; responders extract it with
/// [`as_spdm_wire`] and inject it into the wire `ERROR` PDU.
pub const SUBDOMAIN_WIRE: u8 = 0x01;

/// MCTP transport (used by SPDM).
pub const SUBDOMAIN_MCTP: u8 = 0x10;

/// PCIe DOE transport (used by SPDM) — reserved for future use.
pub const SUBDOMAIN_DOE: u8 = 0x11;

/// VDM handler control errors that affect responder framing rather than the
/// vendor-defined wire payload.
pub const SUBDOMAIN_VDM: u8 = 0x20;

/// A matched VDM backend failed in the vendor protocol handler and the request
/// should be dropped without generating an SPDM ERROR response.
///
/// Use this when a backend owns the VDM request but cannot form a valid
/// vendor-defined response payload.
pub const VDM_NO_RESPONSE: PalErrorCode = PalErrorCode::new(domain::SPDM, SUBDOMAIN_VDM, 0x0001);

/// Returns true when `e` requests silent VDM failure handling.
#[inline]
pub const fn is_vdm_no_response(e: PalErrorCode) -> bool {
    e.domain() == domain::SPDM && e.subdomain() == SUBDOMAIN_VDM && e.code() == 0x0001
}

// ----- Wire-byte convention --------------------------------------------------

/// Builds an [`PalErrorCode`] from a DSP0274 §10.10.2 SPDM error byte.
///
/// The byte is preserved in the low 8 bits of the resulting `code`,
/// so SPDM responders can recover it via [`as_spdm_wire`] and write
/// it directly into the wire `ERROR` PDU.
#[inline]
pub const fn spdm_wire(spec_byte: u8) -> PalErrorCode {
    PalErrorCode::new(domain::SPDM, SUBDOMAIN_WIRE, spec_byte as u16)
}

/// If `e` is a [`spdm_wire`] error, returns its DSP0274 byte.
#[inline]
pub const fn as_spdm_wire(e: PalErrorCode) -> Option<u8> {
    if e.domain() == domain::SPDM && e.subdomain() == SUBDOMAIN_WIRE {
        Some(e.code() as u8)
    } else {
        None
    }
}

// ----- Classifier helpers ----------------------------------------------------

/// `true` if `e` is an spdm-lib local error (never on the wire).
#[inline]
pub const fn is_spdm_local(e: PalErrorCode) -> bool {
    e.domain() == domain::SPDM && e.subdomain() == SUBDOMAIN_LOCAL
}

/// `true` if `e` is an SPDM wire error (DSP0274 §10.10.2).
#[inline]
pub const fn is_spdm_wire(e: PalErrorCode) -> bool {
    e.domain() == domain::SPDM && e.subdomain() == SUBDOMAIN_WIRE
}

/// `true` if `e` is an MCTP-transport error.
#[inline]
pub const fn is_mctp_error(e: PalErrorCode) -> bool {
    e.domain() == domain::SPDM && e.subdomain() == SUBDOMAIN_MCTP
}
