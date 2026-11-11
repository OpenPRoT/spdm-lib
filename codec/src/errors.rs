// Licensed under the Apache-2.0 license

//! SPDM-specific error code constants produced by the spdm-lib
//! codec.
//!
//! Subdomain bytes and the wire-byte encoding live in
//! [`spdm_errors`]; this module owns the concrete error
//! constants the codec emits.

use spdm_errors::{domain, PalErrorCode};
use spdm_errors::{spdm_wire, SUBDOMAIN_LOCAL};

// ---- SPDM wire errors (DSP0274) ---------------------------------------------

pub const SPDM_INVALID_REQUEST: PalErrorCode = spdm_wire(0x01);
pub const SPDM_BUSY: PalErrorCode = spdm_wire(0x03);
pub const SPDM_UNEXPECTED_REQUEST: PalErrorCode = spdm_wire(0x04);
pub const SPDM_UNSPECIFIED: PalErrorCode = spdm_wire(0x05);
pub const SPDM_DECRYPT_ERROR: PalErrorCode = spdm_wire(0x06);
pub const SPDM_UNSUPPORTED_REQUEST: PalErrorCode = spdm_wire(0x07);
pub const SPDM_SESSION_LIMIT_EXCEEDED: PalErrorCode = spdm_wire(0x0A);
pub const SPDM_SESSION_REQUIRED: PalErrorCode = spdm_wire(0x0B);
pub const SPDM_RESET_REQUIRED: PalErrorCode = spdm_wire(0x0C);
pub const SPDM_LARGE_RESPONSE: PalErrorCode = spdm_wire(0x0F);
pub const SPDM_VERSION_MISMATCH: PalErrorCode = spdm_wire(0x41);
pub const SPDM_RESPONSE_NOT_READY: PalErrorCode = spdm_wire(0x42);
pub const SPDM_REQUEST_RESYNCH: PalErrorCode = spdm_wire(0x43);
pub const SPDM_OPERATION_FAILED: PalErrorCode = spdm_wire(0x44);

// ---- spdm-lib local / codec errors (never on wire) -------------------------

/// Receive buffer is shorter than the 4-byte SPDM common header.
pub const SHORT_HEADER: PalErrorCode = PalErrorCode::new(domain::SPDM, SUBDOMAIN_LOCAL, 0x0001);

/// SPDM version byte is not a recognized DSP0274 version (`0x10..=0x13`).
pub const BAD_VERSION: PalErrorCode = PalErrorCode::new(domain::SPDM, SUBDOMAIN_LOCAL, 0x0002);

/// Generic wire-format read/write failure surfaced from
/// [`WireReader`](super::WireReader) / [`WireWriter`](super::WireWriter).
pub const WIRE: PalErrorCode = PalErrorCode::new(domain::SPDM, SUBDOMAIN_LOCAL, 0x0003);

// Allow `?` on `Result<_, WireError>` inside any handler returning
// `PalResult<_>` / `SpdmResult<_>` — `WireError` is a ZST so the
// conversion is just "produce the WIRE constant".
impl From<super::WireError> for PalErrorCode {
    #[inline]
    fn from(_: super::WireError) -> Self {
        WIRE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{WireError, WireReader};
    use spdm_errors::{as_spdm_wire, is_spdm_local, is_spdm_wire, PalResult};

    #[test]
    fn test_spdm_wire_errors_carry_the_dsp0274_byte() {
        let table = [
            (SPDM_INVALID_REQUEST, 0x01),
            (SPDM_BUSY, 0x03),
            (SPDM_UNEXPECTED_REQUEST, 0x04),
            (SPDM_UNSPECIFIED, 0x05),
            (SPDM_DECRYPT_ERROR, 0x06),
            (SPDM_UNSUPPORTED_REQUEST, 0x07),
            (SPDM_SESSION_LIMIT_EXCEEDED, 0x0A),
            (SPDM_SESSION_REQUIRED, 0x0B),
            (SPDM_RESET_REQUIRED, 0x0C),
            (SPDM_LARGE_RESPONSE, 0x0F),
            (SPDM_VERSION_MISMATCH, 0x41),
            (SPDM_RESPONSE_NOT_READY, 0x42),
            (SPDM_REQUEST_RESYNCH, 0x43),
            (SPDM_OPERATION_FAILED, 0x44),
        ];
        for (err, byte) in table {
            assert_eq!(as_spdm_wire(err), Some(byte));
            assert!(is_spdm_wire(err));
            assert!(!is_spdm_local(err));
            // Layout: domain SPDM (0x03) << 24 | subdomain WIRE (0x01) << 16 | byte.
            assert_eq!(err.as_u32(), 0x0301_0000 | byte as u32);
        }
    }

    #[test]
    fn test_all_error_codes_are_distinct_and_nonzero() {
        let all = [
            SPDM_INVALID_REQUEST,
            SPDM_BUSY,
            SPDM_UNEXPECTED_REQUEST,
            SPDM_UNSPECIFIED,
            SPDM_DECRYPT_ERROR,
            SPDM_UNSUPPORTED_REQUEST,
            SPDM_SESSION_LIMIT_EXCEEDED,
            SPDM_SESSION_REQUIRED,
            SPDM_RESET_REQUIRED,
            SPDM_LARGE_RESPONSE,
            SPDM_VERSION_MISMATCH,
            SPDM_RESPONSE_NOT_READY,
            SPDM_REQUEST_RESYNCH,
            SPDM_OPERATION_FAILED,
            SHORT_HEADER,
            BAD_VERSION,
            WIRE,
        ];
        for (i, a) in all.iter().enumerate() {
            // PalErrorCode(0) is reserved as the Result niche.
            assert_ne!(a.as_u32(), 0);
            for b in &all[i + 1..] {
                assert!(a != b, "duplicate error {:#010x}", a.as_u32());
            }
        }
    }

    #[test]
    fn test_local_errors_are_local_and_never_wire() {
        for (err, code) in [(SHORT_HEADER, 0x0001), (BAD_VERSION, 0x0002), (WIRE, 0x0003)] {
            assert!(is_spdm_local(err));
            assert!(!is_spdm_wire(err));
            // A local error must not be mistaken for an SPDM ERROR-PDU byte.
            assert_eq!(as_spdm_wire(err), None);
            assert_eq!(err.code(), code);
            // Layout: domain SPDM (0x03) << 24 | subdomain LOCAL (0x00) << 16 | code.
            assert_eq!(err.as_u32(), 0x0300_0000 | code as u32);
        }
    }

    #[test]
    fn test_wire_error_converts_to_wire_constant() {
        assert!(PalErrorCode::from(WireError) == WIRE);

        // `?` on a WireError inside a PalResult function yields WIRE.
        fn read_one(buf: &[u8]) -> PalResult<u8> {
            let mut r = WireReader::new(buf);
            Ok(r.take(1)?[0])
        }
        assert_eq!(read_one(&[0x5A]), Ok(0x5A));
        assert_eq!(read_one(&[]), Err(WIRE));
    }
}
