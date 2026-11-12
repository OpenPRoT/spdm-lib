// Licensed under the Apache-2.0 license

//! END_SESSION / END_SESSION_ACK wire types.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{ReqRespCode, ResponseBody, WireError, WireWriter};

// ---- Request ---------------------------------------------------------------

/// END_SESSION request fixed body (after SPDM header).
///
/// Bit 0 of `attributes` is the Negotiated State Clearing Indicator.
/// This responder does not advertise `CACHE_CAP`, so the bit is ignored
/// by the stack layer; reserved bits are still represented here so the
/// handler can validate them.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug)]
#[repr(C)]
pub struct EndSessionReqBody {
    pub attributes: u8,
    pub reserved: u8,
}

const _: () = assert!(core::mem::size_of::<EndSessionReqBody>() == 2);

impl EndSessionReqBody {
    /// Bit 0: negotiated-state clearing indicator.
    pub const CLEAR_NEGOTIATED_STATE: u8 = 0x01;
    /// Reserved bits in Param1.
    pub const RESERVED_MASK: u8 = !Self::CLEAR_NEGOTIATED_STATE;

    /// Whether the requester asked to clear cached negotiated state.
    #[inline]
    pub fn clear_negotiated_state(&self) -> bool {
        self.attributes & Self::CLEAR_NEGOTIATED_STATE != 0
    }

    /// Whether all reserved bits/fields are zero.
    #[inline]
    pub fn reserved_is_zero(&self) -> bool {
        self.attributes & Self::RESERVED_MASK == 0 && self.reserved == 0
    }
}

// ---- Response builder ------------------------------------------------------

/// END_SESSION_ACK response builder.
///
/// Wire layout: `reserved(1) + reserved(1)`.
pub struct EndSessionAck;

impl ResponseBody for EndSessionAck {
    fn response_code(&self) -> ReqRespCode {
        ReqRespCode::END_SESSION_ACK
    }

    fn body_size(&self) -> usize {
        2
    }

    fn encode_body(&self, w: &mut WireWriter<'_>) -> Result<(), WireError> {
        w.write_bytes(&[0u8, 0u8])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SpdmVersion, WireReader};

    fn parse(bytes: &[u8]) -> EndSessionReqBody {
        let mut r = WireReader::new(bytes);
        *r.read::<EndSessionReqBody>().unwrap()
    }

    #[test]
    fn test_end_session_req_clean() {
        let req = parse(&[0x00, 0x00]);
        assert!(!req.clear_negotiated_state());
        assert!(req.reserved_is_zero());
    }

    #[test]
    fn test_end_session_req_clear_negotiated_state_bit() {
        // Bit 0 is the Negotiated State Clearing Indicator and is not "reserved".
        let req = parse(&[0x01, 0x00]);
        assert!(req.clear_negotiated_state());
        assert!(req.reserved_is_zero());
    }

    #[test]
    fn test_end_session_req_reserved_bits() {
        // RESERVED_MASK = !0x01 = 0xFE: every attribute bit except bit 0.
        assert_eq!(EndSessionReqBody::RESERVED_MASK, 0xFE);

        // Each reserved attribute bit on its own is flagged.
        for bit in 1..8 {
            let req = parse(&[1u8 << bit, 0x00]);
            assert!(!req.clear_negotiated_state(), "bit {bit}");
            assert!(!req.reserved_is_zero(), "bit {bit}");
        }

        // A non-zero Param2 (fully reserved) is flagged too.
        let req = parse(&[0x00, 0x01]);
        assert!(!req.reserved_is_zero());

        // Everything set: clear bit still reads true, reserved reads non-zero.
        let req = parse(&[0xFF, 0xFF]);
        assert!(req.clear_negotiated_state());
        assert!(!req.reserved_is_zero());
    }

    #[test]
    fn test_end_session_req_rejects_truncated() {
        assert!(WireReader::new(&[0x00]).read::<EndSessionReqBody>().is_err());
        assert!(WireReader::new(&[]).read::<EndSessionReqBody>().is_err());
    }

    #[test]
    fn test_end_session_req_ignores_trailing_bytes() {
        // Pins current leniency: the reader takes the 2-byte body and leaves any
        // trailing bytes alone; rejecting oversize requests is the caller's job.
        let mut r = WireReader::new(&[0x01, 0x00, 0xAA, 0xBB]);
        let req: &EndSessionReqBody = r.read().unwrap();
        assert!(req.clear_negotiated_state());
        assert_eq!(r.remaining(), 2);
    }

    #[test]
    fn test_end_session_ack_encode_all_versions() {
        let ack = EndSessionAck;
        // Body = reserved(1) + reserved(1) = 2; wire = 2-byte header + 2 = 4 bytes.
        assert_eq!(ack.body_size(), 2);
        assert_eq!(ack.encoded_size(), 4);

        for v in [
            SpdmVersion::V10,
            SpdmVersion::V11,
            SpdmVersion::V12,
            SpdmVersion::V13,
            SpdmVersion::V14,
        ] {
            let mut buf = [0xFFu8; 4];
            let mut w = WireWriter::new(&mut buf);
            ack.encode_with_header(v, &mut w).unwrap();
            assert_eq!(w.position(), 4);
            // header: version, END_SESSION_ACK (0x6C); body: two reserved zero bytes.
            assert_eq!(buf, [v.to_u8(), 0x6C, 0x00, 0x00]);
        }
    }

    #[test]
    fn test_end_session_ack_buffer_too_small() {
        // Needs 4 bytes; every shorter buffer must fail rather than panic.
        for len in 0..4 {
            let mut buf = [0u8; 4];
            let mut w = WireWriter::new(&mut buf[..len]);
            assert!(
                EndSessionAck
                    .encode_with_header(SpdmVersion::V14, &mut w)
                    .is_err(),
                "len {len}"
            );
        }
    }
}
