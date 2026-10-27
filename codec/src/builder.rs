// Licensed under the Apache-2.0 license

//! `ResponseBody` trait — every SPDM response PDU implements this.
//!
//! The trait captures three command-independent facts:
//!
//! * The [`ReqRespCode`] this body's [`SpdmMsgHdrPdu`] will carry.
//! * How many bytes the body occupies on the wire (`body_size`).
//! * How to write the body at the writer's current position
//!   (`encode_body`) — the SPDM common header is always written
//!   immediately before, by the caller.
//!
//! Handlers don't write the SPDM common header themselves; the
//! dispatcher's `build_response` helper writes it and then calls
//! [`encode_body`](ResponseBody::encode_body). This way every response
//! starts with the same well-formed `(version, code)` pair without
//! the handler having to remember to write it.

use crate::{ReqRespCode, SpdmMsgHdrPdu, SpdmVersion, WireError, WireWriter};

/// SPDM response body — anything that can be written after the SPDM
/// common header.
pub trait ResponseBody {
    /// SPDM response code carried in the common header's `code` byte.
    fn response_code(&self) -> ReqRespCode;

    /// Number of body bytes (i.e. everything after the 2-byte common
    /// header). For variable-length bodies (e.g. VERSION's
    /// `entry_count × VersionNumberEntry`), the implementor computes
    /// this from `self`.
    fn body_size(&self) -> usize;

    /// Encode the body at the writer's current position.
    fn encode_body(&self, w: &mut WireWriter<'_>) -> Result<(), WireError>;

    /// Total SPDM-payload size on the wire (common header + body).
    #[inline]
    fn encoded_size(&self) -> usize
    where
        Self: Sized,
    {
        SpdmMsgHdrPdu::SIZE + self.body_size()
    }

    /// Write `(common-header(version, self.response_code()) | body)`
    /// at the writer's current position.
    fn encode_with_header(
        &self,
        version: SpdmVersion,
        w: &mut WireWriter<'_>,
    ) -> Result<(), WireError>
    where
        Self: Sized,
    {
        w.write(&SpdmMsgHdrPdu::new(version, self.response_code()))?;
        self.encode_body(w)
    }
}

/// SPDM request body — the requester-side mirror of [`ResponseBody`].
///
/// A requester builds a request by writing the SPDM common header
/// `(version, Self::REQUEST_CODE)` followed by the request body. This trait
/// captures the same three command-independent facts as [`ResponseBody`], for
/// the opposite direction.
pub trait RequestBody {
    /// SPDM request code carried in the common header's `code` byte.
    const REQUEST_CODE: ReqRespCode;

    /// Number of body bytes (everything after the 2-byte common header).
    fn body_size(&self) -> usize;

    /// Encode the body at the writer's current position.
    fn encode_body(&self, w: &mut WireWriter<'_>) -> Result<(), WireError>;

    /// Total SPDM-payload size on the wire (common header + body).
    #[inline]
    fn encoded_size(&self) -> usize {
        SpdmMsgHdrPdu::SIZE + self.body_size()
    }

    /// Write `(common-header(version, Self::REQUEST_CODE) | body)` at the
    /// writer's current position.
    fn encode_with_header(
        &self,
        version: SpdmVersion,
        w: &mut WireWriter<'_>,
    ) -> Result<(), WireError> {
        w.write(&SpdmMsgHdrPdu::new(version, Self::REQUEST_CODE))?;
        self.encode_body(w)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Rsp<'a>(&'a [u8]);

    impl ResponseBody for Rsp<'_> {
        fn response_code(&self) -> ReqRespCode {
            ReqRespCode::VERSION
        }
        fn body_size(&self) -> usize {
            self.0.len()
        }
        fn encode_body(&self, w: &mut WireWriter<'_>) -> Result<(), WireError> {
            w.write_bytes(self.0)
        }
    }

    struct Req<'a>(&'a [u8]);

    impl RequestBody for Req<'_> {
        const REQUEST_CODE: ReqRespCode = ReqRespCode::GET_VERSION;
        fn body_size(&self) -> usize {
            self.0.len()
        }
        fn encode_body(&self, w: &mut WireWriter<'_>) -> Result<(), WireError> {
            w.write_bytes(self.0)
        }
    }

    #[test]
    fn test_response_encode_with_header_layout_and_size() {
        let rsp = Rsp(&[0xAA, 0xBB, 0xCC]);
        // Wire size = 2-byte common header + 3-byte body = 5.
        assert_eq!(rsp.encoded_size(), 5);

        let mut buf = [0xFFu8; 5];
        let mut w = WireWriter::new(&mut buf);
        rsp.encode_with_header(SpdmVersion::V12, &mut w).unwrap();
        assert_eq!(w.position(), rsp.encoded_size());
        // (version, code) first, then the body.
        assert_eq!(buf, [0x12, 0x04, 0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn test_request_encode_with_header_layout_and_size() {
        let req = Req(&[0x01, 0x02]);
        // Wire size = 2-byte common header + 2-byte body = 4.
        assert_eq!(req.encoded_size(), 4);

        let mut buf = [0xFFu8; 4];
        let mut w = WireWriter::new(&mut buf);
        req.encode_with_header(SpdmVersion::V10, &mut w).unwrap();
        assert_eq!(buf, [0x10, 0x84, 0x01, 0x02]);
    }

    #[test]
    fn test_empty_body_is_header_only() {
        assert_eq!(Rsp(&[]).encoded_size(), 2);
        assert_eq!(Req(&[]).encoded_size(), 2);

        let mut buf = [0xFFu8; 2];
        let mut w = WireWriter::new(&mut buf);
        Rsp(&[]).encode_with_header(SpdmVersion::V14, &mut w).unwrap();
        assert_eq!(buf, [0x14, 0x04]);
    }

    #[test]
    fn test_encode_with_header_rejects_buffer_too_small_for_header() {
        // Header needs 2 bytes; 1 is too small and nothing is written.
        let mut buf = [0xFFu8; 1];
        let mut w = WireWriter::new(&mut buf);
        assert!(Rsp(&[1]).encode_with_header(SpdmVersion::V12, &mut w).is_err());
        assert_eq!(w.position(), 0);
        assert_eq!(buf, [0xFF]);

        let mut buf = [0xFFu8; 1];
        let mut w = WireWriter::new(&mut buf);
        assert!(Req(&[1]).encode_with_header(SpdmVersion::V12, &mut w).is_err());
        assert_eq!(w.position(), 0);
    }

    // Pins current behavior: the header is written before the body, so a body
    // that does not fit leaves the header in the buffer and the cursor advanced.
    // The caller must discard or `truncate` the writer after an error.
    #[test]
    fn test_encode_with_header_body_failure_leaves_partial_header() {
        // Needs 2 + 3 = 5 bytes; 4 is one short.
        let mut buf = [0xFFu8; 4];
        let mut w = WireWriter::new(&mut buf);
        assert!(Rsp(&[1, 2, 3]).encode_with_header(SpdmVersion::V12, &mut w).is_err());
        assert_eq!(w.position(), 2);
        assert_eq!(&buf[..2], &[0x12, 0x04]);
    }
}
