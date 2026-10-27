// Licensed under the Apache-2.0 license

//! FINISH / FINISH_RSP wire types.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{ReqRespCode, ResponseBody, WireError, WireWriter};

// ---- Request ---------------------------------------------------------------

/// FINISH request fixed body (after SPDM header).
///
/// After this struct the request carries:
/// - In V1.4: `opaque_length(2) + opaque_data`
/// - If `signature_present()`: requester signature (96 bytes, ECC P-384)
/// - Requester verify_data (48 bytes, SHA-384 HMAC)
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug)]
#[repr(C)]
pub struct FinishReqBody {
    /// Bit 0: requester signature present (mutual auth only).
    pub req_signature_present: u8,
    /// Requester slot ID (used only with mutual auth).
    pub req_slot_id: u8,
}

const _: () = assert!(core::mem::size_of::<FinishReqBody>() == 2);

impl FinishReqBody {
    /// Whether the requester signature is present (bit 0).
    #[inline]
    pub fn signature_present(&self) -> bool {
        self.req_signature_present & 0x01 != 0
    }
}

// ---- Response builder ------------------------------------------------------

/// FINISH_RSP response builder.
///
/// Wire layout: `reserved(1) + reserved(1)`, followed in V1.4 by an
/// empty `OpaqueData` field (`opaque_length(2)`). No ResponderVerifyData is
/// present when HBITC is not negotiated (our case).
pub struct FinishRsp {
    pub include_opaque: bool,
}

impl ResponseBody for FinishRsp {
    fn response_code(&self) -> ReqRespCode {
        ReqRespCode::FINISH_RSP
    }

    fn body_size(&self) -> usize {
        if self.include_opaque {
            4
        } else {
            2
        }
    }

    fn encode_body(&self, w: &mut WireWriter<'_>) -> Result<(), WireError> {
        w.write_bytes(&[0u8, 0u8])?;
        if self.include_opaque {
            w.write_bytes(&0u16.to_le_bytes())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SpdmVersion, WireReader};

    #[test]
    fn test_finish_req_signature_present_bit() {
        // Only bit 0 selects "requester signature present"; bits 1..7 are ignored.
        for (byte, expected) in [
            (0x00, false),
            (0x01, true),
            (0x02, false),
            (0x80, false),
            (0xFE, false),
            (0xFF, true),
        ] {
            let body = FinishReqBody {
                req_signature_present: byte,
                req_slot_id: 0,
            };
            assert_eq!(body.signature_present(), expected, "byte {byte:#04x}");
        }
    }

    #[test]
    fn test_finish_req_parse_without_signature() {
        // Body (2) + HMAC verify data (48, SHA-384) = 50 bytes after the common header.
        let mut buf = [0u8; 2 + 48];
        buf[0] = 0x00; // no requester signature
        let mut r = WireReader::new(&buf);
        let body: &FinishReqBody = r.read().unwrap();
        assert!(!body.signature_present());
        assert_eq!(body.req_slot_id, 0);
        // What follows the fixed body is exactly the HMAC.
        assert_eq!(r.remaining(), 48);
    }

    #[test]
    fn test_finish_req_parse_with_signature_and_slot() {
        // Body (2) + signature (96, ECC P-384) + HMAC (48) = 146 bytes.
        let mut buf = [0u8; 2 + 96 + 48];
        buf[0] = 0x01;
        buf[1] = 0x03; // requester slot 3
        let mut r = WireReader::new(&buf);
        let body: &FinishReqBody = r.read().unwrap();
        assert!(body.signature_present());
        assert_eq!(body.req_slot_id, 3);
        // 96 + 48 = 144 bytes remain for the caller to split.
        assert_eq!(r.remaining(), 144);
    }

    #[test]
    fn test_finish_req_rejects_truncated() {
        assert!(WireReader::new(&[0x01]).read::<FinishReqBody>().is_err());
        assert!(WireReader::new(&[]).read::<FinishReqBody>().is_err());
    }

    #[test]
    fn test_finish_rsp_without_opaque() {
        let rsp = FinishRsp {
            include_opaque: false,
        };
        // Body = reserved(1) + reserved(1) = 2; wire = 2 + 2 = 4 bytes.
        assert_eq!(rsp.body_size(), 2);
        assert_eq!(rsp.encoded_size(), 4);

        for v in [SpdmVersion::V12, SpdmVersion::V13] {
            let mut buf = [0xFFu8; 4];
            let mut w = WireWriter::new(&mut buf);
            rsp.encode_with_header(v, &mut w).unwrap();
            // header: version, FINISH_RSP (0x65); body: two reserved zero bytes.
            assert_eq!(buf, [v.to_u8(), 0x65, 0x00, 0x00]);
        }
    }

    #[test]
    fn test_finish_rsp_v14_with_empty_opaque() {
        let rsp = FinishRsp {
            include_opaque: true,
        };
        // Body = reserved(2) + opaque_length(2) = 4; wire = 2 + 4 = 6 bytes.
        assert_eq!(rsp.body_size(), 4);
        assert_eq!(rsp.encoded_size(), 6);

        let mut buf = [0xFFu8; 6];
        let mut w = WireWriter::new(&mut buf);
        rsp.encode_with_header(SpdmVersion::V14, &mut w).unwrap();
        assert_eq!(
            buf,
            [
                0x14, 0x65, // header: V1.4, FINISH_RSP
                0x00, 0x00, // reserved
                0x00, 0x00, // opaque_length = 0 (little-endian)
            ]
        );
    }

    #[test]
    fn test_finish_rsp_opaque_flag_is_independent_of_version() {
        // Pins current leniency: `include_opaque` is the caller's choice and is
        // not tied to the header version, so a V1.2 FINISH_RSP can carry the
        // 1.4-only OpaqueData length field.
        let rsp = FinishRsp {
            include_opaque: true,
        };
        let mut buf = [0xFFu8; 6];
        let mut w = WireWriter::new(&mut buf);
        rsp.encode_with_header(SpdmVersion::V12, &mut w).unwrap();
        assert_eq!(buf, [0x12, 0x65, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_finish_rsp_buffer_too_small() {
        // Without opaque: needs 4 bytes.
        for len in 0..4 {
            let mut buf = [0u8; 4];
            let mut w = WireWriter::new(&mut buf[..len]);
            let rsp = FinishRsp {
                include_opaque: false,
            };
            assert!(
                rsp.encode_with_header(SpdmVersion::V13, &mut w).is_err(),
                "no-opaque len {len}"
            );
        }
        // With opaque: needs 6 bytes; 5 fails on the trailing opaque_length.
        for len in 0..6 {
            let mut buf = [0u8; 6];
            let mut w = WireWriter::new(&mut buf[..len]);
            let rsp = FinishRsp {
                include_opaque: true,
            };
            assert!(
                rsp.encode_with_header(SpdmVersion::V14, &mut w).is_err(),
                "opaque len {len}"
            );
        }
    }
}
