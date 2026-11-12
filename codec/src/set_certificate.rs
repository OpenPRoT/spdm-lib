// Licensed under the Apache-2.0 license

//! SET_CERTIFICATE / SET_CERTIFICATE_RSP wire types.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{ReqRespCode, ResponseBody, WireError, WireWriter};

/// 2-byte SET_CERTIFICATE request body (after the 2-byte SPDM
/// common header).
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct SetCertificateReqBody {
    /// `Param1` — SlotID in bits 0..=3, CertModel in bits 4..=6,
    /// Erase in bit 7.
    pub attributes: u8,
    /// `Param2` — KeyPairID for SPDM 1.3 multi-key flows.
    pub key_pair_id: u8,
}

impl SetCertificateReqBody {
    pub const SIZE: usize = 2;

    #[inline]
    pub const fn slot_id(self) -> u8 {
        self.attributes & 0x0f
    }

    #[inline]
    pub const fn cert_model(self) -> u8 {
        (self.attributes >> 4) & 0x07
    }

    #[inline]
    pub const fn erase(self) -> bool {
        (self.attributes & 0x80) != 0
    }
}

const _: () = assert!(core::mem::size_of::<SetCertificateReqBody>() == SetCertificateReqBody::SIZE);

/// 2-byte SET_CERTIFICATE_RSP response body.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct SetCertificateRspBody {
    pub slot_id: u8,
    pub param2: u8,
}

impl SetCertificateRspBody {
    pub const SIZE: usize = 2;
}

const _: () = assert!(core::mem::size_of::<SetCertificateRspBody>() == SetCertificateRspBody::SIZE);

/// Builder for SET_CERTIFICATE_RSP.
pub struct SetCertificateRsp {
    pub slot_id: u8,
}

impl ResponseBody for SetCertificateRsp {
    fn response_code(&self) -> ReqRespCode {
        ReqRespCode::SET_CERTIFICATE_RSP
    }

    fn body_size(&self) -> usize {
        SetCertificateRspBody::SIZE
    }

    fn encode_body(&self, w: &mut WireWriter<'_>) -> Result<(), WireError> {
        w.write(&SetCertificateRspBody {
            slot_id: self.slot_id,
            param2: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ReqRespCode, SpdmVersion, WireReader};

    #[test]
    fn test_set_certificate_attributes_decode() {
        // attributes = Erase[7] | CertModel[6:4] | SlotID[3:0].
        for (attr, slot, model, erase) in [
            (0x00, 0, 0, false),
            (0x05, 5, 0, false),
            (0x0F, 15, 0, false),
            (0x10, 0, 1, false),
            (0x70, 0, 7, false),
            (0x80, 0, 0, true),
            (0x23, 3, 2, false), // 0010_0011: model 2, slot 3
            (0xA7, 7, 2, true),  // 1010_0111: erase, model 2, slot 7
            (0xFF, 15, 7, true),
        ] {
            let body = SetCertificateReqBody {
                attributes: attr,
                key_pair_id: 0,
            };
            assert_eq!(body.slot_id(), slot, "attr {attr:#04x}");
            assert_eq!(body.cert_model(), model, "attr {attr:#04x}");
            assert_eq!(body.erase(), erase, "attr {attr:#04x}");
        }
    }

    #[test]
    fn test_set_certificate_req_parse_with_chain_tail() {
        // Body (2) + 4 bytes standing in for the cert chain.
        // SPDM message = 2-byte header + 2-byte body + 4 = 8 bytes.
        let buf = [0x23, 0x04, 0xDE, 0xAD, 0xBE, 0xEF];
        let mut r = WireReader::new(&buf);
        let body: &SetCertificateReqBody = r.read().unwrap();
        assert_eq!(body.slot_id(), 3);
        assert_eq!(body.cert_model(), 2);
        assert!(!body.erase());
        assert_eq!(body.key_pair_id, 4);
        assert_eq!(r.rest(), &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_set_certificate_req_erase_has_no_tail() {
        // Erase request: just the 2-byte body, nothing after it.
        let mut r = WireReader::new(&[0x82, 0x00]);
        let body: &SetCertificateReqBody = r.read().unwrap();
        assert!(body.erase());
        assert_eq!(body.slot_id(), 2);
        assert!(r.is_empty());
    }

    #[test]
    fn test_set_certificate_req_rejects_truncated() {
        assert!(WireReader::new(&[0x01]).read::<SetCertificateReqBody>().is_err());
        assert!(WireReader::new(&[]).read::<SetCertificateReqBody>().is_err());
    }

    #[test]
    fn test_set_certificate_req_slot_not_range_checked() {
        // Pins current leniency: slot_id() returns any 4-bit value (up to 15)
        // and cert_model 7 is accepted; checking against supported slots/models
        // is left to the handler.
        let body = SetCertificateReqBody {
            attributes: 0x7F,
            key_pair_id: 0xFF,
        };
        assert_eq!(body.slot_id(), 15);
        assert_eq!(body.cert_model(), 7);
        assert_eq!(body.key_pair_id, 0xFF);
    }

    #[test]
    fn test_set_certificate_rsp_encode_all_versions() {
        let rsp = SetCertificateRsp { slot_id: 3 };
        // Body = slot_id(1) + param2(1) = 2; wire = 2-byte header + 2 = 4 bytes.
        assert_eq!(rsp.body_size(), 2);
        assert_eq!(rsp.encoded_size(), 4);

        for v in [SpdmVersion::V12, SpdmVersion::V13, SpdmVersion::V14] {
            let mut buf = [0xFFu8; 4];
            let mut w = WireWriter::new(&mut buf);
            rsp.encode_with_header(v, &mut w).unwrap();
            // header: version, SET_CERTIFICATE_RSP (0x6E); body: slot, param2 = 0.
            assert_eq!(buf, [v.to_u8(), 0x6E, 0x03, 0x00]);
        }
        assert_eq!(rsp.response_code(), ReqRespCode::SET_CERTIFICATE_RSP);
    }

    #[test]
    fn test_set_certificate_rsp_slot_not_masked() {
        // Pins current leniency: slot_id is written verbatim, even above the
        // 4-bit SlotID range.
        let rsp = SetCertificateRsp { slot_id: 0xFF };
        let mut buf = [0u8; 4];
        let mut w = WireWriter::new(&mut buf);
        rsp.encode_with_header(SpdmVersion::V13, &mut w).unwrap();
        assert_eq!(buf, [0x13, 0x6E, 0xFF, 0x00]);
    }

    #[test]
    fn test_set_certificate_rsp_buffer_too_small() {
        for len in 0..4 {
            let mut buf = [0u8; 4];
            let mut w = WireWriter::new(&mut buf[..len]);
            assert!(
                SetCertificateRsp { slot_id: 1 }
                    .encode_with_header(SpdmVersion::V13, &mut w)
                    .is_err(),
                "len {len}"
            );
        }
    }

    #[test]
    fn test_set_certificate_rsp_body_layout() {
        let body = SetCertificateRspBody {
            slot_id: 2,
            param2: 0,
        };
        assert_eq!(body.as_bytes(), &[0x02, 0x00]);
        assert_eq!(SetCertificateRspBody::SIZE, 2);
        assert_eq!(SetCertificateReqBody::SIZE, 2);
    }
}
