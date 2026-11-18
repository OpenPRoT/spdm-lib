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

//! DIGESTS response.
//!
//! ```text
//!  byte 0           byte 1           byte 2..end
//! ┌────────────────┬─────────────────┬───────────────────┐
//! │ SupportedSlots │ ProvisionedSlots│ digest[0..k]      │
//! │  (Param1)      │  (Param2)       │   variable        │
//! └────────────────┴─────────────────┴───────────────────┘
//! ```
//!
//! `digest[i]` is the negotiated-algorithm hash of the SPDM
//! cert-chain wire format (length(2) | reserved(2) | root_hash(48)
//! | DER chain) for slot `i`. One digest per bit set in
//! `ProvisionedSlots`.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{ReqRespCode, RequestBody, ResponseBody, WireError, WireReader, WireWriter};

/// 2-byte DIGESTS response body header.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct DigestsRspBody {
    /// `Param1` — `SupportedSlotMask` (V1.3+) / Reserved (V1.2-).
    pub supported_slots: u8,
    /// `Param2` — `ProvisionedSlotMask` (V1.3+) / `SlotMask` (V1.2-).
    pub provisioned_slots: u8,
}

impl DigestsRspBody {
    pub const SIZE: usize = 2;
}

const _: () = assert!(core::mem::size_of::<DigestsRspBody>() == DigestsRspBody::SIZE);

/// Builder for a DIGESTS response.
///
/// The handler streams cert-chain bytes through `SpdmPalHash` and
/// fills `digests` itself before calling `build_response`. This
/// builder just writes the 2-byte header + N digest bytes.
pub struct DigestsRsp<'a> {
    pub supported_slots: u8,
    pub provisioned_slots: u8,
    /// Concatenated digests (one per bit set in `provisioned_slots`).
    /// Total length = `popcount(provisioned_slots) * digest_size`.
    pub digests: &'a [u8],
}

impl ResponseBody for DigestsRsp<'_> {
    fn response_code(&self) -> ReqRespCode {
        ReqRespCode::DIGESTS
    }

    fn body_size(&self) -> usize {
        DigestsRspBody::SIZE + self.digests.len()
    }

    fn encode_body(&self, w: &mut WireWriter<'_>) -> Result<(), WireError> {
        w.write(&DigestsRspBody {
            supported_slots: self.supported_slots,
            provisioned_slots: self.provisioned_slots,
        })?;
        w.write_bytes(self.digests)
    }
}

// ---- GET_DIGESTS request (requester side) ----------------------------------

/// GET_DIGESTS request body (DSP0274 §10.5): `Param1`/`Param2` both reserved 0.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct GetDigestsReqBody {
    pub param1: u8,
    pub param2: u8,
}

impl GetDigestsReqBody {
    pub const SIZE: usize = 2;
}

const _: () = assert!(core::mem::size_of::<GetDigestsReqBody>() == GetDigestsReqBody::SIZE);

impl RequestBody for GetDigestsReqBody {
    const REQUEST_CODE: ReqRespCode = ReqRespCode::GET_DIGESTS;

    fn body_size(&self) -> usize {
        GetDigestsReqBody::SIZE
    }

    fn encode_body(&self, w: &mut WireWriter<'_>) -> Result<(), WireError> {
        w.write(self)
    }
}

/// A parsed DIGESTS response: slot masks and a view over the concatenated
/// per-slot digests.
#[derive(Clone, Copy)]
pub struct ParsedDigestsRsp<'a> {
    pub supported_slots: u8,
    pub provisioned_slots: u8,
    /// Concatenated digests, `popcount(provisioned_slots) * digest_size` bytes.
    pub digests: &'a [u8],
}

impl<'a> ParsedDigestsRsp<'a> {
    /// Parse a DIGESTS response body (everything after the 2-byte SPDM header).
    pub fn parse(body: &'a [u8]) -> Result<Self, WireError> {
        let mut r = WireReader::new(body);
        let hdr: &DigestsRspBody = r.read()?;
        let digests = r.rest();
        Ok(Self {
            supported_slots: hdr.supported_slots,
            provisioned_slots: hdr.provisioned_slots,
            digests,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SpdmMsgHdrPdu, SpdmVersion, SHA384_HASH_SIZE};

    const HDR: usize = SpdmMsgHdrPdu::SIZE;
    const MASKS: usize = DigestsRspBody::SIZE;

    #[test]
    fn test_get_digests_req_structure() {
        let req = GetDigestsReqBody::default();
        assert_eq!(req.body_size(), GetDigestsReqBody::SIZE);
        assert_eq!(req.encoded_size(), HDR + GetDigestsReqBody::SIZE);

        let mut buf = [0xFFu8; HDR + GetDigestsReqBody::SIZE];
        let mut w = WireWriter::new(&mut buf);
        req.encode_with_header(SpdmVersion::V13, &mut w).unwrap();
        assert_eq!(buf, [0x13, 0x81, 0x00, 0x00]);
    }

    #[test]
    fn test_digests_rsp_two_slots_roundtrip() {
        // Slots 0 and 1 supported and provisioned (mask 0b11).
        // One SHA-384 digest per provisioned slot.
        let mut digests = [0u8; 2 * SHA384_HASH_SIZE];
        digests[..SHA384_HASH_SIZE].fill(0xAA);
        digests[SHA384_HASH_SIZE..].fill(0xBB);
        assert_eq!(
            digests.len(),
            0b11u8.count_ones() as usize * SHA384_HASH_SIZE
        );

        let rsp = DigestsRsp {
            supported_slots: 0x03,
            provisioned_slots: 0x03,
            digests: &digests,
        };
        assert_eq!(rsp.body_size(), MASKS + digests.len());

        let mut buf = [0u8; HDR + MASKS + 2 * SHA384_HASH_SIZE];
        let mut w = WireWriter::new(&mut buf);
        rsp.encode_with_header(SpdmVersion::V13, &mut w).unwrap();

        let first_end = HDR + MASKS + SHA384_HASH_SIZE;
        assert_eq!(&buf[..HDR + MASKS], &[0x13, 0x01, 0x03, 0x03]); // V1.3, DIGESTS, masks
        assert_eq!(&buf[HDR + MASKS..first_end], &[0xAA; SHA384_HASH_SIZE]);
        assert_eq!(&buf[first_end..], &[0xBB; SHA384_HASH_SIZE]);

        let parsed = ParsedDigestsRsp::parse(&buf[HDR..]).unwrap();
        assert_eq!(parsed.supported_slots, 0x03);
        assert_eq!(parsed.provisioned_slots, 0x03);
        assert_eq!(parsed.digests, &digests[..]);
    }

    #[test]
    fn test_digests_rsp_sparse_slots() {
        // Slots 0-3 supported but only slot 2 provisioned: one digest.
        let digest = [0x5A; SHA384_HASH_SIZE];
        let rsp = DigestsRsp {
            supported_slots: 0b0000_1111,
            provisioned_slots: 0b0000_0100,
            digests: &digest,
        };
        let mut buf = [0u8; HDR + MASKS + SHA384_HASH_SIZE];
        let mut w = WireWriter::new(&mut buf);
        rsp.encode_with_header(SpdmVersion::V13, &mut w).unwrap();

        let parsed = ParsedDigestsRsp::parse(&buf[HDR..]).unwrap();
        assert_eq!(parsed.supported_slots, 0x0F);
        assert_eq!(parsed.provisioned_slots, 0x04);
        assert_eq!(parsed.digests, &digest[..]);
    }

    #[test]
    fn test_digests_rsp_no_provisioned_slots() {
        let rsp = DigestsRsp {
            supported_slots: 0x01,
            provisioned_slots: 0x00,
            digests: &[],
        };
        let mut buf = [0xFFu8; HDR + MASKS];
        let mut w = WireWriter::new(&mut buf);
        rsp.encode_with_header(SpdmVersion::V13, &mut w).unwrap();
        assert_eq!(buf, [0x13, 0x01, 0x01, 0x00]);

        let parsed = ParsedDigestsRsp::parse(&buf[HDR..]).unwrap();
        assert!(parsed.digests.is_empty());
    }

    #[test]
    fn test_digests_rsp_buffer_too_small() {
        let digests = [0u8; SHA384_HASH_SIZE];
        let rsp = DigestsRsp {
            supported_slots: 0x01,
            provisioned_slots: 0x01,
            digests: &digests,
        };
        // One byte short.
        let mut buf = [0u8; HDR + MASKS + SHA384_HASH_SIZE - 1];
        let mut w = WireWriter::new(&mut buf);
        assert!(rsp.encode_with_header(SpdmVersion::V13, &mut w).is_err());
    }

    #[test]
    fn test_parse_digests_rejects_short_header() {
        assert!(ParsedDigestsRsp::parse(&[]).is_err());
        assert!(ParsedDigestsRsp::parse(&[0x01; MASKS - 1]).is_err());
    }

    #[test]
    fn test_parse_digests_does_not_check_length_against_mask() {
        // Pins current leniency: provisioned mask says 2 slots but only 3 digest
        // bytes follow. The parser returns the tail as-is; the caller must
        // validate popcount(provisioned) * digest_size.
        let body = [0x03, 0x03, 0x01, 0x02, 0x03];
        let parsed = ParsedDigestsRsp::parse(&body).unwrap();
        assert_eq!(parsed.digests, &[0x01, 0x02, 0x03]);
    }
}
