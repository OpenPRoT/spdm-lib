// Licensed under the Apache-2.0 license

//! GET_CERTIFICATE / CERTIFICATE wire types.
//!
//! ## Request
//!
//! ```text
//!  byte 0     byte 1     byte 2..3   byte 4..5
//! ┌──────────┬──────────┬───────────┬──────────┐
//! │ SlotID   │ Attrib   │ Offset    │ Length   │
//! │ (Param1) │ (Param2) │ (LE u16)  │ (LE u16) │
//! └──────────┴──────────┴───────────┴──────────┘
//! ```
//!
//! `Attrib` bit 0 = `SlotSizeRequested` (V1.2+).
//!
//! ## Response
//!
//! ```text
//!  byte 0     byte 1     byte 2..3        byte 4..5         byte 6..end
//! ┌──────────┬──────────┬─────────────────┬─────────────────┬──────────────┐
//! │ SlotID   │ CertInfo │ PortionLength   │ RemainderLength │ CertChain[..]│
//! │ (Param1) │ (Param2) │ (LE u16)        │ (LE u16)        │              │
//! └──────────┴──────────┴─────────────────┴─────────────────┴──────────────┘
//! ```
//!
//! `CertChain` carries `PortionLength` bytes of the SPDM cert-chain
//! wire format (length(2) | reserved(2) | root_hash(48) | DER).

use zerocopy::{
    little_endian::{U16, U32},
    FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned,
};

use crate::{ReqRespCode, RequestBody, ResponseBody, WireError, WireReader, WireWriter};
use bitfield_struct::bitfield;

/// `Param1` field of GET_CERTIFICATE / CERTIFICATE
/// Bits 0..=3 carry the `SlotID`, and bit 7 is the `LargeCertChain` flag (SPDM 1.4).
#[bitfield(u8)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, PartialEq, Eq)]
pub struct GetCertificateParam1 {
    #[bits(4)]
    pub slot_id: u8,
    #[bits(3)]
    _reserved: u8,
    pub large_cert_chain: bool,
}

const PARAM1_SLOT_ID_MASK: u8 = 0xF;

/// 6-byte GET_CERTIFICATE request body (after the 2-byte SPDM
/// common header).
#[derive(
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
    Copy,
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
)]
#[repr(C)]
pub struct GetCertificateReqBody {
    /// `Param1` — `SlotID` in bits 0..=3.
    pub slot_id: u8,
    /// `Param2` — request attributes (bit 0 = SlotSizeRequested).
    pub attributes: u8,
    /// Offset into the SPDM cert chain (bytes).
    pub offset: U16,
    /// Requested length (bytes).
    pub length: U16,
}

impl GetCertificateReqBody {
    pub const SIZE: usize = 6;
}

const _: () = assert!(core::mem::size_of::<GetCertificateReqBody>() == GetCertificateReqBody::SIZE);

/// 14-byte GET_CERTIFICATE request body when LargeCertChain=1
/// (after the 2-byte SPDM common header).
#[derive(
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
    Copy,
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
)]
#[repr(C)]
pub struct GetCertificateLargeReqBody {
    /// `Param1` — `SlotID` in bits 0..=3, `LargeCertChain` in bit 7.
    pub param1: GetCertificateParam1,
    /// `Param2` — request attributes (bit 0 = SlotSizeRequested).
    pub attributes: u8,
    /// 16-bit offset (0 when LargeCertChain=1).
    pub offset: U16,
    /// 16-bit length (0 when LargeCertChain=1).
    pub length: U16,
    /// 32-bit LargeOffset into the SPDM cert chain (bytes).
    pub large_offset: U32,
    /// 32-bit LargeLength requested (bytes).
    pub large_length: U32,
}

impl GetCertificateLargeReqBody {
    pub const SIZE: usize = 14;
}

const _: () =
    assert!(core::mem::size_of::<GetCertificateLargeReqBody>() == GetCertificateLargeReqBody::SIZE);

/// Parsed representation of a GET_CERTIFICATE request body (standard 6-byte or SPDM 1.4 14-byte large).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GetCertificateReq<'a> {
    Standard(&'a GetCertificateReqBody),
    Large(&'a GetCertificateLargeReqBody),
}

impl<'a> GetCertificateReq<'a> {
    /// Parse a GET_CERTIFICATE request body (excluding the 2-byte common SPDM header).
    pub fn parse(body: &'a [u8]) -> Result<Self, WireError> {
        let param1 = GetCertificateParam1::from_bits(*body.first().ok_or(WireError)?);
        if param1.large_cert_chain() {
            let (req, _) =
                GetCertificateLargeReqBody::ref_from_prefix(body).map_err(|_| WireError)?;
            if req.offset != 0 || req.length != 0 {
                return Err(WireError);
            }
            Ok(Self::Large(req))
        } else {
            if body.len() != GetCertificateReqBody::SIZE {
                return Err(WireError);
            }
            let (req, _) = GetCertificateReqBody::ref_from_prefix(body).map_err(|_| WireError)?;
            Ok(Self::Standard(req))
        }
    }

    /// Whether this is a large (SPDM 1.4 LargeCertChain) request.
    #[inline]
    pub fn is_large(&self) -> bool {
        matches!(self, Self::Large(_))
    }

    /// Target SlotID (bits 0..=3).
    #[inline]
    pub fn slot_id(&self) -> u8 {
        match self {
            Self::Standard(req) => req.slot_id & PARAM1_SLOT_ID_MASK,
            Self::Large(req) => req.param1.slot_id(),
        }
    }

    /// Request attributes (Param2).
    #[inline]
    pub fn attributes(&self) -> u8 {
        match self {
            Self::Standard(req) => req.attributes,
            Self::Large(req) => req.attributes,
        }
    }

    /// Whether the SlotSizeRequested attribute bit is set.
    #[inline]
    pub fn is_slot_size_requested(&self) -> bool {
        (self.attributes() & ATTR_SLOT_SIZE_REQUESTED) != 0
    }

    /// Offset into the cert chain in bytes (16-bit for standard, 32-bit for large).
    #[inline]
    pub fn offset(&self) -> usize {
        match self {
            Self::Standard(req) => req.offset.get() as usize,
            Self::Large(req) => req.large_offset.get() as usize,
        }
    }

    /// Requested portion length in bytes (16-bit for standard, 32-bit for large).
    #[inline]
    pub fn length(&self) -> usize {
        match self {
            Self::Standard(req) => req.length.get() as usize,
            Self::Large(req) => req.large_length.get() as usize,
        }
    }

    /// Body size of the corresponding response header (6 for standard, 14 for large).
    #[inline]
    pub fn rsp_header_body_size(&self) -> usize {
        if self.is_large() {
            CertificateLargeRspBody::SIZE
        } else {
            CertificateRspBody::SIZE
        }
    }

    /// Maximum cert chain length that can be represented in this request mode.
    #[inline]
    pub fn max_length_cap(&self) -> usize {
        if self.is_large() {
            u32::MAX as usize
        } else {
            u16::MAX as usize
        }
    }
}

/// Request attribute bit: requester is asking for the total cert
/// chain size only — responder sets `PortionLength = 0` and
/// `RemainderLength = total_cert_chain_size`.
pub const ATTR_SLOT_SIZE_REQUESTED: u8 = 0x01;

/// 6-byte CERTIFICATE response body header.
#[derive(
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
    Copy,
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
)]
#[repr(C)]
pub struct CertificateRspBody {
    pub slot_id: u8,
    /// V1.3: `CertModel` (bits 0..=2), else Reserved.
    pub param2: u8,
    pub portion_length: U16,
    pub remainder_length: U16,
}

impl CertificateRspBody {
    pub const SIZE: usize = 6;
}

const _: () = assert!(core::mem::size_of::<CertificateRspBody>() == CertificateRspBody::SIZE);

/// 14-byte CERTIFICATE response body header when LargeCertChain=1.
#[derive(
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
    Copy,
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
)]
#[repr(C)]
pub struct CertificateLargeRspBody {
    /// `Param1` — `SlotID` in bits 0..=3, `LargeCertChain` in bit 7.
    pub param1: GetCertificateParam1,
    /// V1.3+: `CertModel` (bits 0..=2), else Reserved.
    pub param2: u8,
    /// 16-bit PortionLength (0 per spec when LargeCertChain=1).
    pub portion_length: U16,
    /// 16-bit RemainderLength (0 per spec when LargeCertChain=1).
    pub remainder_length: U16,
    /// 32-bit LargePortionLength.
    pub large_portion_length: U32,
    /// 32-bit LargeRemainderLength.
    pub large_remainder_length: U32,
}

impl CertificateLargeRspBody {
    pub const SIZE: usize = 14;
}

const _: () =
    assert!(core::mem::size_of::<CertificateLargeRspBody>() == CertificateLargeRspBody::SIZE);

/// Builder for a CERTIFICATE response. The handler pre-fills the
/// `chain_portion` slice (from a pool-allocated buffer) before
/// calling [`build_response`](spdm_stack::build).
pub struct CertificateRsp<'a> {
    pub slot_id: u8,
    pub param2: u8,
    pub portion_length: u16,
    pub remainder_length: u16,
    /// Slice of `portion_length` bytes carrying SPDM cert-chain
    /// content for `[offset, offset + portion_length)`.
    pub chain_portion: &'a [u8],
}

impl ResponseBody for CertificateRsp<'_> {
    fn response_code(&self) -> ReqRespCode {
        ReqRespCode::CERTIFICATE
    }

    fn body_size(&self) -> usize {
        CertificateRspBody::SIZE + self.chain_portion.len()
    }

    fn encode_body(&self, w: &mut WireWriter<'_>) -> Result<(), WireError> {
        w.write(&CertificateRspBody {
            slot_id: self.slot_id,
            param2: self.param2,
            portion_length: U16::new(self.portion_length),
            remainder_length: U16::new(self.remainder_length),
        })?;
        w.write_bytes(self.chain_portion)
    }
}

/// Builder for a large CERTIFICATE response (SPDM 1.4 LargeCertChain=1).
pub struct CertificateLargeRsp<'a> {
    pub slot_id: u8,
    pub param2: u8,
    pub large_portion_length: u32,
    pub large_remainder_length: u32,
    /// Slice of `large_portion_length` bytes carrying SPDM cert-chain
    /// content for `[large_offset, large_offset + large_portion_length)`.
    pub chain_portion: &'a [u8],
}

impl ResponseBody for CertificateLargeRsp<'_> {
    fn response_code(&self) -> ReqRespCode {
        ReqRespCode::CERTIFICATE
    }

    fn body_size(&self) -> usize {
        CertificateLargeRspBody::SIZE + self.chain_portion.len()
    }

    fn encode_body(&self, w: &mut WireWriter<'_>) -> Result<(), WireError> {
        if self.slot_id > 0x0F {
            return Err(WireError);
        }
        w.write(&CertificateLargeRspBody {
            param1: GetCertificateParam1::new()
                .with_slot_id(self.slot_id)
                .with_large_cert_chain(true),
            param2: self.param2,
            portion_length: U16::new(0),
            remainder_length: U16::new(0),
            large_portion_length: U32::new(self.large_portion_length),
            large_remainder_length: U32::new(self.large_remainder_length),
        })?;
        w.write_bytes(self.chain_portion)
    }
}

// ---- GET_CERTIFICATE request (requester side) ------------------------------

/// Builder for a GET_CERTIFICATE request. Requests `[offset, offset+length)` of
/// the SPDM cert chain for `slot_id`.
pub struct GetCertificateReqBuilder {
    pub slot_id: u8,
    pub attributes: u8,
    pub offset: u16,
    pub length: u16,
}

impl RequestBody for GetCertificateReqBuilder {
    const REQUEST_CODE: ReqRespCode = ReqRespCode::GET_CERTIFICATE;

    fn body_size(&self) -> usize {
        GetCertificateReqBody::SIZE
    }

    fn encode_body(&self, w: &mut WireWriter<'_>) -> Result<(), WireError> {
        w.write(&GetCertificateReqBody {
            slot_id: self.slot_id,
            attributes: self.attributes,
            offset: U16::new(self.offset),
            length: U16::new(self.length),
        })
    }
}

/// A parsed CERTIFICATE response: the header fields plus a view over the
/// cert-chain portion bytes for `[offset, offset+portion_length)`.
#[derive(Clone, Copy)]
pub struct ParsedCertificateRsp<'a> {
    pub slot_id: u8,
    pub param2: u8,
    pub portion_length: u16,
    pub remainder_length: u16,
    pub portion: &'a [u8],
}

impl<'a> ParsedCertificateRsp<'a> {
    /// Parse a CERTIFICATE response body (everything after the 2-byte SPDM
    /// header).
    pub fn parse(body: &'a [u8]) -> Result<Self, WireError> {
        let mut r = WireReader::new(body);
        let hdr: &CertificateRspBody = r.read()?;
        let portion_length = hdr.portion_length.get();
        let portion = r.take(portion_length as usize)?;
        Ok(Self {
            slot_id: hdr.slot_id,
            param2: hdr.param2,
            portion_length,
            remainder_length: hdr.remainder_length.get(),
            portion,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SpdmVersion;

    #[test]
    fn test_large_req_body_size_and_decode() {
        let bytes = [
            0x81, // slot 1 | LargeCertChain (0x80)
            0x01, // SlotSizeRequested
            0x00, 0x00, // offset
            0x00, 0x00, // length
            0x40, 0x00, 0x00, 0x00, // large_offset = 64
            0x00, 0x10, 0x00, 0x00, // large_length = 4096
        ];
        let (req, _) = GetCertificateLargeReqBody::ref_from_prefix(&bytes).unwrap();
        assert_eq!(req.param1.into_bits(), 0x81);
        assert_eq!(req.param1.slot_id(), 1);
        assert!(req.param1.large_cert_chain());
        assert_eq!(req.attributes, ATTR_SLOT_SIZE_REQUESTED);
        assert_eq!(req.large_offset.get(), 64);
        assert_eq!(req.large_length.get(), 4096);
    }

    #[test]
    fn test_large_rsp_builder() {
        let payload = [0xAA, 0xBB, 0xCC, 0xDD];
        let rsp = CertificateLargeRsp {
            slot_id: 1,
            param2: 2,
            large_portion_length: 4,
            large_remainder_length: 100,
            chain_portion: &payload,
        };

        assert_eq!(rsp.body_size(), 14 + 4);
        let mut buf = [0u8; 2 + 14 + 4];
        let mut w = WireWriter::new(&mut buf);
        rsp.encode_with_header(SpdmVersion::V14, &mut w).unwrap();

        assert_eq!(buf[0], SpdmVersion::V14.to_u8());
        assert_eq!(buf[1], ReqRespCode::CERTIFICATE.0);
        assert_eq!(buf[2], 0x81); // slot 1 | LargeCertChain
        assert_eq!(buf[3], 2); // param2
        assert_eq!(&buf[4..6], &[0, 0]); // portion_length == 0
        assert_eq!(&buf[6..8], &[0, 0]); // remainder_length == 0
        assert_eq!(&buf[8..12], &[4, 0, 0, 0]); // large_portion_length == 4
        assert_eq!(&buf[12..16], &[100, 0, 0, 0]); // large_remainder_length == 100
        assert_eq!(&buf[16..20], &payload);
    }

    #[test]
    fn test_get_certificate_req_enum() {
        // Standard request (6 bytes)
        let std_bytes = [
            0x02, // slot 2
            0x01, // SlotSizeRequested
            0x34, 0x12, // offset = 0x1234
            0x00, 0x10, // length = 0x1000
        ];
        let req = GetCertificateReq::parse(&std_bytes).unwrap();
        assert!(!req.is_large());
        assert_eq!(req.slot_id(), 2);
        assert_eq!(req.attributes(), 0x01);
        assert!(req.is_slot_size_requested());
        assert_eq!(req.offset(), 0x1234);
        assert_eq!(req.length(), 0x1000);
        assert_eq!(req.rsp_header_body_size(), CertificateRspBody::SIZE);
        assert_eq!(req.max_length_cap(), u16::MAX as usize);

        // Large request (14 bytes)
        let large_bytes = [
            0x83, // slot 3 | LargeCertChain
            0x00, // attributes
            0x00, 0x00, // offset
            0x00, 0x00, // length
            0x78, 0x56, 0x34, 0x12, // large_offset = 0x12345678
            0x00, 0x00, 0x01, 0x00, // large_length = 0x00010000
        ];
        let req = GetCertificateReq::parse(&large_bytes).unwrap();
        assert!(req.is_large());
        assert_eq!(req.slot_id(), 3);
        assert_eq!(req.attributes(), 0x00);
        assert!(!req.is_slot_size_requested());
        assert_eq!(req.offset(), 0x12345678);
        assert_eq!(req.length(), 0x00010000);
        assert_eq!(req.rsp_header_body_size(), CertificateLargeRspBody::SIZE);
        assert_eq!(req.max_length_cap(), u32::MAX as usize);

        // Truncated request errors
        assert!(GetCertificateReq::parse(&[]).is_err());
        assert!(GetCertificateReq::parse(&[0x00; 5]).is_err());
        assert!(GetCertificateReq::parse(&[0x80; 13]).is_err());
    }

    // ---- GetCertificateParam1 ---------------------------------------------------

    #[test]
    fn test_param1_bitfield_layout() {
        // Bits 0..=3 SlotID, bits 4..=6 reserved, bit 7 LargeCertChain.
        let p = GetCertificateParam1::from_bits(0x8F);
        assert_eq!(p.slot_id(), 15);
        assert!(p.large_cert_chain());

        let p = GetCertificateParam1::from_bits(0x70); // only reserved bits set
        assert_eq!(p.slot_id(), 0);
        assert!(!p.large_cert_chain());

        // Reserved bits survive a round trip.
        assert_eq!(GetCertificateParam1::from_bits(0xFF).into_bits(), 0xFF);

        // slot 5 (0x05) | LargeCertChain (0x80) = 0x85.
        let built = GetCertificateParam1::new()
            .with_slot_id(5)
            .with_large_cert_chain(true);
        assert_eq!(built.into_bits(), 0x85);
    }

    // ---- GetCertificateReqBuilder ----------------------------------------------

    #[test]
    fn test_get_certificate_req_builder_bytes_and_roundtrip() {
        let req = GetCertificateReqBuilder {
            slot_id: 2,
            attributes: ATTR_SLOT_SIZE_REQUESTED,
            offset: 0x1234,
            length: 0xFFFF,
        };
        // Body = SlotID (1) + Attributes (1) + Offset (2) + Length (2) = 6.
        assert_eq!(req.body_size(), 6);
        // Wire = 2-byte common header + 6-byte body = 8 bytes.
        assert_eq!(req.encoded_size(), 8);

        let mut buf = [0xEEu8; 8];
        let mut w = WireWriter::new(&mut buf);
        req.encode_with_header(SpdmVersion::V13, &mut w).unwrap();
        let len = w.position();
        assert_eq!(len, 8);
        assert_eq!(
            buf,
            [
                0x13, 0x82, // header: V1.3, GET_CERTIFICATE
                0x02, 0x01, // slot 2, SlotSizeRequested
                0x34, 0x12, // offset = 0x1234, little-endian
                0xFF, 0xFF, // length = 0xFFFF
            ]
        );

        let parsed = GetCertificateReq::parse(&buf[2..]).unwrap();
        assert!(!parsed.is_large());
        assert_eq!(parsed.slot_id(), 2);
        assert!(parsed.is_slot_size_requested());
        assert_eq!(parsed.offset(), 0x1234);
        assert_eq!(parsed.length(), 0xFFFF);
    }

    #[test]
    fn test_get_certificate_req_builder_buffer_too_small() {
        let req = GetCertificateReqBuilder {
            slot_id: 0,
            attributes: 0,
            offset: 0,
            length: 0,
        };
        // Needs 2 + 6 = 8 bytes; every shorter writer must fail.
        for len in 0..8 {
            let mut buf = [0u8; 8];
            let mut w = WireWriter::new(&mut buf[..len]);
            assert!(
                req.encode_with_header(SpdmVersion::V13, &mut w).is_err(),
                "writer of {len} bytes must fail"
            );
        }
    }

    // ---- GetCertificateReq::parse edge cases -----------------------------------

    #[test]
    fn test_get_certificate_req_standard_offset_length_extremes() {
        // offset = 0xFFFF, length = 0 (zero-length request is not rejected).
        let req = GetCertificateReq::parse(&[0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00]).unwrap();
        assert_eq!(req.offset(), 0xFFFF);
        assert_eq!(req.length(), 0);

        // offset = 0, length = 0xFFFF.
        let req = GetCertificateReq::parse(&[0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF]).unwrap();
        assert_eq!(req.offset(), 0);
        assert_eq!(req.length(), 0xFFFF);
    }

    #[test]
    fn test_get_certificate_req_standard_requires_exact_length() {
        // Standard form is exactly 6 bytes; one extra byte is rejected.
        assert!(GetCertificateReq::parse(&[0u8; 7]).is_err());
        assert!(GetCertificateReq::parse(&[0u8; 6]).is_ok());
    }

    #[test]
    fn test_get_certificate_req_standard_reserved_bits_not_rejected() {
        // Pins current leniency: reserved Param1 bits 4..=6 and the non-SlotSizeRequested
        // attribute bits are accepted. slot_id() masks to bits 0..=3 (0x72 -> 2).
        let req = GetCertificateReq::parse(&[0x72, 0xFE, 0x00, 0x00, 0x00, 0x00]).unwrap();
        assert!(!req.is_large());
        assert_eq!(req.slot_id(), 2);
        assert_eq!(req.attributes(), 0xFE);
        assert!(!req.is_slot_size_requested()); // bit 0 of 0xFE is clear
    }

    #[test]
    fn test_get_certificate_req_large_rejects_nonzero_16bit_fields() {
        // LargeCertChain=1 requires the 16-bit Offset and Length to be 0.
        let mut bytes = [0u8; 14];
        bytes[0] = 0x80;
        assert!(GetCertificateReq::parse(&bytes).is_ok());

        bytes[2] = 1; // Offset = 1
        assert!(GetCertificateReq::parse(&bytes).is_err());
        bytes[2] = 0;

        bytes[4] = 1; // Length = 1
        assert!(GetCertificateReq::parse(&bytes).is_err());
    }

    #[test]
    fn test_get_certificate_req_large_extremes_trailing_and_reserved_bits() {
        // Pins current leniency: the Large form (unlike Standard) accepts trailing
        // bytes, and reserved Param1 bits 4..=6 are not rejected.
        // Buffer = 14-byte body + 2 trailing bytes = 16.
        let mut bytes = [0u8; 16];
        bytes[0] = 0xF3; // reserved bits 4..=6 | LargeCertChain | slot 3
        bytes[6..10].copy_from_slice(&u32::MAX.to_le_bytes()); // LargeOffset
        bytes[10..14].copy_from_slice(&0x100u32.to_le_bytes()); // LargeLength
        bytes[14..].fill(0xCC);

        let req = GetCertificateReq::parse(&bytes).unwrap();
        assert!(req.is_large());
        assert_eq!(req.slot_id(), 3);
        assert_eq!(req.offset(), u32::MAX as usize);
        assert_eq!(req.length(), 0x100);
    }

    #[test]
    fn test_get_certificate_req_large_truncation_fails() {
        // Large form needs 14 bytes; every shorter slice starting with the
        // LargeCertChain bit must fail.
        let mut bytes = [0u8; 14];
        bytes[0] = 0x80;
        for len in 1..14 {
            assert!(
                GetCertificateReq::parse(&bytes[..len]).is_err(),
                "large prefix of {len} bytes must fail"
            );
        }
    }

    // ---- CertificateRsp encode / ParsedCertificateRsp::parse --------------------

    #[test]
    fn test_certificate_rsp_roundtrip() {
        let payload = [0xAA, 0xBB, 0xCC, 0xDD];
        let rsp = CertificateRsp {
            slot_id: 1,
            param2: 0x02,
            portion_length: 4,
            remainder_length: 100,
            chain_portion: &payload,
        };
        // Body = 6-byte header + 4 portion bytes = 10.
        assert_eq!(rsp.body_size(), 10);

        // Buffer = 2-byte common header + 10-byte body = 12 bytes.
        let mut buf = [0u8; 12];
        let mut w = WireWriter::new(&mut buf);
        rsp.encode_with_header(SpdmVersion::V13, &mut w).unwrap();
        assert_eq!(
            buf,
            [
                0x13, 0x02, // header: V1.3, CERTIFICATE
                0x01, 0x02, // slot 1, param2 (CertModel) = 2
                0x04, 0x00, // portion_length = 4
                0x64, 0x00, // remainder_length = 100
                0xAA, 0xBB, 0xCC, 0xDD, // chain portion
            ]
        );

        let parsed = ParsedCertificateRsp::parse(&buf[2..]).unwrap();
        assert_eq!(parsed.slot_id, 1);
        assert_eq!(parsed.param2, 2);
        assert_eq!(parsed.portion_length, 4);
        assert_eq!(parsed.remainder_length, 100);
        assert_eq!(parsed.portion, &payload);
    }

    #[test]
    fn test_certificate_rsp_slot_size_only_response() {
        // SlotSizeRequested reply: PortionLength = 0, RemainderLength = total chain size.
        let rsp = CertificateRsp {
            slot_id: 0,
            param2: 0,
            portion_length: 0,
            remainder_length: 0x1234,
            chain_portion: &[],
        };
        // Body = 6; buffer = 2 + 6 = 8 bytes.
        assert_eq!(rsp.body_size(), 6);
        let mut buf = [0xEEu8; 8];
        let mut w = WireWriter::new(&mut buf);
        rsp.encode_with_header(SpdmVersion::V13, &mut w).unwrap();
        assert_eq!(buf, [0x13, 0x02, 0x00, 0x00, 0x00, 0x00, 0x34, 0x12]);

        let parsed = ParsedCertificateRsp::parse(&buf[2..]).unwrap();
        assert_eq!(parsed.portion_length, 0);
        assert_eq!(parsed.remainder_length, 0x1234);
        assert!(parsed.portion.is_empty());
    }

    #[test]
    fn test_certificate_rsp_buffer_too_small() {
        let payload = [0xAA, 0xBB, 0xCC, 0xDD];
        let rsp = CertificateRsp {
            slot_id: 1,
            param2: 0,
            portion_length: 4,
            remainder_length: 0,
            chain_portion: &payload,
        };
        // Needs 2 + 6 + 4 = 12 bytes; every shorter writer must fail.
        for len in 0..12 {
            let mut buf = [0u8; 12];
            let mut w = WireWriter::new(&mut buf[..len]);
            assert!(
                rsp.encode_with_header(SpdmVersion::V13, &mut w).is_err(),
                "writer of {len} bytes must fail"
            );
        }
    }

    #[test]
    fn test_certificate_rsp_header_length_not_derived_from_portion() {
        // Pins current gap: the builder writes the caller's `portion_length` verbatim
        // instead of deriving it from `chain_portion.len()`. A mismatched pair encodes
        // successfully into a message the parser then rejects.
        let payload = [0xAA, 0xBB, 0xCC, 0xDD];
        let rsp = CertificateRsp {
            slot_id: 0,
            param2: 0,
            portion_length: 8, // claims 8, carries 4
            remainder_length: 0,
            chain_portion: &payload,
        };
        let mut buf = [0u8; 12];
        let mut w = WireWriter::new(&mut buf);
        rsp.encode_with_header(SpdmVersion::V13, &mut w).unwrap();
        assert_eq!(&buf[4..6], &[0x08, 0x00]);
        assert!(ParsedCertificateRsp::parse(&buf[2..]).is_err());
    }

    #[test]
    fn test_parse_certificate_rsp_rejects_short_header() {
        // Header is 6 bytes; every shorter slice must fail.
        for len in 0..6 {
            assert!(ParsedCertificateRsp::parse(&[0u8; 6][..len]).is_err());
        }
    }

    #[test]
    fn test_parse_certificate_rsp_portion_length_exceeds_body() {
        // Claims 4 portion bytes, only 3 present.
        let body = [0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xAA, 0xBB, 0xCC];
        assert!(ParsedCertificateRsp::parse(&body).is_err());

        // Claims the maximum 0xFFFF bytes with none present (no overflow or panic).
        let body = [0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00];
        assert!(ParsedCertificateRsp::parse(&body).is_err());
    }

    #[test]
    fn test_parse_certificate_rsp_ignores_trailing_bytes() {
        // Pins current leniency: bytes beyond PortionLength are not rejected; the
        // returned portion is limited to the claimed 2 bytes of the 5 present.
        let body = [0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let parsed = ParsedCertificateRsp::parse(&body).unwrap();
        assert_eq!(parsed.portion, &[0x11, 0x22]);
    }

    #[test]
    fn test_parse_certificate_rsp_cannot_parse_large_response() {
        // Pins current gap: ParsedCertificateRsp has no Large variant. A large
        // (LargeCertChain=1) response puts 0 in the 16-bit PortionLength, so it
        // parses "successfully" with an empty portion, slot_id 0x81 (large bit
        // unmasked) and the real lengths dropped, instead of being flagged.
        let payload = [0xAA, 0xBB, 0xCC, 0xDD];
        let rsp = CertificateLargeRsp {
            slot_id: 1,
            param2: 0,
            large_portion_length: 4,
            large_remainder_length: 100,
            chain_portion: &payload,
        };
        let mut buf = [0u8; 2 + 14 + 4];
        let mut w = WireWriter::new(&mut buf);
        rsp.encode_with_header(SpdmVersion::V14, &mut w).unwrap();

        let parsed = ParsedCertificateRsp::parse(&buf[2..]).unwrap();
        assert_eq!(parsed.slot_id, 0x81);
        assert_eq!(parsed.portion_length, 0);
        assert_eq!(parsed.remainder_length, 0);
        assert!(parsed.portion.is_empty());
    }

    // ---- CertificateLargeRsp encode --------------------------------------------

    #[test]
    fn test_large_rsp_empty_portion_exact_bytes() {
        // Remainder above u16::MAX (65536) is only expressible in the 32-bit field.
        let rsp = CertificateLargeRsp {
            slot_id: 0,
            param2: 0,
            large_portion_length: 0,
            large_remainder_length: 0x0001_0000,
            chain_portion: &[],
        };
        // Body = 14; buffer = 2 + 14 = 16 bytes.
        assert_eq!(rsp.body_size(), 14);
        let mut buf = [0xEEu8; 16];
        let mut w = WireWriter::new(&mut buf);
        rsp.encode_with_header(SpdmVersion::V14, &mut w).unwrap();
        assert_eq!(
            buf,
            [
                0x14, 0x02, // header: V1.4, CERTIFICATE
                0x80, 0x00, // param1: slot 0 | LargeCertChain, param2
                0x00, 0x00, // 16-bit portion_length = 0
                0x00, 0x00, // 16-bit remainder_length = 0
                0x00, 0x00, 0x00, 0x00, // large_portion_length = 0
                0x00, 0x00, 0x01, 0x00, // large_remainder_length = 0x0001_0000
            ]
        );
    }

    #[test]
    fn test_large_rsp_buffer_too_small() {
        let payload = [0xAA, 0xBB, 0xCC, 0xDD];
        let rsp = CertificateLargeRsp {
            slot_id: 1,
            param2: 0,
            large_portion_length: 4,
            large_remainder_length: 0,
            chain_portion: &payload,
        };
        // Needs 2 + 14 + 4 = 20 bytes; every shorter writer must fail.
        for len in 0..20 {
            let mut buf = [0u8; 20];
            let mut w = WireWriter::new(&mut buf[..len]);
            assert!(
                rsp.encode_with_header(SpdmVersion::V14, &mut w).is_err(),
                "writer of {len} bytes must fail"
            );
        }
    }

    #[test]
    fn test_large_rsp_header_length_not_derived_from_portion() {
        // Pins current gap (same as the standard builder): large_portion_length is
        // written verbatim and is not checked against chain_portion.len().
        let payload = [0xAA, 0xBB];
        let rsp = CertificateLargeRsp {
            slot_id: 0,
            param2: 0,
            large_portion_length: 0x1000, // claims 4096, carries 2
            large_remainder_length: 0,
            chain_portion: &payload,
        };
        let mut buf = [0u8; 2 + 14 + 2];
        let mut w = WireWriter::new(&mut buf);
        rsp.encode_with_header(SpdmVersion::V14, &mut w).unwrap();
        assert_eq!(&buf[8..12], &[0x00, 0x10, 0x00, 0x00]);
    }

    #[test]
    fn test_large_rsp_rejects_slot_id_above_15() {
        // Intended behavior: a slot_id that does not fit the 4-bit SlotID field is
        // rejected with an error; encoding must not panic (panic-free rule).
        let rsp = CertificateLargeRsp {
            slot_id: 0x1F,
            param2: 0,
            large_portion_length: 0,
            large_remainder_length: 0,
            chain_portion: &[],
        };
        let mut buf = [0u8; 16];
        let mut w = WireWriter::new(&mut buf);
        assert!(rsp.encode_with_header(SpdmVersion::V14, &mut w).is_err());
    }
}
