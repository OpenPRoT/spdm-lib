// Licensed under the Apache-2.0 license

//! SPDM protocol version + VERSION response wire types.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{ReqRespCode, RequestBody, ResponseBody, WireError, WireReader, WireWriter};

// ---- SpdmVersion -----------------------------------------------------------

/// SPDM protocol version. Spec encodes it as a single byte
/// `(major << 4) | minor`.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SpdmVersion {
    V10 = 0x10,
    V11 = 0x11,
    V12 = 0x12,
    V13 = 0x13,
    V14 = 0x14,
}

impl SpdmVersion {
    /// Highest spec version implemented by the spdm-lib stack.
    pub const MAX: Self = SpdmVersion::V14;

    /// Encode as the DSP0274 single-byte representation.
    pub const fn to_u8(self) -> u8 {
        self as u8
    }

    /// Decode from the DSP0274 single-byte representation. Returns
    /// `None` for an unsupported / future spec version.
    pub const fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x10 => Some(SpdmVersion::V10),
            0x11 => Some(SpdmVersion::V11),
            0x12 => Some(SpdmVersion::V12),
            0x13 => Some(SpdmVersion::V13),
            0x14 => Some(SpdmVersion::V14),
            _ => None,
        }
    }

    /// Wire-spec "M.N" string used as the version token inside the
    /// SPDM signing-context prefix.
    pub const fn spec_str(self) -> &'static str {
        match self {
            SpdmVersion::V10 => "1.0",
            SpdmVersion::V11 => "1.1",
            SpdmVersion::V12 => "1.2",
            SpdmVersion::V13 => "1.3",
            SpdmVersion::V14 => "1.4",
        }
    }
}

// ---- GET_VERSION request wire types ----------------------------------------

/// 2-byte GET_VERSION request body (DSP0274 §10.2 Table 8): `Param1` and
/// `Param2` are both Reserved and must be 0.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct GetVersionReqBody {
    pub param1: u8,
    pub param2: u8,
}

impl GetVersionReqBody {
    pub const SIZE: usize = 2;
}

const _: () = assert!(core::mem::size_of::<GetVersionReqBody>() == GetVersionReqBody::SIZE);

impl RequestBody for GetVersionReqBody {
    const REQUEST_CODE: ReqRespCode = ReqRespCode::GET_VERSION;

    fn body_size(&self) -> usize {
        GetVersionReqBody::SIZE
    }

    fn encode_body(&self, w: &mut WireWriter<'_>) -> Result<(), WireError> {
        w.write(self)
    }
}

// ---- VERSION response parser (requester side) ------------------------------

/// A parsed VERSION response: the responder's supported version list.
#[derive(Debug, Clone)]
pub struct ParsedVersionRsp {
    /// Number of valid entries in `versions`.
    pub count: usize,
    /// Supported versions, decoded from the entry list. Unknown/future
    /// encodings are skipped, so `count` may be less than the wire entry count.
    pub versions: [Option<SpdmVersion>; Self::MAX_ENTRIES],
}

impl ParsedVersionRsp {
    /// Maximum number of version entries we retain (there are only four
    /// defined SPDM versions today).
    pub const MAX_ENTRIES: usize = 8;

    /// Parses a VERSION response body (everything after the 2-byte SPDM common
    /// header). Returns the decoded version list.
    pub fn parse(body: &[u8]) -> Result<Self, WireError> {
        let mut r = WireReader::new(body);
        let hdr: &VersionRspBody = r.read()?;
        let entry_count = hdr.entry_count as usize;

        let mut versions = [None; Self::MAX_ENTRIES];
        let mut kept = 0;
        for _ in 0..entry_count {
            let entry: &VersionNumberEntry = r.read()?;
            if let Some(v) = SpdmVersion::from_u8(entry.major_minor) {
                if kept < Self::MAX_ENTRIES {
                    versions[kept] = Some(v);
                    kept += 1;
                }
            }
        }
        Ok(Self {
            count: kept,
            versions,
        })
    }
}

// ---- VERSION response wire types -------------------------------------------

/// 4-byte VERSION response body header.
///
/// ```text
///  byte 0   byte 1   byte 2     byte 3
/// ┌────────┬────────┬──────────┬───────┐
/// │ Param1 │ Param2 │ Reserved │ Count │
/// └────────┬────────┬──────────┬───────┘
/// ```
///
/// `Count` is the number of [`VersionNumberEntry`] entries that
/// follow. `param1` and `param2` are unused (always 0).
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct VersionRspBody {
    pub param1: u8,
    pub param2: u8,
    pub reserved: u8,
    pub entry_count: u8,
}

impl VersionRspBody {
    pub const SIZE: usize = 4;
}

/// 2-byte SPDM `VersionNumberEntry`.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct VersionNumberEntry {
    /// `Update[7:4] | Alpha[3:0]` — both zero in this stack.
    pub update_alpha: u8,
    /// `Major[7:4] | Minor[3:0]`.
    pub major_minor: u8,
}

impl VersionNumberEntry {
    pub const SIZE: usize = 2;

    /// Construct an entry from an [`SpdmVersion`] (major/minor only,
    /// update/alpha = 0).
    pub const fn from_version(v: SpdmVersion) -> Self {
        Self {
            update_alpha: 0,
            major_minor: v.to_u8(),
        }
    }
}

const _: () = assert!(core::mem::size_of::<VersionRspBody>() == VersionRspBody::SIZE);
const _: () = assert!(core::mem::size_of::<VersionNumberEntry>() == VersionNumberEntry::SIZE);

/// Builder for a VERSION response.
///
/// Per DSP0274 the VERSION response's `SPDMVersion` field is
/// always `V1.0` (version negotiation happens later, in
/// `GET_CAPABILITIES`). The caller of
/// [`encode_with_header`](crate::ResponseBody::encode_with_header)
/// must pass `SpdmVersion::V10`.
pub struct VersionRsp<'a> {
    pub versions: &'a [SpdmVersion],
}

impl ResponseBody for VersionRsp<'_> {
    fn response_code(&self) -> ReqRespCode {
        ReqRespCode::VERSION
    }

    fn body_size(&self) -> usize {
        VersionRspBody::SIZE + self.versions.len() * VersionNumberEntry::SIZE
    }

    fn encode_body(&self, w: &mut WireWriter<'_>) -> Result<(), WireError> {
        w.write(&VersionRspBody {
            param1: 0,
            param2: 0,
            reserved: 0,
            entry_count: u8::try_from(self.versions.len()).map_err(|_| WireError)?,
        })?;
        for &v in self.versions {
            w.write(&VersionNumberEntry::from_version(v))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SpdmMsgHdrPdu;

    const HDR: usize = SpdmMsgHdrPdu::SIZE;
    const BODY_HDR: usize = VersionRspBody::SIZE;
    const ENTRY: usize = VersionNumberEntry::SIZE;
    const OVERFLOW_ENTRIES: usize = u8::MAX as usize + 1;

    #[test]
    fn test_get_version_req_structure() {
        let req = GetVersionReqBody::default();
        assert_eq!(req.body_size(), GetVersionReqBody::SIZE);
        assert_eq!(req.encoded_size(), HDR + GetVersionReqBody::SIZE);

        // DSP0274 §10.2: GET_VERSION is always sent with SPDMVersion = 1.0.
        let mut buf = [0xFFu8; HDR + GetVersionReqBody::SIZE];
        let mut w = WireWriter::new(&mut buf);
        req.encode_with_header(SpdmVersion::V10, &mut w).unwrap();

        assert_eq!(buf, [0x10, 0x84, 0x00, 0x00]);
    }

    #[test]
    fn test_version_rsp_1_2_to_1_4_roundtrip() {
        let supported = [SpdmVersion::V12, SpdmVersion::V13, SpdmVersion::V14];
        let rsp = VersionRsp {
            versions: &supported,
        };
        assert_eq!(rsp.body_size(), BODY_HDR + supported.len() * ENTRY);

        let mut buf = [0xFFu8; HDR + BODY_HDR + 3 * ENTRY];
        let mut w = WireWriter::new(&mut buf);
        rsp.encode_with_header(SpdmVersion::V10, &mut w).unwrap();

        assert_eq!(
            buf,
            [
                0x10, 0x04, // header: V1.0, VERSION
                0x00, 0x00, 0x00, 0x03, // param1, param2, reserved, count = 3
                0x00, 0x12, 0x00, 0x13, 0x00, 0x14, // entries
            ]
        );

        // parse() takes the body, i.e. everything after the common header.
        let parsed = ParsedVersionRsp::parse(&buf[HDR..]).unwrap();
        assert_eq!(parsed.count, 3);
        assert_eq!(
            &parsed.versions[..3],
            &[
                Some(SpdmVersion::V12),
                Some(SpdmVersion::V13),
                Some(SpdmVersion::V14)
            ]
        );
        assert!(parsed.versions[3..].iter().all(Option::is_none));
    }

    // ---- ParsedVersionRsp::parse: malformed input ----------------------------

    #[test]
    fn test_parse_rejects_short_header() {
        // Anything shorter than VersionRspBody must fail.
        assert!(ParsedVersionRsp::parse(&[]).is_err());
        assert!(ParsedVersionRsp::parse(&[0x00; BODY_HDR - 1]).is_err());
    }

    #[test]
    fn test_parse_rejects_truncated_entries() {
        // Header claims 3 entries but only 2 are present.
        let two_of_three = [0x00, 0x00, 0x00, 0x03, 0x00, 0x13, 0x00, 0x14];
        assert!(ParsedVersionRsp::parse(&two_of_three).is_err());

        // Header claims 1 entry but only half an entry follows.
        let half_entry = [0x00, 0x00, 0x00, 0x01, 0x00];
        assert!(ParsedVersionRsp::parse(&half_entry).is_err());

        // Header claims 1 entry but none follow.
        assert!(ParsedVersionRsp::parse(&[0x00, 0x00, 0x00, 0x01]).is_err());
    }

    #[test]
    fn test_parse_zero_entries() {
        let parsed = ParsedVersionRsp::parse(&[0x00, 0x00, 0x00, 0x00]).unwrap();
        assert_eq!(parsed.count, 0);
        assert!(parsed.versions.iter().all(Option::is_none));
    }

    #[test]
    fn test_parse_skips_unknown_version() {
        // 3 wire entries: 1.2, an unknown 1.5 (0x15), 1.4. The unknown one is
        // dropped, so count (2) is below the wire count (3).
        let body = [
            0x00, 0x00, 0x00, 0x03, // header, count = 3
            0x00, 0x12, 0x00, 0x15, 0x00, 0x14, // entries
        ];
        let parsed = ParsedVersionRsp::parse(&body).unwrap();
        assert_eq!(parsed.count, 2);
        assert_eq!(
            &parsed.versions[..2],
            &[Some(SpdmVersion::V12), Some(SpdmVersion::V14)]
        );
        assert!(parsed.versions[2..].iter().all(Option::is_none));
    }

    #[test]
    fn test_parse_caps_at_max_entries() {
        // More valid entries than MAX_ENTRIES: the rest are dropped without
        // panicking or erroring.
        const ENTRIES: usize = ParsedVersionRsp::MAX_ENTRIES + 2;
        let mut body = [0u8; BODY_HDR + ENTRIES * ENTRY];
        body[BODY_HDR - 1] = ENTRIES as u8;
        for entry in body[BODY_HDR..].chunks_exact_mut(ENTRY) {
            entry[1] = 0x14;
        }
        let parsed = ParsedVersionRsp::parse(&body).unwrap();
        assert_eq!(parsed.count, ParsedVersionRsp::MAX_ENTRIES);
        assert!(parsed.versions.iter().all(|v| *v == Some(SpdmVersion::V14)));
    }

    #[test]
    fn test_parse_ignores_update_alpha_and_keeps_duplicates() {
        // Pins current leniency: Update/Alpha (first byte of each entry) is not
        // inspected, and duplicates are not collapsed.
        let body = [
            0x00, 0x00, 0x00, 0x02, // header, count = 2
            0x05, 0x14, // update_alpha = 0x05, still decodes as 1.4
            0x00, 0x14, // duplicate 1.4
        ];
        let parsed = ParsedVersionRsp::parse(&body).unwrap();
        assert_eq!(parsed.count, 2);
        assert_eq!(
            &parsed.versions[..2],
            &[Some(SpdmVersion::V14), Some(SpdmVersion::V14)]
        );
    }

    // ---- VersionRsp encode: edge cases ---------------------------------------

    #[test]
    fn test_version_rsp_empty_list() {
        let rsp = VersionRsp { versions: &[] };
        assert_eq!(rsp.body_size(), BODY_HDR);
        let mut buf = [0xFFu8; HDR + BODY_HDR];
        let mut w = WireWriter::new(&mut buf);
        rsp.encode_with_header(SpdmVersion::V10, &mut w).unwrap();
        assert_eq!(buf, [0x10, 0x04, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_version_rsp_buffer_too_small() {
        let versions = [SpdmVersion::V12, SpdmVersion::V13, SpdmVersion::V14];
        let rsp = VersionRsp {
            versions: &versions,
        };
        // One byte short, so the last entry write must fail.
        let mut buf = [0u8; HDR + BODY_HDR + 3 * ENTRY - 1];
        let mut w = WireWriter::new(&mut buf);
        assert!(rsp.encode_with_header(SpdmVersion::V10, &mut w).is_err());
    }

    #[test]
    fn test_version_rsp_rejects_more_than_255_entries() {
        // Intended behavior: a list whose count does not fit the 1-byte Count
        // field must be rejected, not encoded with a wrapped count (256 -> 0).
        let versions = [SpdmVersion::V14; OVERFLOW_ENTRIES];
        let rsp = VersionRsp {
            versions: &versions,
        };
        // Large enough that only the count check (not buffer space) can cause
        // the failure.
        let mut buf = [0u8; HDR + BODY_HDR + OVERFLOW_ENTRIES * ENTRY];
        let mut w = WireWriter::new(&mut buf);
        assert!(rsp.encode_with_header(SpdmVersion::V10, &mut w).is_err());
    }

    // ---- SpdmVersion helpers -------------------------------------------------

    #[test]
    fn test_spdm_version_roundtrip_and_strings() {
        let all = [
            (SpdmVersion::V10, 0x10, "1.0"),
            (SpdmVersion::V11, 0x11, "1.1"),
            (SpdmVersion::V12, 0x12, "1.2"),
            (SpdmVersion::V13, 0x13, "1.3"),
            (SpdmVersion::V14, 0x14, "1.4"),
        ];
        for (v, byte, s) in all {
            assert_eq!(v.to_u8(), byte);
            assert_eq!(SpdmVersion::from_u8(byte), Some(v));
            assert_eq!(v.spec_str(), s);
        }
    }

    #[test]
    fn test_spdm_version_rejects_unknown_bytes() {
        // Below 1.0, a minor nibble past the defined range, and a future version.
        for b in [0x00, 0x0F, 0x15, 0x20, 0xFF] {
            assert_eq!(SpdmVersion::from_u8(b), None);
        }
    }

    #[test]
    fn test_spdm_version_ordering_and_max() {
        assert!(SpdmVersion::V10 < SpdmVersion::V11);
        assert!(SpdmVersion::V13 < SpdmVersion::V14);
        assert_eq!(SpdmVersion::MAX, SpdmVersion::V14);
    }

    // ---- GET_VERSION request decode ------------------------------------------

    #[test]
    fn test_get_version_req_decode() {
        let mut r = WireReader::new(&[0x00, 0x00]);
        let req: &GetVersionReqBody = r.read().unwrap();
        assert_eq!(req.param1, 0);
        assert_eq!(req.param2, 0);
        assert!(r.is_empty());

        // One byte short of the body.
        let mut short = WireReader::new(&[0x00; GetVersionReqBody::SIZE - 1]);
        assert!(short.read::<GetVersionReqBody>().is_err());
    }
}
