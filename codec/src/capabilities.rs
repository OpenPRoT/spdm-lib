// Licensed under the Apache-2.0 license

//! SPDM CAPABILITIES wire types.
//!
//! Two layers:
//!
//! 1. [`CapFlags`] — `Unaligned` newtype over `le::U32` with
//!    bitflags-style API. Embeds directly in [`CapabilitiesBody`] —
//!    no parse-time conversion, no `u32 -> CapFlags` glue.
//! 2. [`CapabilitiesBody`] — single 18-byte wire body for v1.2+
//!    GET_CAPABILITIES request and CAPABILITIES response (same wire
//!    shape in both directions).

use zerocopy::{
    little_endian::{U16, U32},
    FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned,
};

use crate::flag_macros::def_flag_set_le;
use crate::{ReqRespCode, RequestBody, ResponseBody, WireError, WireReader, WireWriter};

def_flag_set_le! {
    /// SPDM capability bitfield. Constants
    /// cover single-bit flags directly. The 2-bit `MEAS` and `PSK`
    /// fields are exposed as per-value constants (`MEAS_NO_SIG`,
    /// `MEAS_SIG`, `PSK`, `PSK_WITH_CTX`).
    pub struct CapFlags(U32: u32) {
        CACHE = 1 << 0,
        CERT = 1 << 1,
        CHAL = 1 << 2,
        /// `MEAS` field bit 3 set (value `1` = NO_SIG).
        MEAS_NO_SIG = 1 << 3,
        /// `MEAS` field bit 4 set (value `2` = SIG).
        MEAS_SIG = 2 << 3,
        MEAS_FRESH = 1 << 5,
        ENCRYPT = 1 << 6,
        MAC = 1 << 7,
        MUT_AUTH = 1 << 8,
        KEY_EX = 1 << 9,
        /// `PSK` field bit 10 set (value `1` = PSK).
        PSK = 1 << 10,
        /// `PSK` field bit 11 set (value `2` = PSK_WITH_CTX).
        PSK_WITH_CTX = 2 << 10,
        ENCAP = 1 << 12,
        HBEAT = 1 << 13,
        KEY_UPD = 1 << 14,
        HANDSHAKE_IN_THE_CLEAR = 1 << 15,
        PUB_KEY_ID = 1 << 16,
        CHUNK = 1 << 17,
        ALIAS_CERT = 1 << 18,
        SET_CERT = 1 << 19,
        CSR = 1 << 20,
        CERT_INSTALL_RESET = 1 << 21,
        EP_INFO_NO_SIG = 1 << 22,
        EP_INFO_SIG = 2 << 22,
        MEL = 1 << 24,
        EVENT = 1 << 25,
        /// `MULTI_KEY_CAP` field bits 27:26 set to `01b` (`MultiKeyOnly`).
        MULTI_KEY_ONLY = 1 << 26,
        /// `MULTI_KEY_CAP` field bits 27:26 set to `10b` (`MultiKeyConnRsp`).
        MULTI_KEY_CONN_RSP = 2 << 26,
        GET_KEY_PAIR_INFO = 1 << 28,
        SET_KEY_PAIR_INFO = 1 << 29,
        SET_KEY_PAIR_RESET = 1 << 30,
        LARGE_RESP = 1 << 31,
    }
}

impl CapFlags {
    /// 2-bit `MEAS` field value (bits 3..=4).
    #[inline]
    pub fn meas_field(self) -> u8 {
        ((self.into_bits() >> 3) & 0b11) as u8
    }
    /// 2-bit `PSK` field value (bits 10..=11).
    #[inline]
    pub fn psk_field(self) -> u8 {
        ((self.into_bits() >> 10) & 0b11) as u8
    }

    /// 2-bit `MULTI_KEY_CAP` field value (bits 26..=27).
    #[inline]
    pub fn multi_key_field(self) -> u8 {
        ((self.into_bits() >> 26) & 0b11) as u8
    }
}

def_flag_set_le! {
    /// SPDM V1.4 extended responder capability flags. The requester
    /// field is reserved; responders ignore its value.
    pub struct ExtCapFlags(U16: u16) {
        SLOT_MGMT = 1 << 0,
    }
}

/// 18-byte CAPABILITIES body for v1.2+. Identical
/// layout for `GET_CAPABILITIES` request and `CAPABILITIES`
/// response.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Default)]
#[repr(C)]
pub struct CapabilitiesBody {
    pub param1: u8,
    pub param2: u8,
    pub reserved: u8,
    pub ct_exponent: u8,
    /// Extended response capability flags in V1.4. The request field is reserved;
    /// the field is reserved in both directions in older versions.
    pub ext_flags: ExtCapFlags,
    pub flags: CapFlags,
    pub data_transfer_size: U32,
    pub max_spdm_msg_size: U32,
}

impl CapabilitiesBody {
    pub const SIZE: usize = 18;

    /// Minimum DataTransferSize for V1.2+ is 42 bytes.
    pub const MIN_DATA_TRANSFER_SIZE: u32 = 42;

    /// Practical upper bound on CTExponent (CT = 2^32 µs ≈ 1.2 h).
    pub const MAX_CT_EXPONENT: u8 = 32;
}

const _: () = assert!(core::mem::size_of::<CapabilitiesBody>() == CapabilitiesBody::SIZE);

/// Builder for a CAPABILITIES response.
pub struct CapabilitiesRsp {
    pub ct_exponent: u8,
    pub ext_flags: ExtCapFlags,
    pub flags: CapFlags,
    pub data_transfer_size: u32,
    pub max_spdm_msg_size: u32,
}

impl ResponseBody for CapabilitiesRsp {
    fn response_code(&self) -> ReqRespCode {
        ReqRespCode::CAPABILITIES
    }

    fn body_size(&self) -> usize {
        CapabilitiesBody::SIZE
    }

    fn encode_body(&self, w: &mut WireWriter<'_>) -> Result<(), WireError> {
        w.write(&CapabilitiesBody {
            param1: 0,
            param2: 0,
            reserved: 0,
            ct_exponent: self.ct_exponent,
            ext_flags: self.ext_flags,
            flags: self.flags,
            data_transfer_size: U32::new(self.data_transfer_size),
            max_spdm_msg_size: U32::new(self.max_spdm_msg_size),
        })
    }
}

/// Builder for a GET_CAPABILITIES request (requester side). Same 18-byte
/// [`CapabilitiesBody`] wire shape as the response, but carries the
/// `GET_CAPABILITIES` request code.
pub struct GetCapabilitiesReq {
    pub ct_exponent: u8,
    pub flags: CapFlags,
    pub data_transfer_size: u32,
    pub max_spdm_msg_size: u32,
}

impl RequestBody for GetCapabilitiesReq {
    const REQUEST_CODE: ReqRespCode = ReqRespCode::GET_CAPABILITIES;

    fn body_size(&self) -> usize {
        CapabilitiesBody::SIZE
    }

    fn encode_body(&self, w: &mut WireWriter<'_>) -> Result<(), WireError> {
        w.write(&CapabilitiesBody {
            param1: 0,
            param2: 0,
            reserved: 0,
            ct_exponent: self.ct_exponent,
            ext_flags: ExtCapFlags::EMPTY,
            flags: self.flags,
            data_transfer_size: U32::new(self.data_transfer_size),
            max_spdm_msg_size: U32::new(self.max_spdm_msg_size),
        })
    }
}

impl CapabilitiesBody {
    /// Parse a CAPABILITIES response body (everything after the 2-byte SPDM
    /// common header) into the owned [`CapabilitiesBody`] wire struct.
    pub fn parse(body: &[u8]) -> Result<Self, WireError> {
        let mut r = WireReader::new(body);
        let parsed: &CapabilitiesBody = r.read()?;
        Ok(*parsed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SpdmVersion;

    #[test]
    fn test_get_capabilities_req_all_flags_roundtrip() {
        // The defined constants cover bits 0..=31 with no gaps (the 2-bit
        // MEAS/PSK/EP_INFO/MULTI_KEY fields fill their upper bit via the
        // `2 << n` values), so enabling every flag is all 32 bits set.
        // Note this makes each 2-bit field 0b11, which the spec reserves;
        // the codec does not validate field values.
        let flags = CapFlags::from_bits(u32::MAX);
        assert_eq!(flags.meas_field(), 0b11);
        assert_eq!(flags.psk_field(), 0b11);
        assert_eq!(flags.multi_key_field(), 0b11);
        assert!(flags.contains(CapFlags::CACHE));
        assert!(flags.contains(CapFlags::LARGE_RESP));

        let req = GetCapabilitiesReq {
            ct_exponent: 10,
            flags,
            data_transfer_size: 0x1200,
            max_spdm_msg_size: 0x1200,
        };

        // Body = Param1, Param2, Reserved, CTExponent (4) + ExtFlags (2)
        //      + Flags (4) + DataTransferSize (4) + MaxSPDMmsgSize (4) = 18.
        assert_eq!(req.body_size(), 18);

        // Buffer = 2-byte common header + 18-byte body = 20 bytes.
        let mut buf = [0u8; 2 + 18];
        let mut w = WireWriter::new(&mut buf);
        req.encode_with_header(SpdmVersion::V14, &mut w).unwrap();

        assert_eq!(
            buf,
            [
                0x14, 0xE1, // header: V1.4, GET_CAPABILITIES
                0x00, 0x00, 0x00, 0x0A, // param1, param2, reserved, ct_exponent = 10
                0x00, 0x00, // ext_flags (reserved in a request)
                0xFF, 0xFF, 0xFF, 0xFF, // flags: every bit set
                0x00, 0x12, 0x00, 0x00, // data_transfer_size = 0x1200 (little-endian)
                0x00, 0x12, 0x00, 0x00, // max_spdm_msg_size = 0x1200 (little-endian)
            ]
        );

        let parsed = CapabilitiesBody::parse(&buf[2..]).unwrap();
        assert_eq!(parsed.ct_exponent, 10);
        assert!(parsed.ext_flags.is_empty());
        assert_eq!(parsed.flags.into_bits(), u32::MAX);
        assert_eq!(parsed.data_transfer_size.get(), 0x1200);
        assert_eq!(parsed.max_spdm_msg_size.get(), 0x1200);
    }

    #[test]
    fn test_capabilities_rsp_valid_flags_roundtrip() {
        // One legal value per 2-bit field, so no field holds the reserved 0b11:
        //   MEAS = 0b10 (MEAS_SIG), PSK = 0b10 (PSK_WITH_CTX),
        //   EP_INFO = 0b10 (EP_INFO_SIG), MULTI_KEY = 0b10 (MULTI_KEY_CONN_RSP).
        // Every single-bit flag is enabled.
        let flags = CapFlags::CACHE
            | CapFlags::CERT
            | CapFlags::CHAL
            | CapFlags::MEAS_SIG
            | CapFlags::MEAS_FRESH
            | CapFlags::ENCRYPT
            | CapFlags::MAC
            | CapFlags::MUT_AUTH
            | CapFlags::KEY_EX
            | CapFlags::PSK_WITH_CTX
            | CapFlags::ENCAP
            | CapFlags::HBEAT
            | CapFlags::KEY_UPD
            | CapFlags::HANDSHAKE_IN_THE_CLEAR
            | CapFlags::PUB_KEY_ID
            | CapFlags::CHUNK
            | CapFlags::ALIAS_CERT
            | CapFlags::SET_CERT
            | CapFlags::CSR
            | CapFlags::CERT_INSTALL_RESET
            | CapFlags::EP_INFO_SIG
            | CapFlags::MEL
            | CapFlags::EVENT
            | CapFlags::MULTI_KEY_CONN_RSP
            | CapFlags::GET_KEY_PAIR_INFO
            | CapFlags::SET_KEY_PAIR_INFO
            | CapFlags::SET_KEY_PAIR_RESET
            | CapFlags::LARGE_RESP;

        // Each 2-bit field is exactly 0b10, never the reserved 0b11.
        assert_eq!(flags.meas_field(), 0b10);
        assert_eq!(flags.psk_field(), 0b10);
        assert_eq!(flags.multi_key_field(), 0b10);
        assert!(!flags.contains(CapFlags::MEAS_NO_SIG));
        assert!(!flags.contains(CapFlags::PSK));
        assert!(!flags.contains(CapFlags::EP_INFO_NO_SIG));
        assert!(!flags.contains(CapFlags::MULTI_KEY_ONLY));

        // All 32 bits minus the four "low" field bits left clear:
        //   bit 3 (MEAS_NO_SIG) = 0x0000_0008, bit 10 (PSK) = 0x0000_0400,
        //   bit 22 (EP_INFO_NO_SIG) = 0x0040_0000, bit 26 (MULTI_KEY_ONLY) = 0x0400_0000.
        //   0xFFFF_FFFF - 0x0440_0408 = 0xFBBF_FBF7.
        assert_eq!(flags.into_bits(), 0xFBBF_FBF7);

        let rsp = CapabilitiesRsp {
            ct_exponent: 10,
            ext_flags: ExtCapFlags::SLOT_MGMT,
            flags,
            data_transfer_size: 0x400,
            max_spdm_msg_size: 0x800,
        };

        // Body is the same 18-byte CapabilitiesBody as the request.
        assert_eq!(rsp.body_size(), 18);

        // Buffer = 2-byte common header + 18-byte body = 20 bytes.
        let mut buf = [0u8; 2 + 18];
        let mut w = WireWriter::new(&mut buf);
        rsp.encode_with_header(SpdmVersion::V14, &mut w).unwrap();

        assert_eq!(
            buf,
            [
                0x14, 0x61, // header: V1.4, CAPABILITIES
                0x00, 0x00, 0x00, 0x0A, // param1, param2, reserved, ct_exponent = 10
                0x01, 0x00, // ext_flags: SLOT_MGMT (bit 0), little-endian
                0xF7, 0xFB, 0xBF, 0xFB, // flags = 0xFBBF_FBF7, little-endian
                0x00, 0x04, 0x00, 0x00, // data_transfer_size = 0x400 (1024)
                0x00, 0x08, 0x00, 0x00, // max_spdm_msg_size = 0x800 (2048)
            ]
        );

        let parsed = CapabilitiesBody::parse(&buf[2..]).unwrap();
        assert_eq!(parsed.ct_exponent, 10);
        assert_eq!(parsed.ext_flags.into_bits(), ExtCapFlags::SLOT_MGMT.into_bits());
        assert_eq!(parsed.flags.into_bits(), flags.into_bits());
        assert_eq!(parsed.data_transfer_size.get(), 0x400);
        assert_eq!(parsed.max_spdm_msg_size.get(), 0x800);

        // Both sizes are below the 0x1200 used in the request test, and the
        // max message size is not smaller than the transfer size.
        assert!(parsed.data_transfer_size.get() >= CapabilitiesBody::MIN_DATA_TRANSFER_SIZE);
        assert!(parsed.max_spdm_msg_size.get() >= parsed.data_transfer_size.get());
    }
}
