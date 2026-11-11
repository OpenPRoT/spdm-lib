// Licensed under the Apache-2.0 license

//! SPDM common message header — wire-format
//! [`SpdmMsgHdrPdu`] (2 bytes) plus the [`ReqRespCode`] map.
//!
//! Every SPDM PDU begins with the same two bytes
//! `(SPDMVersion, RequestResponseCode)`. The next two bytes (`Param1`,
//! `Param2`) are command-specific and belong to each command's body
//! type, not to the common header — see how individual response body
//! structs (`VersionRspBody`, `CapabilitiesRspBody`, …) carry their
//! own `param1` / `param2` fields with command-specific meanings.

use crate::SpdmVersion;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

/// Size of [`SpdmMsgHdrPdu`] in bytes.
pub const SPDM_MSG_HDR_SIZE: usize = 2;

/// SPDM RequestResponseCode.
#[derive(
    FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug, PartialEq, Eq, Hash,
)]
#[repr(transparent)]
pub struct ReqRespCode(pub u8);

impl ReqRespCode {
    // ----- Request codes -----
    pub const GET_DIGESTS: Self = Self(0x81);
    pub const GET_CERTIFICATE: Self = Self(0x82);
    pub const CHALLENGE: Self = Self(0x83);
    pub const GET_VERSION: Self = Self(0x84);
    pub const CHUNK_SEND: Self = Self(0x85);
    pub const CHUNK_GET: Self = Self(0x86);
    pub const GET_MEASUREMENTS: Self = Self(0xE0);
    pub const GET_CAPABILITIES: Self = Self(0xE1);
    pub const NEGOTIATE_ALGORITHMS: Self = Self(0xE3);
    pub const KEY_EXCHANGE: Self = Self(0xE4);
    pub const FINISH: Self = Self(0xE5);
    pub const PSK_EXCHANGE: Self = Self(0xE6);
    pub const PSK_FINISH: Self = Self(0xE7);
    pub const HEARTBEAT: Self = Self(0xE8);
    pub const KEY_UPDATE: Self = Self(0xE9);
    pub const GET_ENCAPSULATED_REQUEST: Self = Self(0xEA);
    pub const DELIVER_ENCAPSULATED_RESPONSE: Self = Self(0xEB);
    pub const END_SESSION: Self = Self(0xEC);
    pub const GET_CSR: Self = Self(0xED);
    pub const SET_CERTIFICATE: Self = Self(0xEE);
    pub const VENDOR_DEFINED_REQUEST: Self = Self(0xFE);

    // ----- Response codes -----
    pub const DIGESTS: Self = Self(0x01);
    pub const CERTIFICATE: Self = Self(0x02);
    pub const CHALLENGE_AUTH: Self = Self(0x03);
    pub const VERSION: Self = Self(0x04);
    pub const CHUNK_SEND_ACK: Self = Self(0x05);
    pub const CHUNK_RESPONSE: Self = Self(0x06);
    pub const MEASUREMENTS: Self = Self(0x60);
    pub const CAPABILITIES: Self = Self(0x61);
    pub const ALGORITHMS: Self = Self(0x63);
    pub const KEY_EXCHANGE_RSP: Self = Self(0x64);
    pub const FINISH_RSP: Self = Self(0x65);
    pub const PSK_EXCHANGE_RSP: Self = Self(0x66);
    pub const PSK_FINISH_RSP: Self = Self(0x67);
    pub const HEARTBEAT_ACK: Self = Self(0x68);
    pub const KEY_UPDATE_ACK: Self = Self(0x69);
    pub const ENCAPSULATED_REQUEST: Self = Self(0x6A);
    pub const ENCAPSULATED_RESPONSE_ACK: Self = Self(0x6B);
    pub const END_SESSION_ACK: Self = Self(0x6C);
    pub const CSR: Self = Self(0x6D);
    pub const SET_CERTIFICATE_RSP: Self = Self(0x6E);
    pub const VENDOR_DEFINED_RESPONSE: Self = Self(0x7E);
    pub const ERROR: Self = Self(0x7F);
}

/// 2-byte SPDM common header (`SPDMHeader`).
///
/// `version` is a raw `u8` because not every byte is a valid
/// [`SpdmVersion`]; the dispatcher validates once via
/// [`SpdmVersion::from_u8`] before dispatching to a handler.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug)]
#[repr(C)]
pub struct SpdmMsgHdrPdu {
    pub version: u8,
    pub code: ReqRespCode,
}

impl SpdmMsgHdrPdu {
    pub const SIZE: usize = SPDM_MSG_HDR_SIZE;

    /// Build a header from typed parts.
    pub const fn new(version: SpdmVersion, code: ReqRespCode) -> Self {
        Self {
            version: version.to_u8(),
            code,
        }
    }
}

const _: () = assert!(core::mem::size_of::<SpdmMsgHdrPdu>() == SpdmMsgHdrPdu::SIZE);
const _: () = assert!(core::mem::align_of::<SpdmMsgHdrPdu>() == 1);

// ---- Protocol-wide constants ------------------------------------------------

pub use spdm_traits::SPDM_NONCE_LEN;

/// SHA-384 digest size (48 bytes).
pub const SHA384_HASH_SIZE: usize = 48;

/// RequesterContext length (SPDM V1.3+, 8 bytes).
pub const REQUESTER_CONTEXT_LEN: usize = 8;

/// ECC P-384 signature size (r || s, 96 bytes).
pub const ECC_P384_SIGNATURE_SIZE: usize = 96;

/// ML-DSA-87 signature size.
pub const MLDSA87_SIGNATURE_SIZE: usize = 4627;

/// SPDM signing context prefix length (4 × 16 bytes).
pub const SPDM_PREFIX_LEN: usize = 64;

/// SPDM signing context operation string length.
pub const SPDM_CONTEXT_LEN: usize = 36;

/// Total signing context length.
pub const SPDM_SIGNING_CONTEXT_LEN: usize = SPDM_PREFIX_LEN + SPDM_CONTEXT_LEN;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WireReader;

    #[test]
    fn test_msg_hdr_new_wire_bytes() {
        assert_eq!(SpdmMsgHdrPdu::SIZE, 2);
        let hdr = SpdmMsgHdrPdu::new(SpdmVersion::V13, ReqRespCode::GET_VERSION);
        assert_eq!(hdr.as_bytes(), &[0x13, 0x84]);

        for (v, byte) in [
            (SpdmVersion::V10, 0x10),
            (SpdmVersion::V11, 0x11),
            (SpdmVersion::V12, 0x12),
            (SpdmVersion::V13, 0x13),
            (SpdmVersion::V14, 0x14),
        ] {
            assert_eq!(SpdmMsgHdrPdu::new(v, ReqRespCode::ERROR).as_bytes(), &[byte, 0x7F]);
        }
    }

    #[test]
    fn test_msg_hdr_decode() {
        let mut r = WireReader::new(&[0x14, 0xE1]);
        let hdr: &SpdmMsgHdrPdu = r.read().unwrap();
        assert_eq!(SpdmVersion::from_u8(hdr.version), Some(SpdmVersion::V14));
        assert_eq!(hdr.code, ReqRespCode::GET_CAPABILITIES);
    }

    // Pins current behavior: the header stores the version as a raw byte and
    // does not validate it; the dispatcher must call SpdmVersion::from_u8.
    #[test]
    fn test_msg_hdr_decode_does_not_validate_version_or_code() {
        let mut r = WireReader::new(&[0xFF, 0x7F]);
        let hdr: &SpdmMsgHdrPdu = r.read().unwrap();
        assert_eq!(hdr.version, 0xFF);
        assert_eq!(SpdmVersion::from_u8(hdr.version), None);
        assert_eq!(hdr.code, ReqRespCode::ERROR);

        // An undefined request code is also accepted at this layer.
        let mut r = WireReader::new(&[0x12, 0x99]);
        let hdr: &SpdmMsgHdrPdu = r.read().unwrap();
        assert_eq!(hdr.code, ReqRespCode(0x99));
    }

    #[test]
    fn test_msg_hdr_rejects_short_input_and_reads_prefix_of_longer() {
        assert!(WireReader::new(&[]).read::<SpdmMsgHdrPdu>().is_err());
        assert!(WireReader::new(&[0x10]).read::<SpdmMsgHdrPdu>().is_err());

        // 4 bytes: the 2-byte header is consumed and Param1/Param2 remain.
        let mut r = WireReader::new(&[0x10, 0x84, 0x00, 0x00]);
        r.read::<SpdmMsgHdrPdu>().unwrap();
        assert_eq!(r.remaining(), 2);
    }

    #[test]
    fn test_req_resp_code_values_and_request_response_pairing() {
        // (request const, request byte, response const, response byte).
        // Every response code is its request code with the top bit cleared.
        let pairs = [
            (ReqRespCode::GET_DIGESTS, 0x81, ReqRespCode::DIGESTS, 0x01),
            (ReqRespCode::GET_CERTIFICATE, 0x82, ReqRespCode::CERTIFICATE, 0x02),
            (ReqRespCode::CHALLENGE, 0x83, ReqRespCode::CHALLENGE_AUTH, 0x03),
            (ReqRespCode::GET_VERSION, 0x84, ReqRespCode::VERSION, 0x04),
            (ReqRespCode::CHUNK_SEND, 0x85, ReqRespCode::CHUNK_SEND_ACK, 0x05),
            (ReqRespCode::CHUNK_GET, 0x86, ReqRespCode::CHUNK_RESPONSE, 0x06),
            (ReqRespCode::GET_MEASUREMENTS, 0xE0, ReqRespCode::MEASUREMENTS, 0x60),
            (ReqRespCode::GET_CAPABILITIES, 0xE1, ReqRespCode::CAPABILITIES, 0x61),
            (ReqRespCode::NEGOTIATE_ALGORITHMS, 0xE3, ReqRespCode::ALGORITHMS, 0x63),
            (ReqRespCode::KEY_EXCHANGE, 0xE4, ReqRespCode::KEY_EXCHANGE_RSP, 0x64),
            (ReqRespCode::FINISH, 0xE5, ReqRespCode::FINISH_RSP, 0x65),
            (ReqRespCode::PSK_EXCHANGE, 0xE6, ReqRespCode::PSK_EXCHANGE_RSP, 0x66),
            (ReqRespCode::PSK_FINISH, 0xE7, ReqRespCode::PSK_FINISH_RSP, 0x67),
            (ReqRespCode::HEARTBEAT, 0xE8, ReqRespCode::HEARTBEAT_ACK, 0x68),
            (ReqRespCode::KEY_UPDATE, 0xE9, ReqRespCode::KEY_UPDATE_ACK, 0x69),
            (ReqRespCode::GET_ENCAPSULATED_REQUEST, 0xEA, ReqRespCode::ENCAPSULATED_REQUEST, 0x6A),
            (
                ReqRespCode::DELIVER_ENCAPSULATED_RESPONSE,
                0xEB,
                ReqRespCode::ENCAPSULATED_RESPONSE_ACK,
                0x6B,
            ),
            (ReqRespCode::END_SESSION, 0xEC, ReqRespCode::END_SESSION_ACK, 0x6C),
            (ReqRespCode::GET_CSR, 0xED, ReqRespCode::CSR, 0x6D),
            (ReqRespCode::SET_CERTIFICATE, 0xEE, ReqRespCode::SET_CERTIFICATE_RSP, 0x6E),
            (
                ReqRespCode::VENDOR_DEFINED_REQUEST,
                0xFE,
                ReqRespCode::VENDOR_DEFINED_RESPONSE,
                0x7E,
            ),
        ];
        for (req, req_byte, rsp, rsp_byte) in pairs {
            assert_eq!(req.0, req_byte);
            assert_eq!(rsp.0, rsp_byte);
            assert_eq!(req.0 ^ 0x80, rsp.0);
        }
        // ERROR (0x7F) is a response with no request counterpart.
        assert_eq!(ReqRespCode::ERROR.0, 0x7F);
    }

    #[test]
    fn test_req_resp_codes_are_unique() {
        let all = [
            ReqRespCode::GET_DIGESTS,
            ReqRespCode::GET_CERTIFICATE,
            ReqRespCode::CHALLENGE,
            ReqRespCode::GET_VERSION,
            ReqRespCode::CHUNK_SEND,
            ReqRespCode::CHUNK_GET,
            ReqRespCode::GET_MEASUREMENTS,
            ReqRespCode::GET_CAPABILITIES,
            ReqRespCode::NEGOTIATE_ALGORITHMS,
            ReqRespCode::KEY_EXCHANGE,
            ReqRespCode::FINISH,
            ReqRespCode::PSK_EXCHANGE,
            ReqRespCode::PSK_FINISH,
            ReqRespCode::HEARTBEAT,
            ReqRespCode::KEY_UPDATE,
            ReqRespCode::GET_ENCAPSULATED_REQUEST,
            ReqRespCode::DELIVER_ENCAPSULATED_RESPONSE,
            ReqRespCode::END_SESSION,
            ReqRespCode::GET_CSR,
            ReqRespCode::SET_CERTIFICATE,
            ReqRespCode::VENDOR_DEFINED_REQUEST,
            ReqRespCode::DIGESTS,
            ReqRespCode::CERTIFICATE,
            ReqRespCode::CHALLENGE_AUTH,
            ReqRespCode::VERSION,
            ReqRespCode::CHUNK_SEND_ACK,
            ReqRespCode::CHUNK_RESPONSE,
            ReqRespCode::MEASUREMENTS,
            ReqRespCode::CAPABILITIES,
            ReqRespCode::ALGORITHMS,
            ReqRespCode::KEY_EXCHANGE_RSP,
            ReqRespCode::FINISH_RSP,
            ReqRespCode::PSK_EXCHANGE_RSP,
            ReqRespCode::PSK_FINISH_RSP,
            ReqRespCode::HEARTBEAT_ACK,
            ReqRespCode::KEY_UPDATE_ACK,
            ReqRespCode::ENCAPSULATED_REQUEST,
            ReqRespCode::ENCAPSULATED_RESPONSE_ACK,
            ReqRespCode::END_SESSION_ACK,
            ReqRespCode::CSR,
            ReqRespCode::SET_CERTIFICATE_RSP,
            ReqRespCode::VENDOR_DEFINED_RESPONSE,
            ReqRespCode::ERROR,
        ];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert!(a != b, "duplicate code {:#04x}", a.0);
            }
        }
    }

    #[test]
    fn test_protocol_constants() {
        assert_eq!(SPDM_MSG_HDR_SIZE, 2);
        assert_eq!(SPDM_NONCE_LEN, 32);
        // SHA-384: 384 bits / 8 = 48 bytes.
        assert_eq!(SHA384_HASH_SIZE, 384 / 8);
        assert_eq!(REQUESTER_CONTEXT_LEN, 8);
        // ECDSA P-384 signature is r || s, each 48 bytes: 2 * 48 = 96.
        assert_eq!(ECC_P384_SIGNATURE_SIZE, 2 * SHA384_HASH_SIZE);
        // Signing-context prefix is 4 strings of 16 bytes: 4 * 16 = 64.
        assert_eq!(SPDM_PREFIX_LEN, 4 * 16);
        assert_eq!(SPDM_CONTEXT_LEN, 36);
        // Total signing context = 64 + 36 = 100.
        assert_eq!(SPDM_SIGNING_CONTEXT_LEN, 100);
    }
}
