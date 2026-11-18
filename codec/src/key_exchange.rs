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

//! KEY_EXCHANGE / KEY_EXCHANGE_RSP wire types.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    ReqRespCode, ResponseBody, WireError, WireReader, WireWriter, OPAQUE_DATA_LEN_FIELD_SIZE,
    SHA384_HASH_SIZE,
};

// ---- Constants -------------------------------------------------------------

/// Size of one P-384 coordinate.
const ECC_P384_COORDINATE_SIZE: usize = 48;

/// ECDH P-384 exchange data size (x || y).
pub const ECDH_P384_EXCHANGE_DATA_SIZE: usize = 2 * ECC_P384_COORDINATE_SIZE;

/// Largest ExchangeData field this responder can negotiate.
pub const MAX_EXCHANGE_DATA_SIZE: usize = ECDH_P384_EXCHANGE_DATA_SIZE;

/// Random data length in KEY_EXCHANGE req/rsp.
pub const KEY_EXCHANGE_RANDOM_DATA_LEN: usize = 32;

/// Fixed KEY_EXCHANGE_RSP body bytes before `ExchangeData`.
pub const KEY_EXCHANGE_RSP_FIXED_BODY_SIZE: usize = core::mem::size_of::<KeyExchangeRspBodyFixed>();

/// KEY_EXCHANGE_RSP fixed prefix (after SPDM header, before `ExchangeData`).
#[derive(IntoBytes, Immutable)]
#[repr(C)]
struct KeyExchangeRspBodyFixed {
    heartbeat_period: u8,
    _reserved0: u8,
    rsp_session_id: [u8; 2],
    mut_auth_requested: u8,
    req_slot_id_param: u8,
    random_data: [u8; KEY_EXCHANGE_RANDOM_DATA_LEN],
}

/// KEY_EXCHANGE_RSP HeartbeatPeriod (Param1 of the response, DSP0274): a count
/// of seconds. Zero means heartbeat is supported but not desired on this
/// session, so no liveness watchdog runs.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct HeartBeatPeriod(pub u8);

impl HeartBeatPeriod {
    /// Heartbeat supported but not desired: no watchdog on this session.
    pub const DISABLED: HeartBeatPeriod = HeartBeatPeriod(0);

    /// Whole seconds carried by this period.
    #[inline]
    pub fn secs(self) -> u8 {
        self.0
    }

    /// True when a non-zero period was negotiated.
    #[inline]
    pub fn is_enabled(self) -> bool {
        self.0 != 0
    }
}

// ---- Request ---------------------------------------------------------------

/// KEY_EXCHANGE request fixed prefix (after SPDM header, before variable fields).
///
/// After this struct the request carries:
/// - `ExchangeData(96 for ECDH P-384)`
/// - `OpaqueDataLength(2) + SupportedVersionList(variable)`
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug)]
#[repr(C)]
pub struct KeyExchangeReqBodyFixed {
    /// Measurement summary hash type (0=none, 0xFF=all).
    pub meas_summary_hash_type: u8,
    /// Slot number (0..7).
    pub slot_id: u8,
    /// Requester half of session ID (LE u16).
    pub req_session_id: [u8; 2],
    /// Session policy flags.
    pub session_policy: u8,
    pub _reserved: u8,
    /// Requester random (32 bytes).
    pub random_data: [u8; KEY_EXCHANGE_RANDOM_DATA_LEN],
}

const _: () = assert!(
    core::mem::size_of::<KeyExchangeReqBodyFixed>()
        == core::mem::offset_of!(KeyExchangeReqBodyFixed, random_data)
            + KEY_EXCHANGE_RANDOM_DATA_LEN
);

impl KeyExchangeReqBodyFixed {
    /// Requester session ID as u16 (little-endian).
    #[inline]
    pub fn req_session_id_u16(&self) -> u16 {
        u16::from_le_bytes(self.req_session_id)
    }
}

/// Parsed KEY_EXCHANGE request body.
///
/// Provides a view over the complete request body that follows the SPDM header,
/// including the variable-length exchange data and opaque data fields.
pub struct KeyExchangeReq<'a> {
    /// Fixed prefix fields.
    pub fixed: &'a KeyExchangeReqBodyFixed,
    /// Requester's ECDH P-384 public key.
    pub exchange_data: &'a [u8],
    /// Opaque data (typically secured-message version selection).
    pub opaque_data: &'a [u8],
}

impl<'a> KeyExchangeReq<'a> {
    /// Parse a KEY_EXCHANGE request body.
    pub fn parse(body: &'a [u8], exchange_data_size: usize) -> Result<Self, WireError> {
        let mut r = WireReader::new(body);
        let fixed = r.read::<KeyExchangeReqBodyFixed>()?;
        let exchange_data = r.take(exchange_data_size)?;
        let opaque_len = u16::from_le_bytes([
            *r.take(1)?.first().ok_or(WireError)?,
            *r.take(1)?.first().ok_or(WireError)?,
        ]);
        let opaque_data = r.take(opaque_len as usize)?;
        Ok(Self {
            fixed,
            exchange_data,
            opaque_data,
        })
    }

    /// Total encoded length of the request body (used for transcript hashing).
    #[inline]
    pub fn encoded_len(&self) -> usize {
        core::mem::size_of::<KeyExchangeReqBodyFixed>()
            + self.exchange_data.len()
            + OPAQUE_DATA_LEN_FIELD_SIZE
            + self.opaque_data.len()
    }
}

// ---- Response builder ------------------------------------------------------

/// KEY_EXCHANGE_RSP response builder.
///
/// Wire layout:
/// ```text
/// [ heartbeat_period(1) | reserved(1) | rsp_session_id(2) |
///   mut_auth_requested(1) | req_slot_id_param(1) | random(32) |
///   exchange_data(96) | meas_summary_hash(0|48) |
///   opaque_len(2) | opaque_data(var) |
///   signature(96|4627) | responder_verify_data(0|48) ]
/// ```
pub struct KeyExchangeRsp<'a> {
    pub heartbeat_period: HeartBeatPeriod,
    pub rsp_session_id: u16,
    pub random_data: &'a [u8; KEY_EXCHANGE_RANDOM_DATA_LEN],
    /// Length of responder exchange data already populated in the response buffer.
    pub exchange_data_len: usize,
    pub meas_summary_hash: Option<&'a [u8; SHA384_HASH_SIZE]>,
    pub opaque_data: &'a [u8],
    pub signature: &'a [u8],
    /// Present when HBITC is NOT negotiated and session has MAC/ENCRYPT.
    pub responder_verify_data: Option<&'a [u8; SHA384_HASH_SIZE]>,
}

impl ResponseBody for KeyExchangeRsp<'_> {
    fn response_code(&self) -> ReqRespCode {
        ReqRespCode::KEY_EXCHANGE_RSP
    }

    fn body_size(&self) -> usize {
        KEY_EXCHANGE_RSP_FIXED_BODY_SIZE
            + self.exchange_data_len
            + self.meas_hash_len()
            + OPAQUE_DATA_LEN_FIELD_SIZE
            + self.opaque_data.len()
            + self.signature.len()
            + self.verify_data_len()
    }

    fn encode_body(&self, w: &mut WireWriter<'_>) -> Result<(), WireError> {
        w.write_bytes(
            KeyExchangeRspBodyFixed {
                heartbeat_period: self.heartbeat_period.0,
                _reserved0: 0,
                rsp_session_id: self.rsp_session_id.to_le_bytes(),
                mut_auth_requested: 0,
                req_slot_id_param: 0,
                random_data: *self.random_data,
            }
            .as_bytes(),
        )?;
        w.reserve(self.exchange_data_len)?;
        if let Some(mh) = self.meas_summary_hash {
            w.write_bytes(mh)?;
        }
        let opaque_len = u16::try_from(self.opaque_data.len()).map_err(|_| WireError)?;
        w.write_bytes(&opaque_len.to_le_bytes())?;
        if !self.opaque_data.is_empty() {
            w.write_bytes(self.opaque_data)?;
        }
        if !self.signature.is_empty() {
            w.write_bytes(self.signature)?;
        }
        if let Some(vd) = self.responder_verify_data {
            w.write_bytes(vd)?;
        }
        Ok(())
    }
}

impl KeyExchangeRsp<'_> {
    fn meas_hash_len(&self) -> usize {
        if self.meas_summary_hash.is_some() {
            SHA384_HASH_SIZE
        } else {
            0
        }
    }

    fn verify_data_len(&self) -> usize {
        if self.responder_verify_data.is_some() {
            SHA384_HASH_SIZE
        } else {
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SpdmMsgHdrPdu, SpdmVersion, ECC_P384_SIGNATURE_SIZE};

    const HDR: usize = SpdmMsgHdrPdu::SIZE;
    const FIXED: usize = KEY_EXCHANGE_RSP_FIXED_BODY_SIZE;
    const EXCHANGE: usize = ECDH_P384_EXCHANGE_DATA_SIZE;
    const OPAQUE_LEN: usize = OPAQUE_DATA_LEN_FIELD_SIZE;
    const REQ_OPAQUE_START: usize = FIXED + EXCHANGE + OPAQUE_LEN;
    const REQ_BUF_LEN: usize = REQ_OPAQUE_START + 24;
    const ALL_FIELDS_EXCHANGE_LEN: usize = 4;
    const ALL_FIELDS_OPAQUE: [u8; 2] = [0xAA, 0xBB];
    const ALL_FIELDS_SIGNATURE_LEN: usize = 6;
    const ALL_FIELDS_BODY_LEN: usize = FIXED
        + ALL_FIELDS_EXCHANGE_LEN
        + SHA384_HASH_SIZE
        + OPAQUE_LEN
        + ALL_FIELDS_OPAQUE.len()
        + ALL_FIELDS_SIGNATURE_LEN
        + SHA384_HASH_SIZE;
    const ALL_FIELDS_MSG_LEN: usize = HDR + ALL_FIELDS_BODY_LEN;

    fn encode(period: u8) -> ([u8; 256], usize) {
        let random = [0u8; KEY_EXCHANGE_RANDOM_DATA_LEN];
        let body = KeyExchangeRsp {
            heartbeat_period: HeartBeatPeriod(period),
            rsp_session_id: 0xABCD,
            random_data: &random,
            exchange_data_len: ECDH_P384_EXCHANGE_DATA_SIZE,
            meas_summary_hash: None,
            opaque_data: &[],
            signature: &[],
            responder_verify_data: None,
        };
        let mut buf = [0u8; 256];
        let mut w = WireWriter::new(&mut buf);
        body.encode_with_header(SpdmVersion::V13, &mut w).unwrap();
        let len = w.position();
        (buf, len)
    }

    #[test]
    fn heartbeat_period_is_first_body_byte() {
        let (buf, _) = encode(3);
        assert_eq!(buf[SpdmMsgHdrPdu::SIZE], 3);
        assert_eq!(buf[SpdmMsgHdrPdu::SIZE + 1], 0);
    }

    #[test]
    fn heartbeat_period_zero_encodes_zero() {
        let (buf, _) = encode(0);
        assert_eq!(buf[SpdmMsgHdrPdu::SIZE], 0);
    }

    #[test]
    fn in_place_exchange_data_is_preserved() {
        const EXCHANGE_DATA_LEN: usize = ECC_P384_SIGNATURE_SIZE;
        const SENTINEL: u8 = 0xa5;
        const ENCODED_LEN: usize = SpdmMsgHdrPdu::SIZE
            + KEY_EXCHANGE_RSP_FIXED_BODY_SIZE
            + EXCHANGE_DATA_LEN
            + OPAQUE_DATA_LEN_FIELD_SIZE;

        let random_data = [0u8; KEY_EXCHANGE_RANDOM_DATA_LEN];
        let response = KeyExchangeRsp {
            heartbeat_period: HeartBeatPeriod::DISABLED,
            rsp_session_id: 1,
            random_data: &random_data,
            exchange_data_len: EXCHANGE_DATA_LEN,
            meas_summary_hash: None,
            opaque_data: &[],
            signature: &[],
            responder_verify_data: None,
        };
        let mut encoded = [SENTINEL; ENCODED_LEN];

        response
            .encode_with_header(SpdmVersion::V14, &mut WireWriter::new(&mut encoded))
            .unwrap();

        let exchange_data_start = SpdmMsgHdrPdu::SIZE + KEY_EXCHANGE_RSP_FIXED_BODY_SIZE;
        assert_eq!(
            &encoded[exchange_data_start..exchange_data_start + EXCHANGE_DATA_LEN],
            &[SENTINEL; EXCHANGE_DATA_LEN]
        );
    }

    // ---- constants / HeartBeatPeriod -------------------------------------------

    #[test]
    fn test_key_exchange_constants() {
        // x || y and r || s are both two P-384 coordinates.
        assert_eq!(ECDH_P384_EXCHANGE_DATA_SIZE, ECC_P384_SIGNATURE_SIZE);
        assert_eq!(MAX_EXCHANGE_DATA_SIZE, ECDH_P384_EXCHANGE_DATA_SIZE);
        // The request and response fixed prefixes have the same layout size.
        assert_eq!(
            KEY_EXCHANGE_RSP_FIXED_BODY_SIZE,
            core::mem::size_of::<KeyExchangeReqBodyFixed>()
        );
    }

    #[test]
    fn test_heartbeat_period_helpers() {
        assert_eq!(HeartBeatPeriod::default(), HeartBeatPeriod::DISABLED);
        assert!(!HeartBeatPeriod::DISABLED.is_enabled());
        assert_eq!(HeartBeatPeriod::DISABLED.secs(), 0);
        assert!(HeartBeatPeriod(1).is_enabled());
        assert_eq!(HeartBeatPeriod(30).secs(), 30);
        assert!(HeartBeatPeriod(u8::MAX).is_enabled());
        assert_eq!(HeartBeatPeriod(u8::MAX).secs(), 255);
    }

    // ---- KeyExchangeReq::parse -------------------------------------------------

    // Hand-built KEY_EXCHANGE request body: fixed prefix, exchange data, opaque
    // length field, opaque bytes. Returns the buffer and the used length.
    fn req_body(opaque_len_field: u16, opaque: &[u8]) -> ([u8; REQ_BUF_LEN], usize) {
        let mut b = [0u8; REQ_BUF_LEN];
        b[0] = 0xFF; // MeasurementSummaryHashType: all measurements
        b[1] = 3; // SlotID
        b[2] = 0x34; // ReqSessionID = 0x1234 (little-endian)
        b[3] = 0x12;
        b[4] = 1; // SessionPolicy
        b[5] = 0; // Reserved
        b[6..FIXED].fill(0x11); // RandomData
        b[FIXED..FIXED + EXCHANGE].fill(0x22); // ExchangeData
        b[FIXED + EXCHANGE..REQ_OPAQUE_START].copy_from_slice(&opaque_len_field.to_le_bytes());
        b[REQ_OPAQUE_START..REQ_OPAQUE_START + opaque.len()].copy_from_slice(opaque);
        (b, REQ_OPAQUE_START + opaque.len())
    }

    #[test]
    fn test_key_exchange_req_parse_roundtrip() {
        let (b, n) = req_body(4, &[1, 2, 3, 4]);
        assert_eq!(n, REQ_OPAQUE_START + 4);

        let req = KeyExchangeReq::parse(&b[..n], ECDH_P384_EXCHANGE_DATA_SIZE).unwrap();
        assert_eq!(req.fixed.meas_summary_hash_type, 0xFF);
        assert_eq!(req.fixed.slot_id, 3);
        assert_eq!(req.fixed.req_session_id, [0x34, 0x12]);
        assert_eq!(req.fixed.req_session_id_u16(), 0x1234);
        assert_eq!(req.fixed.session_policy, 1);
        assert_eq!(req.fixed.random_data, [0x11; KEY_EXCHANGE_RANDOM_DATA_LEN]);
        assert_eq!(req.exchange_data, &[0x22; EXCHANGE][..]);
        assert_eq!(req.opaque_data, &[1, 2, 3, 4]);
        assert_eq!(req.encoded_len(), n);
    }

    #[test]
    fn test_key_exchange_req_parse_zero_length_opaque() {
        let (b, n) = req_body(0, &[]);
        assert_eq!(n, REQ_OPAQUE_START);
        let req = KeyExchangeReq::parse(&b[..n], ECDH_P384_EXCHANGE_DATA_SIZE).unwrap();
        assert!(req.opaque_data.is_empty());
        assert_eq!(req.encoded_len(), n);
    }

    #[test]
    fn test_key_exchange_req_parse_every_truncation_fails() {
        let (b, n) = req_body(4, &[1, 2, 3, 4]);
        // Every strict prefix of the valid body must be rejected: short fixed
        // prefix, short exchange data, half an opaque length field, and short
        // opaque data.
        for len in 0..n {
            assert!(
                KeyExchangeReq::parse(&b[..len], ECDH_P384_EXCHANGE_DATA_SIZE).is_err(),
                "prefix of {len} bytes must fail"
            );
        }
    }

    #[test]
    fn test_key_exchange_req_parse_opaque_length_exceeds_buffer() {
        // Length field says 4, only 3 opaque bytes present.
        let (b, n) = req_body(4, &[1, 2, 3]);
        assert!(KeyExchangeReq::parse(&b[..n], ECDH_P384_EXCHANGE_DATA_SIZE).is_err());

        // Length field says 0xFFFF (max), nothing follows.
        let (b, n) = req_body(0xFFFF, &[]);
        assert!(KeyExchangeReq::parse(&b[..n], ECDH_P384_EXCHANGE_DATA_SIZE).is_err());
    }

    #[test]
    fn test_key_exchange_req_parse_exchange_size_larger_than_body() {
        // Caller expects a full exchange data field but only half follows the prefix.
        let body = [0u8; FIXED + EXCHANGE / 2];
        assert!(KeyExchangeReq::parse(&body, ECDH_P384_EXCHANGE_DATA_SIZE).is_err());
    }

    #[test]
    fn test_key_exchange_req_parse_ignores_trailing_bytes() {
        // Pins current leniency: bytes after the opaque data are not rejected;
        // encoded_len() reports only the parsed portion, not body.len().
        const TRAILING: usize = 5;
        let (mut b, n) = req_body(4, &[1, 2, 3, 4]);
        b[n..n + TRAILING].fill(0xCC);
        let req = KeyExchangeReq::parse(&b[..n + TRAILING], ECDH_P384_EXCHANGE_DATA_SIZE).unwrap();
        assert_eq!(req.encoded_len(), n);
        assert_eq!(req.opaque_data, &[1, 2, 3, 4]);
    }

    #[test]
    fn test_key_exchange_req_parse_zero_exchange_size_accepted() {
        // Pins current leniency: the codec trusts the caller's negotiated DHE size,
        // including 0.
        let body = [0u8; FIXED + OPAQUE_LEN];
        let req = KeyExchangeReq::parse(&body, 0).unwrap();
        assert!(req.exchange_data.is_empty());
        assert!(req.opaque_data.is_empty());
        assert_eq!(req.encoded_len(), body.len());
    }

    #[test]
    fn test_key_exchange_req_parse_does_not_validate_params() {
        // Pins current leniency: MeasSummaryHashType (0x42, reserved) and SlotID
        // (9, outside 0..=7) are returned as-is; validation is the handler's job.
        let (mut b, n) = req_body(0, &[]);
        b[0] = 0x42;
        b[1] = 9;
        let req = KeyExchangeReq::parse(&b[..n], ECDH_P384_EXCHANGE_DATA_SIZE).unwrap();
        assert_eq!(req.fixed.meas_summary_hash_type, 0x42);
        assert_eq!(req.fixed.slot_id, 9);
    }

    // ---- KeyExchangeRsp encode -------------------------------------------------

    #[test]
    fn test_key_exchange_rsp_all_fields_exact_layout() {
        let random = [0x77; KEY_EXCHANGE_RANDOM_DATA_LEN];
        let meas_hash = [0x33; SHA384_HASH_SIZE];
        let verify_data = [0x55; SHA384_HASH_SIZE];
        let rsp = KeyExchangeRsp {
            heartbeat_period: HeartBeatPeriod(5),
            rsp_session_id: 0xABCD,
            random_data: &random,
            exchange_data_len: ALL_FIELDS_EXCHANGE_LEN,
            meas_summary_hash: Some(&meas_hash),
            opaque_data: &ALL_FIELDS_OPAQUE,
            signature: &[0x44; ALL_FIELDS_SIGNATURE_LEN],
            responder_verify_data: Some(&verify_data),
        };

        assert_eq!(rsp.body_size(), ALL_FIELDS_BODY_LEN);

        // Pre-filled with 0xEE so the in-place exchange data region is visibly
        // left untouched.
        let mut buf = [0xEEu8; ALL_FIELDS_MSG_LEN];
        let mut w = WireWriter::new(&mut buf);
        rsp.encode_with_header(SpdmVersion::V14, &mut w).unwrap();
        assert_eq!(w.position(), ALL_FIELDS_MSG_LEN);

        assert_eq!(&buf[..HDR], &[0x14, 0x64]); // V1.4, KEY_EXCHANGE_RSP
        assert_eq!(buf[2], 5); // HeartbeatPeriod
        assert_eq!(buf[3], 0); // Reserved
        assert_eq!(&buf[4..6], &[0xCD, 0xAB]); // RspSessionID, little-endian
        assert_eq!(buf[6], 0); // MutAuthRequested (always 0 from this builder)
        assert_eq!(buf[7], 0); // ReqSlotIDParam (always 0 from this builder)
        let (random, rest) = buf[HDR + FIXED - KEY_EXCHANGE_RANDOM_DATA_LEN..]
            .split_at(KEY_EXCHANGE_RANDOM_DATA_LEN);
        assert_eq!(random, &[0x77; KEY_EXCHANGE_RANDOM_DATA_LEN]);
        let (exchange, rest) = rest.split_at(ALL_FIELDS_EXCHANGE_LEN);
        assert_eq!(exchange, &[0xEE; ALL_FIELDS_EXCHANGE_LEN]); // reserved, not written
        let (meas, rest) = rest.split_at(SHA384_HASH_SIZE);
        assert_eq!(meas, &[0x33; SHA384_HASH_SIZE]);
        let (opaque_len, rest) = rest.split_at(OPAQUE_LEN);
        assert_eq!(opaque_len, &[0x02, 0x00]); // OpaqueDataLength = 2
        let (opaque, rest) = rest.split_at(ALL_FIELDS_OPAQUE.len());
        assert_eq!(opaque, &ALL_FIELDS_OPAQUE);
        let (signature, verify) = rest.split_at(ALL_FIELDS_SIGNATURE_LEN);
        assert_eq!(signature, &[0x44; ALL_FIELDS_SIGNATURE_LEN]);
        assert_eq!(verify, &[0x55; SHA384_HASH_SIZE]); // ResponderVerifyData
    }

    #[test]
    fn test_key_exchange_rsp_signature_only() {
        // HBITC-style response: no measurement hash, no opaque data, no verify data.
        let random = [0x77; KEY_EXCHANGE_RANDOM_DATA_LEN];
        let rsp = KeyExchangeRsp {
            heartbeat_period: HeartBeatPeriod::DISABLED,
            rsp_session_id: 0x0001,
            random_data: &random,
            exchange_data_len: ECDH_P384_EXCHANGE_DATA_SIZE,
            meas_summary_hash: None,
            opaque_data: &[],
            signature: &[0x44; ECC_P384_SIGNATURE_SIZE],
            responder_verify_data: None,
        };
        const BODY_LEN: usize = FIXED + EXCHANGE + OPAQUE_LEN + ECC_P384_SIGNATURE_SIZE;
        assert_eq!(rsp.body_size(), BODY_LEN);

        let mut buf = [0u8; HDR + BODY_LEN];
        let mut w = WireWriter::new(&mut buf);
        rsp.encode_with_header(SpdmVersion::V13, &mut w).unwrap();
        assert_eq!(w.position(), buf.len());

        assert_eq!(&buf[..HDR], &[0x13, 0x64]);
        assert_eq!(&buf[4..6], &[0x01, 0x00]); // RspSessionID = 1
                                               // Opaque length field is always written, even when 0.
        let opaque_len_start = HDR + FIXED + EXCHANGE;
        let signature_start = opaque_len_start + OPAQUE_LEN;
        assert_eq!(&buf[opaque_len_start..signature_start], &[0x00, 0x00]);
        assert_eq!(&buf[signature_start..], &[0x44; ECC_P384_SIGNATURE_SIZE]);
    }

    #[test]
    fn test_key_exchange_rsp_pqc_sized_fields() {
        // 1.4 PQC-sized fields: ML-KEM-768 ciphertext as exchange data and an
        // ML-DSA-87 signature. Pins current leniency: the builder does not cap
        // exchange_data_len at MAX_EXCHANGE_DATA_SIZE.
        const ML_KEM_768_CIPHERTEXT_SIZE: usize = 1088;
        const ML_DSA_87_SIGNATURE_SIZE: usize = 4627;
        const BODY_LEN: usize =
            FIXED + ML_KEM_768_CIPHERTEXT_SIZE + OPAQUE_LEN + ML_DSA_87_SIGNATURE_SIZE;
        let random = [0u8; KEY_EXCHANGE_RANDOM_DATA_LEN];
        let signature = [0x66u8; ML_DSA_87_SIGNATURE_SIZE];
        let rsp = KeyExchangeRsp {
            heartbeat_period: HeartBeatPeriod::DISABLED,
            rsp_session_id: 0,
            random_data: &random,
            exchange_data_len: ML_KEM_768_CIPHERTEXT_SIZE,
            meas_summary_hash: None,
            opaque_data: &[],
            signature: &signature,
            responder_verify_data: None,
        };
        assert_eq!(rsp.body_size(), BODY_LEN);

        let mut buf = [0u8; HDR + BODY_LEN];
        let mut w = WireWriter::new(&mut buf);
        rsp.encode_with_header(SpdmVersion::V14, &mut w).unwrap();
        assert_eq!(w.position(), buf.len());

        let signature_start = HDR + FIXED + ML_KEM_768_CIPHERTEXT_SIZE + OPAQUE_LEN;
        assert_eq!(
            &buf[signature_start - OPAQUE_LEN..signature_start],
            &[0x00, 0x00]
        ); // OpaqueDataLength = 0
        assert!(buf[signature_start..].iter().all(|&b| b == 0x66));
    }

    #[test]
    fn test_key_exchange_rsp_buffer_too_small() {
        let random = [0x77; KEY_EXCHANGE_RANDOM_DATA_LEN];
        let meas_hash = [0x33; SHA384_HASH_SIZE];
        let verify_data = [0x55; SHA384_HASH_SIZE];
        let rsp = KeyExchangeRsp {
            heartbeat_period: HeartBeatPeriod(5),
            rsp_session_id: 0xABCD,
            random_data: &random,
            exchange_data_len: ALL_FIELDS_EXCHANGE_LEN,
            meas_summary_hash: Some(&meas_hash),
            opaque_data: &ALL_FIELDS_OPAQUE,
            signature: &[0x44; ALL_FIELDS_SIGNATURE_LEN],
            responder_verify_data: Some(&verify_data),
        };
        // Every writer shorter than the complete message must fail at whichever
        // field runs out of room (header, fixed prefix, exchange data, meas hash,
        // opaque, signature, verify data).
        for len in 0..ALL_FIELDS_MSG_LEN {
            let mut buf = [0u8; ALL_FIELDS_MSG_LEN];
            let mut w = WireWriter::new(&mut buf[..len]);
            assert!(
                rsp.encode_with_header(SpdmVersion::V14, &mut w).is_err(),
                "writer of {len} bytes must fail"
            );
        }
    }

    #[test]
    fn test_key_exchange_rsp_empty_signature_accepted() {
        // Pins current leniency: an empty signature is silently omitted rather than
        // rejected, producing a KEY_EXCHANGE_RSP with no signature field.
        let random = [0u8; KEY_EXCHANGE_RANDOM_DATA_LEN];
        let rsp = KeyExchangeRsp {
            heartbeat_period: HeartBeatPeriod::DISABLED,
            rsp_session_id: 0,
            random_data: &random,
            exchange_data_len: 0,
            meas_summary_hash: None,
            opaque_data: &[],
            signature: &[],
            responder_verify_data: None,
        };
        const BODY_LEN: usize = FIXED + OPAQUE_LEN;
        assert_eq!(rsp.body_size(), BODY_LEN);
        let mut buf = [0u8; HDR + BODY_LEN];
        let mut w = WireWriter::new(&mut buf);
        rsp.encode_with_header(SpdmVersion::V13, &mut w).unwrap();
        assert_eq!(w.position(), buf.len());
    }

    #[test]
    fn test_key_exchange_rsp_opaque_max_u16_length() {
        // u16::MAX is the largest opaque length the 2-byte field can carry.
        const OPAQUE_MAX: usize = u16::MAX as usize;
        let random = [0u8; KEY_EXCHANGE_RANDOM_DATA_LEN];
        let opaque = [0x99u8; OPAQUE_MAX];
        let rsp = KeyExchangeRsp {
            heartbeat_period: HeartBeatPeriod::DISABLED,
            rsp_session_id: 0,
            random_data: &random,
            exchange_data_len: 0,
            meas_summary_hash: None,
            opaque_data: &opaque,
            signature: &[],
            responder_verify_data: None,
        };
        let mut buf = [0u8; HDR + FIXED + OPAQUE_LEN + OPAQUE_MAX];
        let mut w = WireWriter::new(&mut buf);
        rsp.encode_with_header(SpdmVersion::V13, &mut w).unwrap();
        let opaque_start = HDR + FIXED + OPAQUE_LEN;
        assert_eq!(&buf[opaque_start - OPAQUE_LEN..opaque_start], &[0xFF, 0xFF]);
        assert_eq!(buf.get(opaque_start), Some(&0x99));
        assert_eq!(buf.last(), Some(&0x99));
    }

    #[test]
    fn test_key_exchange_rsp_rejects_opaque_longer_than_u16() {
        // Intended behavior: opaque data whose length does not fit the 2-byte
        // OpaqueDataLength must be rejected, not encoded with a wrapped length
        // (u16::MAX + 1 -> 0) followed by that many stray bytes.
        const OPAQUE_OVERFLOW: usize = u16::MAX as usize + 1;
        let random = [0u8; KEY_EXCHANGE_RANDOM_DATA_LEN];
        let opaque = [0x99u8; OPAQUE_OVERFLOW];
        let rsp = KeyExchangeRsp {
            heartbeat_period: HeartBeatPeriod::DISABLED,
            rsp_session_id: 0,
            random_data: &random,
            exchange_data_len: 0,
            meas_summary_hash: None,
            opaque_data: &opaque,
            signature: &[],
            responder_verify_data: None,
        };
        // Large enough that only a length check (not buffer space) can cause the failure.
        let mut buf = [0u8; HDR + FIXED + OPAQUE_LEN + OPAQUE_OVERFLOW];
        let mut w = WireWriter::new(&mut buf);
        assert!(rsp.encode_with_header(SpdmVersion::V13, &mut w).is_err());
    }
}
