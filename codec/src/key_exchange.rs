// Licensed under the Apache-2.0 license

//! KEY_EXCHANGE / KEY_EXCHANGE_RSP wire types.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{ReqRespCode, ResponseBody, WireError, WireReader, WireWriter, SHA384_HASH_SIZE};

// ---- Constants -------------------------------------------------------------

/// ECDH P-384 exchange data size (x || y, 48 x 2).
pub const ECDH_P384_EXCHANGE_DATA_SIZE: usize = 96;

/// Largest ExchangeData field this responder can negotiate.
pub const MAX_EXCHANGE_DATA_SIZE: usize = ECDH_P384_EXCHANGE_DATA_SIZE;

/// Random data length in KEY_EXCHANGE req/rsp.
pub const KEY_EXCHANGE_RANDOM_DATA_LEN: usize = 32;

/// Fixed KEY_EXCHANGE_RSP body bytes before `ExchangeData`.
pub const KEY_EXCHANGE_RSP_FIXED_BODY_SIZE: usize = 6 + KEY_EXCHANGE_RANDOM_DATA_LEN;

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

const _: () = assert!(core::mem::size_of::<KeyExchangeReqBodyFixed>() == 38);

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
            + 2
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
            + 2
            + self.opaque_data.len()
            + self.signature.len()
            + self.verify_data_len()
    }

    fn encode_body(&self, w: &mut WireWriter<'_>) -> Result<(), WireError> {
        w.write_bytes(&[self.heartbeat_period.0])?;
        w.write_bytes(&[0u8])?;
        w.write_bytes(&self.rsp_session_id.to_le_bytes())?;
        w.write_bytes(&[0u8])?;
        w.write_bytes(&[0u8])?;
        w.write_bytes(self.random_data)?;
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
        let random_data = [0u8; KEY_EXCHANGE_RANDOM_DATA_LEN];
        let response = KeyExchangeRsp {
            heartbeat_period: HeartBeatPeriod::DISABLED,
            rsp_session_id: 1,
            random_data: &random_data,
            exchange_data_len: 4,
            meas_summary_hash: None,
            opaque_data: &[],
            signature: &[],
            responder_verify_data: None,
        };
        let mut encoded = [0xa5; 64];

        response
            .encode_with_header(SpdmVersion::V14, &mut WireWriter::new(&mut encoded))
            .unwrap();

        let exchange_data_start = SpdmMsgHdrPdu::SIZE + KEY_EXCHANGE_RSP_FIXED_BODY_SIZE;
        assert_eq!(
            &encoded[exchange_data_start..exchange_data_start + 4],
            &[0xa5; 4]
        );
    }

    // ---- constants / HeartBeatPeriod -------------------------------------------

    #[test]
    fn test_key_exchange_constants() {
        // ECDH P-384 exchange data is x || y = 48 + 48 bytes.
        assert_eq!(ECDH_P384_EXCHANGE_DATA_SIZE, 48 * 2);
        assert_eq!(MAX_EXCHANGE_DATA_SIZE, ECDH_P384_EXCHANGE_DATA_SIZE);
        // Fixed response prefix = HeartbeatPeriod(1) + Reserved(1) + RspSessionID(2)
        //   + MutAuthRequested(1) + ReqSlotIDParam(1) + RandomData(32) = 38.
        assert_eq!(KEY_EXCHANGE_RSP_FIXED_BODY_SIZE, 1 + 1 + 2 + 1 + 1 + 32);
        // Fixed request prefix = MeasSummaryHashType(1) + SlotID(1) + ReqSessionID(2)
        //   + SessionPolicy(1) + Reserved(1) + RandomData(32) = 38.
        assert_eq!(core::mem::size_of::<KeyExchangeReqBodyFixed>(), 1 + 1 + 2 + 1 + 1 + 32);
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

    // Hand-built KEY_EXCHANGE request body:
    //   fixed prefix 38 (meas type 1 + slot 1 + req_session_id 2 + policy 1 + reserved 1 + random 32)
    //   + exchange data 96 (offset 38..134)
    //   + opaque length 2 (offset 134..136)
    //   + opaque bytes (offset 136..).
    // Returns the buffer and the used length (136 + opaque.len()).
    fn req_body(opaque_len_field: u16, opaque: &[u8]) -> ([u8; 160], usize) {
        let mut b = [0u8; 160];
        b[0] = 0xFF; // MeasurementSummaryHashType: all measurements
        b[1] = 3; // SlotID
        b[2] = 0x34; // ReqSessionID = 0x1234 (little-endian)
        b[3] = 0x12;
        b[4] = 1; // SessionPolicy
        b[5] = 0; // Reserved
        b[6..38].fill(0x11); // RandomData
        b[38..134].fill(0x22); // ExchangeData (ECDH P-384, 96 bytes)
        b[134..136].copy_from_slice(&opaque_len_field.to_le_bytes());
        b[136..136 + opaque.len()].copy_from_slice(opaque);
        (b, 136 + opaque.len())
    }

    #[test]
    fn test_key_exchange_req_parse_roundtrip() {
        let (b, n) = req_body(4, &[1, 2, 3, 4]);
        // Body = 38 fixed + 96 exchange data + 2 opaque length + 4 opaque = 140.
        assert_eq!(n, 140);

        let req = KeyExchangeReq::parse(&b[..n], ECDH_P384_EXCHANGE_DATA_SIZE).unwrap();
        assert_eq!(req.fixed.meas_summary_hash_type, 0xFF);
        assert_eq!(req.fixed.slot_id, 3);
        assert_eq!(req.fixed.req_session_id, [0x34, 0x12]);
        assert_eq!(req.fixed.req_session_id_u16(), 0x1234);
        assert_eq!(req.fixed.session_policy, 1);
        assert_eq!(req.fixed.random_data, [0x11; KEY_EXCHANGE_RANDOM_DATA_LEN]);
        assert_eq!(req.exchange_data, &[0x22; 96][..]);
        assert_eq!(req.opaque_data, &[1, 2, 3, 4]);
        assert_eq!(req.encoded_len(), 140);
    }

    #[test]
    fn test_key_exchange_req_parse_zero_length_opaque() {
        let (b, n) = req_body(0, &[]);
        // Body = 38 + 96 + 2 (length field, value 0) + 0 = 136.
        assert_eq!(n, 136);
        let req = KeyExchangeReq::parse(&b[..n], ECDH_P384_EXCHANGE_DATA_SIZE).unwrap();
        assert!(req.opaque_data.is_empty());
        assert_eq!(req.encoded_len(), 136);
    }

    #[test]
    fn test_key_exchange_req_parse_every_truncation_fails() {
        let (b, n) = req_body(4, &[1, 2, 3, 4]);
        // Every strict prefix of the valid 140-byte body must be rejected:
        // short fixed prefix (<38), short exchange data (<134), half an opaque
        // length field (135), and short opaque data (136..140).
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
        // Caller expects 96 bytes of exchange data but only 50 follow the prefix.
        let body = [0u8; 38 + 50];
        assert!(KeyExchangeReq::parse(&body, ECDH_P384_EXCHANGE_DATA_SIZE).is_err());
    }

    #[test]
    fn test_key_exchange_req_parse_ignores_trailing_bytes() {
        // Pins current leniency: bytes after the opaque data are not rejected;
        // encoded_len() reports only the parsed portion (140), not body.len() (145).
        let (mut b, n) = req_body(4, &[1, 2, 3, 4]);
        b[n..n + 5].fill(0xCC);
        let req = KeyExchangeReq::parse(&b[..n + 5], ECDH_P384_EXCHANGE_DATA_SIZE).unwrap();
        assert_eq!(req.encoded_len(), 140);
        assert_eq!(req.opaque_data, &[1, 2, 3, 4]);
    }

    #[test]
    fn test_key_exchange_req_parse_zero_exchange_size_accepted() {
        // Pins current leniency: the codec trusts the caller's negotiated DHE size,
        // including 0. Body = 38 fixed + 0 exchange data + 2 opaque length (0) = 40.
        let body = [0u8; 40];
        let req = KeyExchangeReq::parse(&body, 0).unwrap();
        assert!(req.exchange_data.is_empty());
        assert!(req.opaque_data.is_empty());
        assert_eq!(req.encoded_len(), 40);
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
            exchange_data_len: 4,
            meas_summary_hash: Some(&meas_hash),
            opaque_data: &[0xAA, 0xBB],
            signature: &[0x44; 6],
            responder_verify_data: Some(&verify_data),
        };

        // Body = 38 fixed + 4 exchange data + 48 meas hash + 2 opaque length
        //      + 2 opaque + 6 signature + 48 verify data = 148.
        assert_eq!(rsp.body_size(), 148);

        // Buffer = 2-byte common header + 148-byte body = 150 bytes. Pre-filled with
        // 0xEE so the in-place exchange data region is visibly left untouched.
        let mut buf = [0xEEu8; 150];
        let mut w = WireWriter::new(&mut buf);
        rsp.encode_with_header(SpdmVersion::V14, &mut w).unwrap();
        assert_eq!(w.position(), 150);

        assert_eq!(&buf[0..2], &[0x14, 0x64]); // V1.4, KEY_EXCHANGE_RSP
        assert_eq!(buf[2], 5); // HeartbeatPeriod
        assert_eq!(buf[3], 0); // Reserved
        assert_eq!(&buf[4..6], &[0xCD, 0xAB]); // RspSessionID, little-endian
        assert_eq!(buf[6], 0); // MutAuthRequested (always 0 from this builder)
        assert_eq!(buf[7], 0); // ReqSlotIDParam (always 0 from this builder)
        assert_eq!(&buf[8..40], &[0x77; 32]); // RandomData (2 + 6 + 32 = 40)
        assert_eq!(&buf[40..44], &[0xEE; 4]); // ExchangeData: reserved, not written
        assert_eq!(&buf[44..92], &[0x33; 48]); // MeasurementSummaryHash
        assert_eq!(&buf[92..94], &[0x02, 0x00]); // OpaqueDataLength = 2
        assert_eq!(&buf[94..96], &[0xAA, 0xBB]); // OpaqueData
        assert_eq!(&buf[96..102], &[0x44; 6]); // Signature
        assert_eq!(&buf[102..150], &[0x55; 48]); // ResponderVerifyData
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
        // Body = 38 fixed + 96 exchange data + 2 opaque length + 96 signature = 232.
        assert_eq!(rsp.body_size(), 232);

        // Buffer = 2 + 232 = 234 bytes.
        let mut buf = [0u8; 234];
        let mut w = WireWriter::new(&mut buf);
        rsp.encode_with_header(SpdmVersion::V13, &mut w).unwrap();
        assert_eq!(w.position(), 234);

        assert_eq!(&buf[0..2], &[0x13, 0x64]);
        assert_eq!(&buf[4..6], &[0x01, 0x00]); // RspSessionID = 1
        // Opaque length field is always written, even when 0: offset 2 + 38 + 96 = 136.
        assert_eq!(&buf[136..138], &[0x00, 0x00]);
        assert_eq!(&buf[138..234], &[0x44; 96]);
    }

    #[test]
    fn test_key_exchange_rsp_pqc_sized_fields() {
        // 1.4 PQC-sized fields: ML-KEM-768 ciphertext (1088 bytes) as exchange data
        // and an ML-DSA-87 signature (4627 bytes). Pins current leniency: the builder
        // does not cap exchange_data_len at MAX_EXCHANGE_DATA_SIZE (96).
        let random = [0u8; KEY_EXCHANGE_RANDOM_DATA_LEN];
        let signature = [0x66u8; 4627];
        let rsp = KeyExchangeRsp {
            heartbeat_period: HeartBeatPeriod::DISABLED,
            rsp_session_id: 0,
            random_data: &random,
            exchange_data_len: 1088,
            meas_summary_hash: None,
            opaque_data: &[],
            signature: &signature,
            responder_verify_data: None,
        };
        // Body = 38 fixed + 1088 exchange data + 2 opaque length + 4627 signature = 5755.
        assert_eq!(rsp.body_size(), 5755);

        // Buffer = 2 + 5755 = 5757 bytes. Signature starts at 2 + 38 + 1088 + 2 = 1130.
        let mut buf = [0u8; 5757];
        let mut w = WireWriter::new(&mut buf);
        rsp.encode_with_header(SpdmVersion::V14, &mut w).unwrap();
        assert_eq!(w.position(), 5757);

        assert_eq!(&buf[1128..1130], &[0x00, 0x00]); // OpaqueDataLength = 0
        assert!(buf[1130..5757].iter().all(|&b| b == 0x66));
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
            exchange_data_len: 4,
            meas_summary_hash: Some(&meas_hash),
            opaque_data: &[0xAA, 0xBB],
            signature: &[0x44; 6],
            responder_verify_data: Some(&verify_data),
        };
        // The complete message is 150 bytes; every shorter writer must fail at
        // whichever field runs out of room (header, fixed prefix, exchange data,
        // meas hash, opaque, signature, verify data).
        for len in 0..150 {
            let mut buf = [0u8; 150];
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
        // Body = 38 fixed + 0 + 2 opaque length = 40; buffer = 2 + 40 = 42.
        assert_eq!(rsp.body_size(), 40);
        let mut buf = [0u8; 42];
        let mut w = WireWriter::new(&mut buf);
        rsp.encode_with_header(SpdmVersion::V13, &mut w).unwrap();
        assert_eq!(w.position(), 42);
    }

    #[test]
    fn test_key_exchange_rsp_opaque_max_u16_length() {
        // 65535 is the largest opaque length the 2-byte field can carry.
        let random = [0u8; KEY_EXCHANGE_RANDOM_DATA_LEN];
        let opaque = [0x99u8; 65535];
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
        // Buffer = 2 header + 38 fixed + 2 opaque length + 65535 opaque = 65577.
        let mut buf = [0u8; 2 + 38 + 2 + 65535];
        let mut w = WireWriter::new(&mut buf);
        rsp.encode_with_header(SpdmVersion::V13, &mut w).unwrap();
        assert_eq!(&buf[40..42], &[0xFF, 0xFF]);
        assert_eq!(buf[42], 0x99);
        assert_eq!(buf[65576], 0x99);
    }

    #[test]
    fn test_key_exchange_rsp_rejects_opaque_longer_than_u16() {
        // Intended behavior: opaque data whose length does not fit the 2-byte
        // OpaqueDataLength must be rejected, not encoded with a wrapped length
        // (65536 -> 0) followed by 65536 stray bytes.
        let random = [0u8; KEY_EXCHANGE_RANDOM_DATA_LEN];
        let opaque = [0x99u8; 65536];
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
        // Buffer = 2 + 38 + 2 + 65536 = 65578: large enough that only a length
        // check (not buffer space) can cause the failure.
        let mut buf = [0u8; 2 + 38 + 2 + 65536];
        let mut w = WireWriter::new(&mut buf);
        assert!(rsp.encode_with_header(SpdmVersion::V13, &mut w).is_err());
    }
}
