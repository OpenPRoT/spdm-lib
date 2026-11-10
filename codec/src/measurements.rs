// Licensed under the Apache-2.0 license

//! GET_MEASUREMENTS / MEASUREMENTS wire types.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    ReqRespCode, RequestBody, ResponseBody, WireError, WireReader, WireWriter,
    ECC_P384_SIGNATURE_SIZE, REQUESTER_CONTEXT_LEN, SPDM_NONCE_LEN,
};

// ---- Constants -------------------------------------------------------------

/// DMTF measurement block metadata size (7 bytes).
pub const MEAS_BLOCK_METADATA_SIZE: usize = 7;

/// Maximum measurement record length (24-bit field).
pub const SPDM_MAX_MEASUREMENT_RECORD_SIZE: u32 = 0xFF_FFFF;

// ---- Request ---------------------------------------------------------------

/// GET_MEASUREMENTS request fixed fields (after SPDM header).
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug)]
#[repr(C)]
pub struct GetMeasurementsReqBody {
    /// Bit 0: signature requested
    /// Bit 1: raw bitstream requested
    pub attributes: u8,
    /// 0x00 = total count only; 0x01..0xFE = specific index; 0xFF = all
    pub measurement_operation: u8,
}

impl GetMeasurementsReqBody {
    /// Whether a signature is requested (bit 0).
    #[inline]
    pub fn signature_requested(&self) -> bool {
        self.attributes & 0x01 != 0
    }

    /// Whether raw bitstream is requested (bit 1).
    #[inline]
    pub fn raw_bitstream_requested(&self) -> bool {
        self.attributes & 0x02 != 0
    }
}

const _: () = assert!(core::mem::size_of::<GetMeasurementsReqBody>() == 2);

// ---- Response builder ------------------------------------------------------

/// MEASUREMENTS response builder.
///
/// The MEASUREMENTS response layout:
/// ```text
/// [ Param1(1) | Param2(1) | NumberOfBlocks(1) | MeasRecordLen(3) |
///   MeasurementRecord(variable) | Nonce(32) | OpaqueLen(2) |
///   OpaqueData(variable) | RequesterContext(8, V1.3+) | Signature(96, optional) ]
/// ```
pub struct MeasurementsRsp<'a> {
    /// Total number of measurement indices (param1 when op=0).
    pub total_number_of_measurement: u8,
    /// SlotID[3:0] | ContentChanged[5:4] in param2.
    pub slot_id: u8,
    /// Content changed indicator (0=no detection, 1=change, 2=no change).
    pub content_changed: u8,
    /// Number of measurement blocks in the record.
    pub number_of_blocks: u8,
    /// Serialized measurement record bytes.
    pub measurement_record: &'a [u8],
    /// Responder nonce (32 bytes).
    pub nonce: &'a [u8; SPDM_NONCE_LEN],
    /// Opaque data (usually empty).
    pub opaque_data: &'a [u8],
    /// RequesterContext (V1.3+).
    pub requester_context: Option<&'a [u8; REQUESTER_CONTEXT_LEN]>,
    /// Signature (present only if signature was requested).
    pub signature: &'a [u8],
}

impl ResponseBody for MeasurementsRsp<'_> {
    fn response_code(&self) -> ReqRespCode {
        ReqRespCode::MEASUREMENTS
    }

    fn body_size(&self) -> usize {
        // param1(1) + param2(1) + number_of_blocks(1) + meas_record_len(3)
        // + measurement_record + nonce(32) + opaque_len(2)
        // + opaque_data + requester_context(opt) + signature(opt)
        1 + 1
            + 1
            + 3
            + self.measurement_record.len()
            + SPDM_NONCE_LEN
            + 2
            + self.opaque_data.len()
            + self.requester_context_len()
            + self.signature.len()
    }

    fn encode_body(&self, w: &mut WireWriter<'_>) -> Result<(), WireError> {
        // Param1: TotalNumberOfMeasurement
        w.write_bytes(&[self.total_number_of_measurement])?;
        // Param2: SlotID[3:0] | ContentChanged[5:4]
        let param2 = (self.slot_id & 0x0F) | ((self.content_changed & 0x03) << 4);
        w.write_bytes(&[param2])?;
        // NumberOfBlocks
        w.write_bytes(&[self.number_of_blocks])?;
        if self.measurement_record.len() > SPDM_MAX_MEASUREMENT_RECORD_SIZE as usize
            || self.opaque_data.len() > u16::MAX as usize
        {
            return Err(WireError);
        }

        // MeasurementRecordLength (3 bytes LE)
        let rec_len = self.measurement_record.len() as u32;
        w.write_bytes(&[
            (rec_len & 0xFF) as u8,
            ((rec_len >> 8) & 0xFF) as u8,
            ((rec_len >> 16) & 0xFF) as u8,
        ])?;
        // MeasurementRecord
        w.write_bytes(self.measurement_record)?;
        // Nonce
        w.write_bytes(self.nonce)?;
        // OpaqueDataLength (2 bytes LE)
        let opaque_len = self.opaque_data.len() as u16;
        w.write_bytes(&opaque_len.to_le_bytes())?;
        // OpaqueData
        if !self.opaque_data.is_empty() {
            w.write_bytes(self.opaque_data)?;
        }
        // RequesterContext (V1.3+)
        if let Some(ctx) = self.requester_context {
            w.write_bytes(ctx)?;
        }
        // Signature
        if !self.signature.is_empty() {
            w.write_bytes(self.signature)?;
        }
        Ok(())
    }
}

impl MeasurementsRsp<'_> {
    fn requester_context_len(&self) -> usize {
        if self.requester_context.is_some() {
            REQUESTER_CONTEXT_LEN
        } else {
            0
        }
    }
}

// ---- DMTF Measurement Block Metadata (7 bytes) -----------------------------

/// DMTF measurement block metadata header.
///
/// Layout:
/// ```text
/// [Index(1) | MeasurementSpecification(1) | MeasurementSize(2) |
///  DMTFSpecMeasurementValueType(1) | DMTFSpecMeasurementValueSize(2)]
/// ```
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug)]
#[repr(C)]
pub struct DmtfMeasurementBlockHeader {
    /// Measurement index (1..=0xFE).
    pub index: u8,
    /// MeasurementSpecification (bit 0 = DMTF).
    pub measurement_specification: u8,
    /// MeasurementSize = sizeof(ValueType) + sizeof(ValueSize) + value_size
    /// i.e. 3 + value_size (stored LE).
    pub measurement_size: [u8; 2],
    /// Bit[6:0] = value type, Bit[7] = 0 for digest, 1 for raw.
    pub value_type: u8,
    /// Size of the measurement value (LE 16-bit).
    pub value_size: [u8; 2],
}

const _: () =
    assert!(core::mem::size_of::<DmtfMeasurementBlockHeader>() == MEAS_BLOCK_METADATA_SIZE);

impl DmtfMeasurementBlockHeader {
    /// Create a new measurement block header.
    ///
    /// * `index` — measurement index (1..=0xFE)
    /// * `is_raw` — true for raw bitstream, false for digest
    /// * `meas_value_type` — DMTF value type (0..=10)
    /// * `value_len` — length of the measurement value
    pub fn new(
        index: u8,
        is_raw: bool,
        meas_value_type: u8,
        value_len: u16,
    ) -> Result<Self, WireError> {
        // value_type(1) + value_size(2) + value; must fit the 16-bit MeasurementSize.
        let meas_size = value_len.checked_add(3).ok_or(WireError)?;
        Ok(Self {
            index,
            measurement_specification: 0x01, // DMTF
            measurement_size: meas_size.to_le_bytes(),
            value_type: meas_value_type | (if is_raw { 0x80 } else { 0x00 }),
            value_size: value_len.to_le_bytes(),
        })
    }
}

// ---- GET_MEASUREMENTS request builder (requester side) ---------------------

/// Measurement request attribute bit: signature requested.
pub const MEAS_ATTR_SIGNATURE_REQUESTED: u8 = 0x01;
/// Measurement request attribute bit: raw bitstream requested.
pub const MEAS_ATTR_RAW_REQUESTED: u8 = 0x02;
/// Measurement operation value: return all measurement blocks.
pub const MEAS_OP_ALL: u8 = 0xFF;

/// Builder for a GET_MEASUREMENTS request.
///
/// When `signature_requested`, the body carries `Nonce(32) + SlotID(1)` after
/// the 2-byte fixed prefix; V1.3+ then appends an 8-byte RequesterContext.
pub struct GetMeasurementsReq {
    pub attributes: u8,
    pub measurement_operation: u8,
    /// Present when a signature is requested.
    pub nonce: Option<[u8; SPDM_NONCE_LEN]>,
    pub slot_id: u8,
    /// Present for V1.3+.
    pub requester_context: Option<[u8; REQUESTER_CONTEXT_LEN]>,
}

impl RequestBody for GetMeasurementsReq {
    const REQUEST_CODE: ReqRespCode = ReqRespCode::GET_MEASUREMENTS;

    fn body_size(&self) -> usize {
        2 + if self.nonce.is_some() {
            SPDM_NONCE_LEN + 1
        } else {
            0
        } + if self.requester_context.is_some() {
            REQUESTER_CONTEXT_LEN
        } else {
            0
        }
    }

    fn encode_body(&self, w: &mut WireWriter<'_>) -> Result<(), WireError> {
        w.write(&GetMeasurementsReqBody {
            attributes: self.attributes,
            measurement_operation: self.measurement_operation,
        })?;
        if let Some(nonce) = &self.nonce {
            w.write_bytes(nonce)?;
            w.write_bytes(&[self.slot_id & 0x0F])?;
        }
        if let Some(ctx) = &self.requester_context {
            w.write_bytes(ctx)?;
        }
        Ok(())
    }
}

/// A parsed MEASUREMENTS response.
///
/// `no_sig_prefix` is the response body excluding the trailing signature — the
/// bytes the requester appends to the L1 transcript before verifying.
#[derive(Clone, Copy)]
pub struct ParsedMeasurementsRsp<'a> {
    pub total_number_of_measurement: u8,
    pub slot_id: u8,
    pub number_of_blocks: u8,
    pub measurement_record: &'a [u8],
    pub nonce: &'a [u8],
    /// Body bytes excluding the trailing signature (empty signature → whole body).
    pub no_sig_prefix: &'a [u8],
    /// Trailing signature; empty if none was requested.
    pub signature: &'a [u8],
}

impl<'a> ParsedMeasurementsRsp<'a> {
    /// Parse a MEASUREMENTS response body (everything after the 2-byte SPDM
    /// header). `signed` and `has_requester_context` describe the variable
    /// trailing fields negotiated for this request/connection.
    pub fn parse(
        body: &'a [u8],
        signed: bool,
        has_requester_context: bool,
    ) -> Result<Self, WireError> {
        let sig_len = if signed { ECC_P384_SIGNATURE_SIZE } else { 0 };
        Self::parse_with_sig_len(body, sig_len, has_requester_context)
    }

    /// As [`parse`](Self::parse), with an explicit trailing signature length
    /// (0 if unsigned), e.g. [`MLDSA87_SIGNATURE_SIZE`](crate::MLDSA87_SIGNATURE_SIZE).
    pub fn parse_with_sig_len(
        body: &'a [u8],
        sig_len: usize,
        has_requester_context: bool,
    ) -> Result<Self, WireError> {
        if body.len() < sig_len {
            return Err(WireError);
        }
        let no_sig_len = body.len() - sig_len;
        let no_sig_prefix = &body[..no_sig_len];
        let signature = &body[no_sig_len..];

        let mut r = WireReader::new(no_sig_prefix);
        let total = r.take(1)?[0];
        let slot_id = r.take(1)?[0] & 0x0F;
        let number_of_blocks = r.take(1)?[0];
        let rec_len_bytes = r.take(3)?;
        let rec_len =
            u32::from_le_bytes([rec_len_bytes[0], rec_len_bytes[1], rec_len_bytes[2], 0]) as usize;
        let measurement_record = r.take(rec_len)?;
        let nonce = r.take(SPDM_NONCE_LEN)?;
        let opaque_len = u16::from_le_bytes(r.take(2)?.try_into().map_err(|_| WireError)?);
        r.skip(opaque_len as usize)?;
        if has_requester_context {
            r.skip(REQUESTER_CONTEXT_LEN)?;
        }

        Ok(Self {
            total_number_of_measurement: total,
            slot_id,
            number_of_blocks,
            measurement_record,
            nonce,
            no_sig_prefix,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SpdmVersion;

    const NONCE: [u8; SPDM_NONCE_LEN] = [0xA5; SPDM_NONCE_LEN];
    const CTX: [u8; REQUESTER_CONTEXT_LEN] = [0xC0; REQUESTER_CONTEXT_LEN];
    const SIG: [u8; ECC_P384_SIGNATURE_SIZE] = [0x5A; ECC_P384_SIGNATURE_SIZE];

    // ---- constants -----------------------------------------------------------

    #[test]
    fn test_measurement_constants() {
        assert_eq!(MEAS_BLOCK_METADATA_SIZE, 7);
        assert_eq!(SPDM_MAX_MEASUREMENT_RECORD_SIZE, 0xFF_FFFF); // 2^24 - 1
        assert_eq!(MEAS_ATTR_SIGNATURE_REQUESTED, 0x01);
        assert_eq!(MEAS_ATTR_RAW_REQUESTED, 0x02);
        assert_eq!(MEAS_OP_ALL, 0xFF);
    }

    // ---- GET_MEASUREMENTS request --------------------------------------------

    #[test]
    fn test_get_measurements_req_unsigned_total_count() {
        let req = GetMeasurementsReq {
            attributes: 0,
            measurement_operation: 0x00, // total number of measurements only
            nonce: None,
            slot_id: 0,
            requester_context: None,
        };
        // Body = Attributes (1) + MeasurementOperation (1) = 2; wire = 2 + 2 = 4.
        assert_eq!(req.body_size(), 2);
        assert_eq!(req.encoded_size(), 4);
        let mut buf = [0xFFu8; 4];
        let mut w = WireWriter::new(&mut buf);
        req.encode_with_header(SpdmVersion::V12, &mut w).unwrap();
        assert_eq!(buf, [0x12, 0xE0, 0x00, 0x00]);
    }

    #[test]
    fn test_get_measurements_req_signed_raw_all_v12() {
        let req = GetMeasurementsReq {
            attributes: MEAS_ATTR_SIGNATURE_REQUESTED | MEAS_ATTR_RAW_REQUESTED,
            measurement_operation: MEAS_OP_ALL,
            nonce: Some(NONCE),
            slot_id: 2,
            requester_context: None,
        };
        // Body = 2 fixed + Nonce (32) + SlotID (1) = 35; wire = 2 + 35 = 37.
        assert_eq!(req.body_size(), 35);
        let mut buf = [0u8; 37];
        let mut w = WireWriter::new(&mut buf);
        req.encode_with_header(SpdmVersion::V12, &mut w).unwrap();
        assert_eq!(&buf[..4], &[0x12, 0xE0, 0x03, 0xFF]);
        assert_eq!(&buf[4..36], &NONCE);
        assert_eq!(buf[36], 0x02);
    }

    #[test]
    fn test_get_measurements_req_v13_context_and_slot_mask() {
        let req = GetMeasurementsReq {
            attributes: MEAS_ATTR_SIGNATURE_REQUESTED,
            measurement_operation: 0x01, // specific index
            nonce: Some(NONCE),
            slot_id: 0x1F, // only the low nibble is sent
            requester_context: Some(CTX),
        };
        // Body = 2 + 32 + 1 + RequesterContext (8) = 43; wire = 2 + 43 = 45.
        assert_eq!(req.body_size(), 43);
        let mut buf = [0u8; 45];
        let mut w = WireWriter::new(&mut buf);
        req.encode_with_header(SpdmVersion::V13, &mut w).unwrap();
        assert_eq!(&buf[..4], &[0x13, 0xE0, 0x01, 0x01]);
        assert_eq!(buf[36], 0x0F); // 0x1F & 0x0F
        assert_eq!(&buf[37..], &CTX);
    }

    #[test]
    fn test_get_measurements_req_operation_values() {
        // 0x00 = count, 0x01..=0xFE = index, 0xFF = all: the builder passes them
        // through unchanged.
        for op in [0x00u8, 0x01, 0x7F, 0xFE, 0xFF] {
            let req = GetMeasurementsReq {
                attributes: 0,
                measurement_operation: op,
                nonce: None,
                slot_id: 0,
                requester_context: None,
            };
            let mut buf = [0u8; 4];
            let mut w = WireWriter::new(&mut buf);
            req.encode_with_header(SpdmVersion::V12, &mut w).unwrap();
            assert_eq!(buf[3], op);
        }
    }

    #[test]
    fn test_get_measurements_req_does_not_couple_attributes_and_nonce() {
        // Pins leniency: the builder never ties attribute bit 0 to the presence of
        // the Nonce/SlotID fields, so the caller can build a request whose
        // attributes disagree with its length.
        // Signature requested but no nonce: 2-byte body.
        let no_nonce = GetMeasurementsReq {
            attributes: MEAS_ATTR_SIGNATURE_REQUESTED,
            measurement_operation: MEAS_OP_ALL,
            nonce: None,
            slot_id: 0,
            requester_context: None,
        };
        assert_eq!(no_nonce.body_size(), 2);

        // Nonce present but signature bit clear: 35-byte body.
        let stray_nonce = GetMeasurementsReq {
            attributes: 0,
            measurement_operation: MEAS_OP_ALL,
            nonce: Some(NONCE),
            slot_id: 0,
            requester_context: None,
        };
        assert_eq!(stray_nonce.body_size(), 35);
    }

    #[test]
    fn test_get_measurements_req_buffer_too_small() {
        let req = GetMeasurementsReq {
            attributes: MEAS_ATTR_SIGNATURE_REQUESTED,
            measurement_operation: MEAS_OP_ALL,
            nonce: Some(NONCE),
            slot_id: 0,
            requester_context: None,
        };
        // Needs 37 bytes; 36 fails on the SlotID byte.
        let mut buf = [0u8; 36];
        let mut w = WireWriter::new(&mut buf);
        assert!(req.encode_with_header(SpdmVersion::V12, &mut w).is_err());
    }

    #[test]
    fn test_get_measurements_req_body_attribute_bits() {
        for (attrs, sig, raw) in [
            (0x00u8, false, false),
            (0x01, true, false),
            (0x02, false, true),
            (0x03, true, true),
            (0xFC, false, false), // all other bits are ignored
        ] {
            let bytes = [attrs, 0xFF];
            let mut r = WireReader::new(&bytes);
            let body: &GetMeasurementsReqBody = r.read().unwrap();
            assert_eq!(body.signature_requested(), sig);
            assert_eq!(body.raw_bitstream_requested(), raw);
            assert_eq!(body.measurement_operation, 0xFF);
        }
        // Fixed prefix is 2 bytes; 1 is too short.
        assert!(WireReader::new(&[0x01])
            .read::<GetMeasurementsReqBody>()
            .is_err());
    }

    // ---- DmtfMeasurementBlockHeader ------------------------------------------

    #[test]
    fn test_block_header_digest_and_raw() {
        // Digest, index 1, value type 1, 48-byte SHA-384 value:
        //   MeasurementSize = 3 + 48 = 51 = 0x0033; value size 48 = 0x0030.
        let h = DmtfMeasurementBlockHeader::new(1, false, 0x01, 48).unwrap();
        assert_eq!(h.as_bytes(), &[0x01, 0x01, 0x33, 0x00, 0x01, 0x30, 0x00]);
        assert_eq!(h.as_bytes().len(), MEAS_BLOCK_METADATA_SIZE);

        // Raw bitstream sets bit 7 of the value type: 0x04 | 0x80 = 0x84.
        //   MeasurementSize = 3 + 32 = 35 = 0x0023; value size 32 = 0x0020.
        let raw = DmtfMeasurementBlockHeader::new(0xFE, true, 0x04, 32).unwrap();
        assert_eq!(raw.as_bytes(), &[0xFE, 0x01, 0x23, 0x00, 0x84, 0x20, 0x00]);
    }

    #[test]
    fn test_block_header_largest_value_without_overflow() {
        // 3 + 0xFFFC = 0xFFFF is the largest MeasurementSize that fits in 16 bits.
        let h = DmtfMeasurementBlockHeader::new(1, false, 0, 0xFFFC).unwrap();
        assert_eq!(h.measurement_size, [0xFF, 0xFF]);
        assert_eq!(h.value_size, [0xFC, 0xFF]);
    }

    #[test]
    fn test_block_header_value_len_overflow_is_rejected() {
        // MeasurementSize = 3 + value_len must fit 16 bits, so 0xFFFD is the first
        // value_len that is rejected (3 + 0xFFFD = 0x1_0000).
        assert!(DmtfMeasurementBlockHeader::new(1, false, 0, 0xFFFD).is_err());
        assert!(DmtfMeasurementBlockHeader::new(1, false, 0, 0xFFFF).is_err());
    }

    // ---- MEASUREMENTS response -----------------------------------------------

    #[test]
    fn test_measurements_rsp_signed_roundtrip() {
        // One digest block: 7-byte header + 48-byte value = 55-byte record.
        let mut record = [0x77u8; 55];
        record[..7].copy_from_slice(
            DmtfMeasurementBlockHeader::new(1, false, 0x01, 48)
                .unwrap()
                .as_bytes(),
        );

        let rsp = MeasurementsRsp {
            total_number_of_measurement: 5,
            slot_id: 3,
            content_changed: 2, // no change detected
            number_of_blocks: 1,
            measurement_record: &record,
            nonce: &NONCE,
            opaque_data: &[],
            requester_context: None,
            signature: &SIG,
        };
        // Body = param1 (1) + param2 (1) + blocks (1) + record len (3) + record (55)
        //      + nonce (32) + opaque len (2) + signature (96) = 191.
        assert_eq!(rsp.body_size(), 191);
        // Wire = 2 + 191 = 193 bytes.
        let mut buf = [0u8; 193];
        let mut w = WireWriter::new(&mut buf);
        rsp.encode_with_header(SpdmVersion::V12, &mut w).unwrap();

        // param2 = SlotID[3:0] | ContentChanged[5:4] = 0x03 | (2 << 4) = 0x23.
        // record length 55 = 0x37 as 3 bytes LE.
        assert_eq!(&buf[..8], &[0x12, 0x60, 0x05, 0x23, 0x01, 0x37, 0x00, 0x00]);
        assert_eq!(&buf[8..63], &record);
        assert_eq!(&buf[63..95], &NONCE);
        assert_eq!(&buf[95..97], &[0x00, 0x00]);
        assert_eq!(&buf[97..193], &SIG);

        let p = ParsedMeasurementsRsp::parse(&buf[2..], true, false).unwrap();
        assert_eq!(p.total_number_of_measurement, 5);
        assert_eq!(p.slot_id, 3);
        assert_eq!(p.number_of_blocks, 1);
        assert_eq!(p.measurement_record, &record);
        assert_eq!(p.nonce, &NONCE);
        // no_sig_prefix = 191 - 96 = 95 bytes.
        assert_eq!(p.no_sig_prefix.len(), 95);
        assert_eq!(p.signature, &SIG);
    }

    #[test]
    fn test_measurements_rsp_unsigned_v13_with_opaque_and_context() {
        // Operation 0 (count only): empty record, opaque data and context present.
        let rsp = MeasurementsRsp {
            total_number_of_measurement: 7,
            slot_id: 0,
            content_changed: 0,
            number_of_blocks: 0,
            measurement_record: &[],
            nonce: &NONCE,
            opaque_data: &[1, 2, 3, 4],
            requester_context: Some(&CTX),
            signature: &[],
        };
        // Body = 1 + 1 + 1 + 3 + 0 + 32 + 2 + 4 + 8 + 0 = 52; wire = 2 + 52 = 54.
        assert_eq!(rsp.body_size(), 52);
        let mut buf = [0u8; 54];
        let mut w = WireWriter::new(&mut buf);
        rsp.encode_with_header(SpdmVersion::V13, &mut w).unwrap();

        assert_eq!(&buf[..8], &[0x13, 0x60, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(&buf[8..40], &NONCE);
        assert_eq!(&buf[40..42], &[0x04, 0x00]); // opaque_len = 4
        assert_eq!(&buf[42..46], &[1, 2, 3, 4]);
        assert_eq!(&buf[46..54], &CTX);

        let p = ParsedMeasurementsRsp::parse(&buf[2..], false, true).unwrap();
        assert_eq!(p.total_number_of_measurement, 7);
        assert!(p.measurement_record.is_empty());
        assert!(p.signature.is_empty());
        assert_eq!(p.no_sig_prefix.len(), 52); // whole body when unsigned
    }

    #[test]
    fn test_measurements_rsp_param2_masks_slot_and_content_changed() {
        // Pins leniency: out-of-range slot_id / content_changed are masked, not
        // rejected. slot 0xFF -> 0x0F; content_changed 0x07 -> 0x03 << 4 = 0x30.
        let rsp = MeasurementsRsp {
            total_number_of_measurement: 0,
            slot_id: 0xFF,
            content_changed: 0x07,
            number_of_blocks: 0,
            measurement_record: &[],
            nonce: &NONCE,
            opaque_data: &[],
            requester_context: None,
            signature: &[],
        };
        let mut buf = [0u8; 2 + 40];
        let mut w = WireWriter::new(&mut buf);
        rsp.encode_with_header(SpdmVersion::V12, &mut w).unwrap();
        assert_eq!(buf[3], 0x3F);
    }

    #[test]
    fn test_measurements_rsp_record_length_uses_all_three_bytes() {
        // 65536 = 0x010000 needs the third length byte: 00 00 01.
        let record = [0xABu8; 0x1_0000];
        let rsp = MeasurementsRsp {
            total_number_of_measurement: 1,
            slot_id: 0,
            content_changed: 0,
            number_of_blocks: 1,
            measurement_record: &record,
            nonce: &NONCE,
            opaque_data: &[],
            requester_context: None,
            signature: &[],
        };
        // Body = 6 + 65536 + 32 + 2 = 65576; wire = 2 + 65576 = 65578.
        assert_eq!(rsp.body_size(), 65576);
        let mut buf = [0u8; 65578];
        let mut w = WireWriter::new(&mut buf);
        rsp.encode_with_header(SpdmVersion::V12, &mut w).unwrap();
        assert_eq!(&buf[5..8], &[0x00, 0x00, 0x01]);

        let p = ParsedMeasurementsRsp::parse(&buf[2..], false, false).unwrap();
        assert_eq!(p.measurement_record.len(), 0x1_0000);
        assert!(p.measurement_record.iter().all(|b| *b == 0xAB));
    }

    #[test]
    fn test_measurements_rsp_rejects_oversized_opaque_data() {
        // OpaqueLength is 16 bits, so 65536 bytes cannot be described. The buffer
        // is large enough to hold everything, so only the length check can fail.
        let opaque = [0u8; 0x1_0000];
        let rsp = MeasurementsRsp {
            total_number_of_measurement: 0,
            slot_id: 0,
            content_changed: 0,
            number_of_blocks: 0,
            measurement_record: &[],
            nonce: &NONCE,
            opaque_data: &opaque,
            requester_context: None,
            signature: &[],
        };
        // Needs 2 + 6 + 32 + 2 + 65536 = 65578; give 70000.
        let mut buf = [0u8; 70_000];
        let mut w = WireWriter::new(&mut buf);
        assert!(rsp.encode_with_header(SpdmVersion::V12, &mut w).is_err());
    }

    #[test]
    fn test_measurements_rsp_buffer_too_small() {
        let rsp = MeasurementsRsp {
            total_number_of_measurement: 0,
            slot_id: 0,
            content_changed: 0,
            number_of_blocks: 0,
            measurement_record: &[],
            nonce: &NONCE,
            opaque_data: &[],
            requester_context: None,
            signature: &SIG,
        };
        // Needs 2 + (6 + 32 + 2 + 96) = 138 bytes; 137 fails on the signature.
        let mut buf = [0u8; 137];
        let mut w = WireWriter::new(&mut buf);
        assert!(rsp.encode_with_header(SpdmVersion::V12, &mut w).is_err());
    }

    // ---- ParsedMeasurementsRsp::parse: malformed input -----------------------

    // Smallest valid unsigned body: param1 + param2 + blocks (3) + record len (3)
    // + nonce (32) + opaque len (2) = 40 bytes.
    fn minimal_body() -> [u8; 40] {
        let mut b = [0u8; 40];
        b[6..38].copy_from_slice(&NONCE);
        b
    }

    #[test]
    fn test_parse_measurements_rejects_short_bodies() {
        // Signed needs at least the 96-byte signature, and then the prefix too.
        assert!(ParsedMeasurementsRsp::parse(&[0u8; 95], true, false).is_err());
        assert!(ParsedMeasurementsRsp::parse(&[0u8; 96], true, false).is_err());
        // Unsigned: empty body, and a minimal body missing its last byte.
        assert!(ParsedMeasurementsRsp::parse(&[], false, false).is_err());
        let b = minimal_body();
        assert!(ParsedMeasurementsRsp::parse(&b[..39], false, false).is_err());
        assert!(ParsedMeasurementsRsp::parse(&b, false, false).is_ok());
    }

    #[test]
    fn test_parse_measurements_rejects_record_length_beyond_body() {
        // MeasurementRecordLength = 0xFFFFFF (16 MiB) in a 40-byte body.
        let mut b = minimal_body();
        b[3..6].copy_from_slice(&[0xFF, 0xFF, 0xFF]);
        assert!(ParsedMeasurementsRsp::parse(&b, false, false).is_err());
    }

    #[test]
    fn test_parse_measurements_rejects_oversized_opaque_len() {
        let mut b = minimal_body();
        b[38] = 0xFF;
        b[39] = 0xFF; // opaque_len = 65535 with no bytes following
        assert!(ParsedMeasurementsRsp::parse(&b, false, false).is_err());
    }

    #[test]
    fn test_parse_measurements_requires_context_when_expected() {
        // 40-byte body has no RequesterContext; expecting one overruns by 8.
        let b = minimal_body();
        assert!(ParsedMeasurementsRsp::parse(&b, false, true).is_err());
    }

    #[test]
    fn test_parse_measurements_accepts_trailing_bytes() {
        // Pins leniency: bytes after the expected fields (here 5 extra) are not
        // rejected, so a wrong `has_requester_context` flag can go unnoticed.
        let mut b = [0u8; 45];
        b[..40].copy_from_slice(&minimal_body());
        let p = ParsedMeasurementsRsp::parse(&b, false, false).unwrap();
        assert_eq!(p.no_sig_prefix.len(), 45);
    }

    #[test]
    fn test_parse_measurements_drops_content_changed_bits() {
        // Pins a gap: param2 carries ContentChanged[5:4] but the parsed struct has
        // no field for it, so the Requester cannot see it. 0x21 = changed, slot 1.
        let mut b = minimal_body();
        b[1] = 0x21;
        let p = ParsedMeasurementsRsp::parse(&b, false, false).unwrap();
        assert_eq!(p.slot_id, 1);
    }
}
