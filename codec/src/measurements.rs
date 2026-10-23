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
    pub fn new(index: u8, is_raw: bool, meas_value_type: u8, value_len: u16) -> Self {
        let meas_size = 3u16 + value_len; // value_type(1) + value_size(2) + value
        Self {
            index,
            measurement_specification: 0x01, // DMTF
            measurement_size: meas_size.to_le_bytes(),
            value_type: meas_value_type | (if is_raw { 0x80 } else { 0x00 }),
            value_size: value_len.to_le_bytes(),
        }
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
