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

use zerocopy::FromBytes;

use crate::{
    codec::{Codec, MessageBuf},
    commands::measurements::{
        ContentChanged, GetMeasurementsReqAttr, GetMeasurementsReqCommon,
        GetMeasurementsReqSignature, MeasurementBlockHeader, MeasurementOperation,
        MeasurementsRspFixed, RESPONSE_FIXED_FIELDS_SIZE,
    },
    context::SpdmContext,
    error::{CommandError, CommandResult, PlatformError},
    protocol::{MeasurementSpecificationType, ReqRespCode, SpdmMsgHdr, SpdmVersion, NONCE_LEN},
    state::ConnectionState,
    transcript::TranscriptContext,
};

#[derive(Debug)]
pub struct Measurement<'a> {
    pub index: u8,
    pub measurement_spec: MeasurementSpecificationType,
    pub measurement: &'a [u8],
}

/// Parsed MEASUREMENTS response
#[derive(Debug)]
pub struct Measurements<'a> {
    /// Fixed fields
    fixed_fields: &'a MeasurementsRspFixed<[u8; RESPONSE_FIXED_FIELDS_SIZE]>,
    /// Measurement blocks
    measurements: &'a [u8],
    /// 32-byte Nonce
    pub nonce: &'a [u8],
    /// Opaque data
    pub opaque_data: &'a [u8],
    /// Requester context
    pub requester_ctx: Option<&'a [u8]>,
    /// Optional Signature
    ///
    /// _Note_: The length of the signature isn't checked for validity.
    pub signature: Option<&'a [u8]>,
}

/// Generate a GET_MEASUREMENTS request
///
/// # Arguments
/// * `ctx`: The SPDM context
/// * `req_buf`: Buffer to write the request into
/// * `raw_bitstream_requested`: Request a raw bit stream (if supported) (SPDM v1.2+)
/// * `new_measurement_requested`: Request new measurement if the responder has pending updates to blocks (SPDM v1.3+)
/// * `meas_op`: Measurement operation
/// * `slot_id`: Request a signed measurement if provided, signed with certificate slot identifier (0-7)
/// * `context`: Append optional 8 byte context (SPDM v1.3+)
///
/// ## Note
/// For SPDM version 1.0 this implementation does **not** supporte signed measurements.
///
/// # Returns
/// - () on success
/// - [CommandError] on failure
///
/// # Connection State Requirements
/// - Connection state must be >= AlgorithmsNegotiated
///
/// # Transcript
/// - Resets M1/M2 message transcript
/// - Appends request to the L1 transcript context
pub fn generate_get_measurements<'a>(
    ctx: &mut SpdmContext<'a>,
    req_buf: &mut MessageBuf<'a>,
    raw_bitstream_requested: bool,
    new_measurement_requested: bool,
    meas_op: MeasurementOperation,
    slot_id: Option<u8>,
    context: Option<&[u8; 8]>,
) -> CommandResult<()> {
    // Validate connection state - algorithms must be negotiated first
    if ctx.state.connection_info.state() < ConnectionState::AlgorithmsNegotiated {
        return Err((true, CommandError::UnsupportedRequest));
    }

    // TODO: maybe add a check if measuements are supported by the responder

    // Get connection version
    let connection_version = ctx.state.connection_info.version_number();

    // Create and encode SPDM message header
    let spdm_hdr = SpdmMsgHdr::new(connection_version, ReqRespCode::GetMeasurements);
    let mut payload_len = spdm_hdr
        .encode(req_buf)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    let mut req_attr = GetMeasurementsReqAttr(0);

    // signature requested is available in all versions
    // (v1.0 doesn't support slot-ids)
    if slot_id.is_some() {
        if connection_version == SpdmVersion::V10 {
            return Err((true, CommandError::UnsupportedRequest));
        }
        // Error if the responder doesn't support this
        if !responder_supports_signed_measurements(ctx) {
            return Err((true, CommandError::UnsupportedRequest));
        }
        req_attr.set_signature_requested(1);
    }

    if raw_bitstream_requested {
        if connection_version < SpdmVersion::V12 {
            return Err((true, CommandError::UnsupportedRequest));
        }
        // TODO Check measuement block spec
        req_attr.set_raw_bitstream_requested(1);
    }

    if new_measurement_requested {
        if connection_version < SpdmVersion::V13 {
            return Err((true, CommandError::UnsupportedRequest));
        }
        req_attr.set_new_measurement_requested(1);
    }

    // Encode request attributes and `Measurement` operation
    let get_meas_common = GetMeasurementsReqCommon {
        req_attr,
        meas_op: meas_op.try_into().map_err(|e| (true, e))?,
    };
    payload_len += get_meas_common
        .encode(req_buf)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    // Generate Nonce if signature was requested
    if let Some(id) = slot_id {
        let mut nonce = [0; NONCE_LEN];
        ctx.rng
            .get_random_bytes(&mut nonce)
            .map_err(|e| (true, PlatformError::from(e).into()))?;

        if connection_version < SpdmVersion::V11 {
            todo!("Implement encoding of nonce only for v1.0");
        } else {
            let get_meas_sig = GetMeasurementsReqSignature {
                requester_nonce: nonce,
                slot_id: id,
            };
            payload_len += get_meas_sig
                .encode(req_buf)
                .map_err(|e| (false, CommandError::Codec(e)))?;
        }
    }

    // encode context data if spdm version is >= v1.3
    if connection_version >= SpdmVersion::V13 {
        if let Some(context) = context {
            payload_len +=
                crate::codec::encode_u8_slice(context, req_buf).map_err(|e| (true, e.into()))?;
        } else {
            payload_len +=
                crate::codec::encode_u8_slice(&[0; 8], req_buf).map_err(|e| (true, e.into()))?;
        }
    }

    // Finalize message by pushing total payload length
    req_buf
        .push_data(payload_len)
        .map_err(|_| (false, CommandError::BufferTooSmall))?;

    ctx.transcript_mgr.reset_context(TranscriptContext::M1);
    ctx.append_message_to_transcript(req_buf, TranscriptContext::L1)
}

/// Check if the responder supports signing its measurements
///
/// Currently only the `MEAS_CAP` is checked.
/// Checking `BaseAsymSel` and `ExtAsymSelCount` might need to checked,
/// to determine if a signed measurement can be requested.
/// (The Spec is a bit fuzzy about that.)
fn responder_supports_signed_measurements(ctx: &SpdmContext<'_>) -> bool {
    let flags = &ctx.state.connection_info.peer_capabilities().flags;
    // 0b00 no measurements support
    // 0b01 measurements support without signing
    // 0b10 measurements with signing supported
    // 0b11 reserved
    if flags.meas_cap() == 0b10 {
        return true;
    } else {
        return false;
    }
}

/// Handle an incoming MEASUREMENTS response
pub(crate) fn handle_measurements_response<'a>(
    ctx: &mut SpdmContext<'a>,
    resp_header: SpdmMsgHdr,
    resp: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    // Validate connection state - algorithms must be negotiated
    if ctx.state.connection_info.state() < ConnectionState::AlgorithmsNegotiated {
        return Err((true, CommandError::UnsupportedResponse));
    }

    // Validate version matches connection version
    let connection_version = ctx.state.connection_info.version_number();
    if resp_header.version().ok() != Some(connection_version) {
        return Err((true, CommandError::InvalidResponse));
    }

    // Include the already parsed header again to parse `MeasurementsRspFixed`
    resp.push_data(size_of::<SpdmMsgHdr>())
        .map_err(|e| (false, e.into()))?;

    let fixed_fields = MeasurementsRspFixed::decode(resp).map_err(|e| (true, e.into()))?;

    // Convert 3-byte measurement record length to u32
    let _meas_record_length = u32::from_le_bytes([
        fixed_fields.measurement_record_len_byte0(),
        fixed_fields.measurement_record_len_byte1(),
        fixed_fields.measurement_record_len_byte2(),
        0,
    ]);

    // Decode all measurement blocks
    for _ in 0..fixed_fields.num_blocks() {
        let block_header = MeasurementBlockHeader::decode(resp).map_err(|e| (true, e.into()))?;
        resp.pull_data(block_header.measurement_size.get() as usize)
            .map_err(|e| (true, e.into()))?;
    }

    // Decode Nonce
    let _nonce = resp.data(32).map_err(|e| (true, e.into()))?;
    resp.pull_data(32).map_err(|e| (true, e.into()))?;

    // Decode opaque data
    let mut len_bytes = [0; 2];
    len_bytes.copy_from_slice(resp.data(2).map_err(|e| (true, e.into()))?);
    let opaque_data_len = u16::from_le_bytes(len_bytes);
    resp.pull_data(2).map_err(|e| (true, e.into()))?;
    resp.pull_data(opaque_data_len as usize)
        .map_err(|e| (true, e.into()))?;

    if connection_version >= SpdmVersion::V13 {
        // Decode requester context
        let _requester_ctx = resp.data(8).map_err(|e| (true, e.into()))?;
        resp.pull_data(8).map_err(|e| (true, e.into()))?;
    }

    // Remaining is the signature, if requested by the GET_MEASUREMENTS request

    // Append response to transcript (L1 context for measurements)
    // We have to use this ugly hack to bring the message buffer into the right form to exclude the signature.
    let tail = resp.data_len();
    resp.trim(0).map_err(|e| (true, CommandError::Codec(e)))?;
    // Append the entire message (excluding the signature) to the transcript before signature verification, as required by SPDM 1.2 and later.
    ctx.append_message_to_transcript(resp, TranscriptContext::L1)?;
    resp.put_data(tail)
        .map_err(|e| (true, CommandError::Codec(e)))?;

    Ok(())
}

/// Parse a successfull measurements response
///
/// _Note:_ The caller has to ensure that `resp` is a valid MEASUREMENTS response.
/// Returns `None` if parsing fails.
pub fn parse_measurements_response<'a>(resp: &'a [u8]) -> Option<Measurements<'a>> {
    let (fixed_fields, rest) =
        MeasurementsRspFixed::<[u8; RESPONSE_FIXED_FIELDS_SIZE]>::ref_from_prefix(resp).ok()?;

    let connection_version: SpdmVersion = fixed_fields.spdm_version().try_into().ok()?;
    // Convert 3-byte measurement record length to u32
    let meas_record_length = u32::from_le_bytes([
        fixed_fields.measurement_record_len_byte0(),
        fixed_fields.measurement_record_len_byte1(),
        fixed_fields.measurement_record_len_byte2(),
        0,
    ]) as usize;

    // Get measurement blocks
    if meas_record_length > rest.len() {
        return None;
    }
    let (measurements, rest) = rest.split_at(meas_record_length);

    // Decode Nonce
    if rest.len() < 32 {
        return None;
    }
    let (nonce, rest) = rest.split_at(32);

    // Decode opaque data
    let (opaque_data, rest) = decode_opaque_data(rest)?;

    let (requester_ctx, rest) = if connection_version >= SpdmVersion::V13 {
        // Decode requester context
        let requester_ctx = rest.get(..8)?;
        let rest = rest.get(8..)?;
        (Some(requester_ctx), rest)
    } else {
        (None, rest)
    };

    // Remaining is the signature, if requested by the GET_MEASUREMENTS request
    let signature = if !rest.is_empty() { Some(rest) } else { None };

    Some(Measurements {
        fixed_fields,
        measurements,
        nonce,
        opaque_data,
        requester_ctx,
        signature,
    })
}

/// Decode the opaque data
///
/// # Arguments
/// - `buf`: buffer containing 2-byte length and following opaque data
///
/// # Returns
/// - `Some((opaque_data, rest))` on success
/// - `None` if `buf` is to small to hold the opaque data
fn decode_opaque_data<'a>(buf: &'a [u8]) -> Option<(&'a [u8], &'a [u8])> {
    if buf.len() < 2 {
        return None;
    }
    let mut opaque_data_len = [0; 2];
    opaque_data_len.copy_from_slice(&buf[..2]);
    let opaque_data_len = u16::from_le_bytes(opaque_data_len) as usize;

    let rest = buf.get(2..)?;

    let data = rest.get(..opaque_data_len)?;
    let rest = rest.get(opaque_data_len..)?;

    Some((data, rest))
}

impl<'a> Measurements<'a> {
    /// The certificate slot used to sign the measurements
    ///
    /// Returns the slot number of the certificate chain
    /// specified in the GET_MEASUREMENTS request,
    /// or 0xF if the Responder's public key was provisioned
    /// to the Requester previously.
    pub fn slot_id(&self) -> u8 {
        self.fixed_fields.slot_id()
    }

    /// The total number of measurment blocks in this response
    ///
    /// _Note:_ This returns the number of blocks reported by the response header,
    ///         it is not guranteed at this point, that the response actually contains them.
    pub fn total_measurement_blocks(&self) -> u8 {
        self.fixed_fields.num_blocks()
    }

    /// If this message contains a signature, this field shall indicate
    /// if one or more MeasurementRecord fields of previous MEASUREMENTS
    /// responses in the same measurement log have changed.
    pub fn content_changed(&self) -> ContentChanged {
        self.fixed_fields.content_changed().into()
    }

    /// Returns an iterator over the measurements.
    pub fn iter(&self) -> MeasurementIterator<'a> {
        MeasurementIterator {
            measurements: self.measurements,
            pos: 0,
        }
    }
}

impl<'a> IntoIterator for Measurements<'a> {
    type Item = Measurement<'a>;

    type IntoIter = MeasurementIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        MeasurementIterator {
            measurements: self.measurements,
            pos: 0,
        }
    }
}

pub struct MeasurementIterator<'a> {
    measurements: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for MeasurementIterator<'a> {
    type Item = Measurement<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let (header, rest) =
            MeasurementBlockHeader::ref_from_prefix(self.measurements.get(self.pos..)?).ok()?;

        let measurement = rest.get(..header.measurement_size.get() as usize)?;
        self.pos += size_of::<MeasurementBlockHeader>() + header.measurement_size.get() as usize;
        Some(Measurement {
            index: header.index,
            measurement_spec: header.measurement_spec.try_into().ok()?,
            measurement,
        })
    }
}
