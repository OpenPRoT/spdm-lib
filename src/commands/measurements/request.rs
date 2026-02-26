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

use crate::{
    codec::{Codec, MessageBuf},
    commands::measurements::{
        GetMeasurementsReqAttr, GetMeasurementsReqCommon, GetMeasurementsReqSignature,
    },
    context::SpdmContext,
    error::{CommandError, CommandResult, PlatformError},
    protocol::{ReqRespCode, SpdmMsgHdr, SpdmVersion, NONCE_LEN},
    state::ConnectionState,
};

pub fn generate_get_measurements<'a>(
    ctx: &mut SpdmContext<'a>,
    req_buf: &mut MessageBuf<'a>,
    raw_bitstream_requested: bool,
    new_measurement_requested: bool,
    meas_op: u8,
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
    if slot_id.is_some() {
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
    let get_meas_common = GetMeasurementsReqCommon { req_attr, meas_op };
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

    ctx.append_message_to_transcript(req_buf, crate::transcript::TranscriptContext::L1)
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
