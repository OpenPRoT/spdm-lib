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

use crate::cert_store::cert_slot_mask;
use crate::codec::{Codec, MessageBuf};
use crate::commands::error_rsp::ErrorCode;
use crate::context::SpdmContext;
use crate::error::{CommandError, CommandResult};
use crate::state::ConnectionState;
use crate::transcript::TranscriptContext;

use super::*;

pub(crate) fn generate_digests_response<'a>(
    ctx: &mut SpdmContext<'a>,
    rsp: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    // Ensure the selected hash algorithm is SHA384 and retrieve the asymmetric algorithm (currently only ECC-P384 is supported)
    ctx.verify_selected_hash_algo()
        .map_err(|_| ctx.generate_error_response(rsp, ErrorCode::Unspecified, 0, None))?;
    let asym_algo = ctx
        .selected_base_asym_algo()
        .map_err(|_| ctx.generate_error_response(rsp, ErrorCode::Unspecified, 0, None))?;

    // Get the supported and provisioned slot masks.
    let (supported_slot_mask, provisioned_slot_mask) = cert_slot_mask(ctx.device_certs_store);

    // No slots provisioned with certificates
    let slot_cnt = provisioned_slot_mask.count_ones() as usize;
    if slot_cnt == 0 {
        Err(ctx.generate_error_response(rsp, ErrorCode::Unspecified, 0, None))?;
    }

    let connection_version = ctx.state.connection_info.version_number();

    // Start filling the response payload
    let spdm_resp_hdr = SpdmMsgHdr::new(connection_version, ReqRespCode::Digests);
    let mut payload_len = spdm_resp_hdr
        .encode(rsp)
        .map_err(|_| (false, CommandError::BufferTooSmall))?;

    // Fill the response header with param1 and param2
    let dgst_rsp_common = GetDigestsRespCommon {
        supported_slot_mask,
        provisioned_slot_mask,
    };

    payload_len += dgst_rsp_common
        .encode(rsp)
        .map_err(|_| (false, CommandError::BufferTooSmall))?;

    // Encode the certificate chain digests for each provisioned slot
    for slot_id in 0..slot_cnt {
        payload_len += encode_cert_chain_digest(
            ctx.hash,
            slot_id as u8,
            ctx.device_certs_store,
            asym_algo,
            rsp,
        )
        .map_err(|_| ctx.generate_error_response(rsp, ErrorCode::Unspecified, 0, None))?;
    }

    // Fill the multi-key connection response data if applicable
    if connection_version >= SpdmVersion::V13 && ctx.state.connection_info.multi_key_conn_rsp() {
        payload_len += encode_multi_key_conn_rsp_data(ctx, provisioned_slot_mask, rsp)?;
    }

    // Push data offset up by total payload length
    rsp.push_data(payload_len)
        .map_err(|_| (false, CommandError::BufferTooSmall))?;

    // Append the response message to the M1 transcript
    ctx.append_message_to_transcript(rsp, TranscriptContext::M1)
}

fn process_get_digests<'a>(
    ctx: &mut SpdmContext<'a>,
    spdm_hdr: SpdmMsgHdr,
    req_payload: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    // Validate the version
    let connection_version = ctx.state.connection_info.version_number();
    match spdm_hdr.version() {
        Ok(version) if version == connection_version => {}
        _ => Err(ctx.generate_error_response(req_payload, ErrorCode::VersionMismatch, 0, None))?,
    }

    let req = GetDigestsReq::decode(req_payload).map_err(|_| {
        ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None)
    })?;

    // Reserved fields must be zero - or unexpected request error
    if req.param1 != 0 || req.param2 != 0 {
        Err(ctx.generate_error_response(req_payload, ErrorCode::UnexpectedRequest, 0, None))?;
    }

    // Reset the transcript manager
    ctx.reset_transcript_via_req_code(ReqRespCode::GetDigests);

    // Append the request message to the M1 transcript
    ctx.append_message_to_transcript(req_payload, TranscriptContext::M1)
}

pub(crate) fn handle_get_digests<'a>(
    ctx: &mut SpdmContext<'a>,
    spdm_hdr: SpdmMsgHdr,
    req_payload: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    // Validate the connection state
    if ctx.state.connection_info.state() < ConnectionState::AlgorithmsNegotiated {
        Err(ctx.generate_error_response(req_payload, ErrorCode::UnexpectedRequest, 0, None))?;
    }

    // Check if the certificate capability is supported
    if ctx.local_capabilities.flags.cert_cap() == 0 {
        Err(ctx.generate_error_response(req_payload, ErrorCode::UnsupportedRequest, 0, None))?;
    }

    // Process GET_DIGESTS request
    process_get_digests(ctx, spdm_hdr, req_payload)?;

    // Generate DIGESTS response
    ctx.prepare_response_buffer(req_payload)?;
    generate_digests_response(ctx, req_payload)?;

    if ctx.state.connection_info.state() < ConnectionState::AfterDigest {
        ctx.state
            .connection_info
            .set_state(ConnectionState::AfterDigest);
    }

    Ok(())
}
