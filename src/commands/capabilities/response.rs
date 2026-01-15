// Licensed under the Apache-2.0 license
use super::*;
use crate::codec::{Codec, MessageBuf};
use crate::commands::error_rsp::ErrorCode;
use crate::context::SpdmContext;
use crate::error::{CommandError, CommandResult};
use crate::protocol::*;
use crate::state::ConnectionState;
use crate::transcript::TranscriptContext;

fn process_get_capabilities<'a>(
    ctx: &mut SpdmContext<'a>,
    spdm_hdr: SpdmMsgHdr,
    req_payload: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    let version = match spdm_hdr.version() {
        Ok(v) => v,
        Err(_) => {
            Err(ctx.generate_error_response(req_payload, ErrorCode::VersionMismatch, 0, None))?
        }
    };

    // Check if version is supported and set it
    let version = match ctx.supported_versions.iter().find(|&&v| v == version) {
        Some(&v) => {
            ctx.state.connection_info.set_version_number(v);
            v
        }
        None => Err(ctx.generate_error_response(req_payload, ErrorCode::VersionMismatch, 0, None))?,
    };

    let base_req = GetCapabilitiesBase::decode(req_payload).map_err(|_| {
        ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None)
    })?;

    // Reserved fields must be zero - or unexpected request error
    if base_req.param1 != 0 || base_req.param2 != 0 {
        Err(ctx.generate_error_response(req_payload, ErrorCode::UnexpectedRequest, 0, None))?;
    }

    if version > SpdmVersion::V10 {
        let mut max_spdm_msg_size = 0;
        let mut data_transfer_size = 0;

        let req_11 = GetCapabilitiesV11::decode(req_payload).map_err(|_| {
            ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None)
        })?;

        let flags = req_11.flags;
        if !req_flag_compatible(version, &flags) {
            Err(ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None))?;
        }

        if req_11.ct_exponent > MAX_CT_EXPONENT {
            Err(ctx.generate_error_response(req_payload, ErrorCode::UnexpectedRequest, 0, None))?;
        }

        if version >= SpdmVersion::V12 {
            let req_12 = GetCapabilitiesV12::decode(req_payload).map_err(|_| {
                ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None)
            })?;

            max_spdm_msg_size = req_12.max_spdm_msg_size;
            data_transfer_size = req_12.data_transfer_size;

            // Check data transfer size
            if data_transfer_size < MIN_DATA_TRANSFER_SIZE_V12
                || data_transfer_size > req_12.max_spdm_msg_size
            {
                Err(ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None))?;
            }

            // If no large message transfer supported, the data transfer size must be the same as
            // the max SPDM message size
            if flags.chunk_cap() == 0 && data_transfer_size != max_spdm_msg_size {
                Err(ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None))?;
            }

            // If the GET_CAPABILITIES request sets Bit 0 of Param1 to a value of 1 and the
            // Responder does not support the Large SPDM message transfer mechanism ( CHUNK_CAP=0 ),
            // the Responder shall send an ERROR message of ErrorCode=InvalidRequest
            if base_req.param1 & 0b00000001 != 0 && flags.chunk_cap() == 0 {
                Err(ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None))?;
            }
        }

        if version >= SpdmVersion::V11 {
            // Check ct_exponent
            if req_11.ct_exponent > MAX_CT_EXPONENT {
                Err(ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None))?;
            }
        }

        // Save the requester capabilities in the connection info
        let peer_capabilities = DeviceCapabilities {
            ct_exponent: req_11.ct_exponent,
            flags: req_11.flags,
            data_transfer_size,
            max_spdm_msg_size,
            include_supported_algorithms: (base_req.param1 & 0b00000100) != 0,
        };

        ctx.state
            .connection_info
            .set_peer_capabilities(peer_capabilities);
    }

    // Reset the transcript depending on request code
    ctx.reset_transcript_via_req_code(ReqRespCode::GetCapabilities);

    // Set the SPDM version in the transcript manager
    ctx.transcript_mgr
        .set_spdm_version(ctx.state.connection_info.version_number());

    // Append GET_CAPABILITIES to the transcript VCA context
    ctx.append_message_to_transcript(req_payload, TranscriptContext::Vca)
}

fn generate_capabilities_response<'a>(
    ctx: &mut SpdmContext<'a>,
    rsp_buf: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    let version = ctx.state.connection_info.version_number();
    let local_capabilities = ctx.local_capabilities;

    // Fill SPDM common header
    let spdm_resp_hdr = SpdmMsgHdr::new(version, ReqRespCode::Capabilities);
    let mut payload_len = spdm_resp_hdr
        .encode(rsp_buf)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    let rsp_common = GetCapabilitiesBase::default();
    payload_len += rsp_common
        .encode(rsp_buf)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    let rsp_11 = GetCapabilitiesV11::new(local_capabilities.ct_exponent, local_capabilities.flags);

    payload_len += rsp_11
        .encode(rsp_buf)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    if version >= SpdmVersion::V12 {
        let rsp_12 = GetCapabilitiesV12 {
            data_transfer_size: local_capabilities.data_transfer_size,
            max_spdm_msg_size: local_capabilities.max_spdm_msg_size,
        };

        payload_len += rsp_12
            .encode(rsp_buf)
            .map_err(|e| (false, CommandError::Codec(e)))?;
    }

    rsp_buf
        .push_data(payload_len)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    // Append CAPABILITIES to the transcript VCA context
    ctx.append_message_to_transcript(rsp_buf, TranscriptContext::Vca)
}

pub(crate) fn handle_get_capabilities<'a>(
    ctx: &mut SpdmContext<'a>,
    spdm_hdr: SpdmMsgHdr,
    req_payload: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    if ctx.state.connection_info.state() != ConnectionState::AfterVersion {
        Err(ctx.generate_error_response(req_payload, ErrorCode::UnexpectedRequest, 0, None))?;
    }

    // Process GET_CAPABILITIES request
    process_get_capabilities(ctx, spdm_hdr, req_payload)?;

    // Generate CAPABILITIES response
    ctx.prepare_response_buffer(req_payload)?;
    generate_capabilities_response(ctx, req_payload)?;

    // Set state to AfterCapabilities
    ctx.state
        .connection_info
        .set_state(ConnectionState::AfterCapabilities);
    Ok(())
}
