// Licensed under the Apache-2.0 license

use crate::commands::error_rsp::ErrorCode;
use crate::{codec::MessageBuf, context::SpdmContext, error::CommandResult, protocol::SpdmMsgHdr};

use crate::commands::capabilities::{
    req_flag_compatible, CapabilityFlags, GetCapabilitiesBase, GetCapabilitiesV11,
    GetCapabilitiesV12,
};
use crate::protocol::{ReqRespCode, SpdmVersion};

use crate::error::{CommandError, SpdmError};
use crate::transcript::TranscriptContext;

use crate::codec::Codec;

/// Generate the GET_CAPABILITIES command with all the contexts information
// pub fn send_get_capabilities<'a>(
//     ctx: &mut SpdmContext<'a>,
//     req_buf: &mut MessageBuf<'a>,
//     payload:
// ) -> CommandResult<()> {
//     todo!();
// }

/// Requester function handling the parsing of the CAPABILITIES response sent by the Responder.
///
/// # Returns
/// - () on success
///
/// #TODO
/// - [ ] A Responder can report that it needs to transmit the response in smaller
/// transfers by sending an ERROR message of ErrorCode=LargeResponse
/// - [ ] Update the context with the negotiated capabilities? Or where should we store them?
pub(crate) fn handle_capabilities_response<'a>(
    ctx: &mut SpdmContext<'a>,
    resp_header: SpdmMsgHdr,
    resp: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    let version_hdr = match resp_header.version() {
        Ok(v) => v,
        Err(_) => Err(ctx.generate_error_response(resp, ErrorCode::VersionMismatch, 0, None))?,
    };

    // Verify that the version is supported by both parties
    let version = match ctx.supported_versions.iter().find(|&&v| v == version_hdr) {
        Some(&v) => v,
        None => Err(ctx.generate_error_response(resp, ErrorCode::VersionMismatch, 0, None))?,
    };

    let base_resp = GetCapabilitiesBase::decode(resp)
        .map_err(|_| ctx.generate_error_response(resp, ErrorCode::OperationFailed, 0, None))?;

    // Based on the negotiated version, try to decode the rest of the response.
    // If the response misses expected fields, return an error.
    // See src/commands/capabilities/response.rs for more details.

    if version > SpdmVersion::V10 {
        let resp_11 = GetCapabilitiesV11::decode(resp)
            .map_err(|_| ctx.generate_error_response(resp, ErrorCode::InvalidRequest, 0, None))?;

        let flags = resp_11.flags;
        if !req_flag_compatible(version, &flags) {
            Err(ctx.generate_error_response(resp, ErrorCode::InvalidRequest, 0, None))?;
        }

        if version >= SpdmVersion::V12 {
            let _resp_12 = GetCapabilitiesV12::decode(resp).map_err(|_| {
                ctx.generate_error_response(resp, ErrorCode::InvalidRequest, 0, None)
            })?;
        }
    }

    Ok(())
}

/// Generate the GET_CAPABILITIES command with all the contexts information.
///
/// # Arguments
/// - `ctx`: The SPDM context
/// - `req_buf`: The buffer to write the request into
/// - `capabilities`: The base capabilities
/// - `capv11`: The V1.1 capabilities (if applicable)
/// - `capv12`: The V1.2 capabilities (if applicable)
///
/// # Returns
/// - () on success
/// - [CommandError::BufferTooSmall] when the provided buffer is too small
///
fn generate_capabilities_request<'a>(
    ctx: &mut SpdmContext<'a>,
    req_buf: &mut MessageBuf<'a>,
    capabilities: GetCapabilitiesBase,
    capv11: Option<GetCapabilitiesV11>,
    capv12: Option<GetCapabilitiesV12>,
) -> CommandResult<()> {
    // Fill SpdmHeader first
    let ctx_version = ctx.state.connection_info.version_number();
    let spdm_req_hdr = SpdmMsgHdr::new(ctx_version, ReqRespCode::GetCapabilities);
    let mut payload_len = spdm_req_hdr
        .encode(req_buf)
        .map_err(|_| (false, CommandError::BufferTooSmall))?;

    let req_common = capabilities;
    payload_len += req_common
        .encode(req_buf)
        .map_err(|_| (false, CommandError::BufferTooSmall))?;

    // Ensure that only the appropriate capability fields based on version are included.
    if ctx_version >= SpdmVersion::V11 {
        if let Some(capv1) = &capv11 {
            payload_len += capv1
                .encode(req_buf)
                .map_err(|_| (false, CommandError::BufferTooSmall))?;
        }
    }

    if ctx_version >= SpdmVersion::V12 {
        // Versions 1.2 and higher include GetCapabilitiesV12
        if let Some(capv2) = &capv12 {
            payload_len += capv2
                .encode(req_buf)
                .map_err(|_| (false, CommandError::BufferTooSmall))?;
        }
    }

    // Push data offset up by total payload length
    req_buf
        .push_data(payload_len)
        .map_err(|_| (false, CommandError::BufferTooSmall))?;

    // Append response to VCA transcript
    ctx.append_message_to_transcript(req_buf, TranscriptContext::Vca)
}

/// Generate the GET_CAPABILITIES command using the local capabilities from the context.
/// # Arguments
/// - `ctx`: The SPDM context
/// - `req_buf`: The buffer to write the request into
/// # Returns
/// - () on success
/// - [CommandError::BufferTooSmall] when the provided buffer is too small
pub fn generate_capabilities_request_local<'a>(
    ctx: &mut SpdmContext<'a>,
    req_buf: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    let local_capabilities = ctx.local_capabilities;
    let capabilities = GetCapabilitiesBase::default();

    let capv11 = Some(GetCapabilitiesV11::new(
        local_capabilities.ct_exponent,
        local_capabilities.flags,
    ));

    let capv12 = if ctx.state.connection_info.version_number() >= SpdmVersion::V12 {
        Some(GetCapabilitiesV12 {
            data_transfer_size: local_capabilities.data_transfer_size,
            max_spdm_msg_size: local_capabilities.max_spdm_msg_size,
        })
    } else {
        None
    };

    generate_capabilities_request(ctx, req_buf, capabilities, capv11, capv12)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore]
    fn test_generate_capabilities_request() {
        todo!();
    }
}
