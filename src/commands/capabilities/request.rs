// Licensed under the Apache-2.0 license

use crate::commands::error_rsp::ErrorCode;
use crate::{codec::MessageBuf, context::SpdmContext, error::CommandResult, protocol::SpdmMsgHdr};

use crate::commands::capabilities::{GetCapabilitiesBase, GetCapabilitiesV11, GetCapabilitiesV12};
use crate::protocol::{capabilities::DeviceCapabilities, ReqRespCode, SpdmVersion};

use crate::error::CommandError;
use crate::transcript::TranscriptContext;

use crate::codec::Codec;

/// Requester function handling the parsing of the CAPABILITIES response sent by the Responder.
///
/// # Returns
/// - () on success
///
/// #TODO
/// - [ ] A Responder can report that it needs to transmit the response in smaller
///   transfers by sending an ERROR message of ErrorCode=LargeResponse
pub(crate) fn handle_capabilities_response<'a>(
    ctx: &mut SpdmContext<'a>,
    resp_header: SpdmMsgHdr,
    resp: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    // TODO: I don't think we should call _generate_error_response_ here for every error.
    //       Instead just returning proper error codes is probably better.

    let version_hdr = match resp_header.version() {
        Ok(v) => v,
        Err(_) => Err(ctx.generate_error_response(resp, ErrorCode::VersionMismatch, 0, None))?,
    };

    // Verify that the version is supported by both parties
    // TODO: Should responses that don't match the negotiated version be silently accepted?
    let version = match ctx.supported_versions.iter().find(|&&v| v == version_hdr) {
        Some(&v) => v,
        None => Err(ctx.generate_error_response(resp, ErrorCode::VersionMismatch, 0, None))?,
    };

    let _base_resp = GetCapabilitiesBase::decode(resp)
        .map_err(|_| ctx.generate_error_response(resp, ErrorCode::OperationFailed, 0, None))?;

    // Based on the negotiated version, try to decode the rest of the response.
    // If the response misses expected fields, return an error.
    // See src/commands/capabilities/response.rs for more details.

    let mut peer_capabilities = DeviceCapabilities::default();

    if version > SpdmVersion::V10 {
        let resp_11 = GetCapabilitiesV11::decode(resp)
            .map_err(|_| ctx.generate_error_response(resp, ErrorCode::InvalidRequest, 0, None))?;
        peer_capabilities.ct_exponent = resp_11.ct_exponent;

        // TODO?
        let _flags = resp_11.flags;
        // THIS FAILS
        // if !req_flag_compatible(version, &flags) {
        //     Err(ctx.generate_error_response(resp, ErrorCode::InvalidPolicy, 0, None))?;
        // }
        peer_capabilities.flags = resp_11.flags;

        if version >= SpdmVersion::V12 {
            let resp_12 = GetCapabilitiesV12::decode(resp).map_err(|_| {
                ctx.generate_error_response(resp, ErrorCode::InvalidRequest, 0, None)
            })?;

            // _DataTransferSize_ shall be equal to or greater than _MinDataTransferSize_
            if resp_12.data_transfer_size < crate::protocol::MIN_DATA_TRANSFER_SIZE_V12 {
                return Err((false, CommandError::InvalidResponse));
            }

            // _MaxSPDMmsgSize_ should be greater than or equal to _DataTransferSize_
            if resp_12.max_spdm_msg_size < resp_12.data_transfer_size {
                return Err((false, CommandError::InvalidResponse));
            }

            peer_capabilities.data_transfer_size = resp_12.data_transfer_size;
            peer_capabilities.max_spdm_msg_size = resp_12.max_spdm_msg_size;
        }
    }

    ctx.state
        .connection_info
        .set_peer_capabilities(peer_capabilities);

    ctx.state
        .connection_info
        .set_state(crate::state::ConnectionState::AfterCapabilities);

    ctx.append_message_to_transcript(resp, TranscriptContext::Vca)
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
    let mut capabilities = GetCapabilitiesBase::default();

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

    if ctx.state.connection_info.version_number() >= SpdmVersion::V13 {
        capabilities.param1 |= (local_capabilities.include_supported_algorithms as u8) << 2;
    }

    generate_capabilities_request(ctx, req_buf, capabilities, capv11, capv12)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        protocol::{CapabilityFlags, MAX_MCTP_SPDM_MSG_SIZE},
        test::*,
    };

    #[test]
    fn test_handle_capabilities_response_happy_path() {
        let versions = versions_default();
        let mut stack = MockResources::new();
        let algorithms = crate::protocol::LocalDeviceAlgorithms::default();
        let mut context = create_context(&mut stack, &versions, algorithms);

        context
            .state
            .connection_info
            .set_version_number(SpdmVersion::V12);
        context
            .state
            .connection_info
            .set_state(crate::state::ConnectionState::AfterVersion);

        let header = SpdmMsgHdr::new(SpdmVersion::V12, crate::protocol::ReqRespCode::Capabilities);

        let mut msg_buf = [0; MAX_MCTP_SPDM_MSG_SIZE];
        let mut msg = MessageBuf::new(&mut msg_buf);
        let mut len = 0;
        let cap_base = GetCapabilitiesBase::default();
        len += cap_base.encode(&mut msg).unwrap();
        let cap_11 = GetCapabilitiesV11::new(10, CapabilityFlags::default());
        len += cap_11.encode(&mut msg).unwrap();
        let cap_12 = GetCapabilitiesV12 {
            data_transfer_size: crate::protocol::MIN_DATA_TRANSFER_SIZE_V12,
            max_spdm_msg_size: crate::protocol::MIN_DATA_TRANSFER_SIZE_V12,
        };
        len += cap_12.encode(&mut msg).unwrap();
        msg.push_data(len).unwrap();

        handle_capabilities_response(&mut context, header, &mut msg)
            .expect("Failed to handle capabilities response");
    }

    #[test]
    fn test_handle_capabilities_response_error_cases() {
        let versions = versions_default();
        let mut stack = MockResources::new();
        let algorithms = crate::protocol::LocalDeviceAlgorithms::default();
        let mut context = create_context(&mut stack, &versions, algorithms);

        context
            .state
            .connection_info
            .set_version_number(SpdmVersion::V13);
        context
            .state
            .connection_info
            .set_state(crate::state::ConnectionState::AfterVersion);

        let header = SpdmMsgHdr::new(SpdmVersion::V13, crate::protocol::ReqRespCode::Capabilities);

        // Encode invalid MEAS_CAP flag
        let mut msg_buf = [0; MAX_MCTP_SPDM_MSG_SIZE];
        let cap_base = GetCapabilitiesBase::default();
        let mut cap_flags = CapabilityFlags::default();
        cap_flags.set_meas_cap(0b11); // 0x11 is reserved
        let cap_12 = GetCapabilitiesV12::default();
        let mut msg = prepare_response(&mut msg_buf, cap_base, cap_flags, 10, cap_12);

        let res = handle_capabilities_response(&mut context, header.clone(), &mut msg);
        if let Err((_, e)) = res {
            assert_eq!(
                e,
                CommandError::ErrorCode(ErrorCode::InvalidPolicy),
                "Expected invalid policy error, got {e:?}"
            );
        } else {
            panic!("Expected invalid policy error, got OK(())")
        }

        // Test invalid v1.2 fields
        let mut msg_buf = [0; MAX_MCTP_SPDM_MSG_SIZE];
        let cap_base = GetCapabilitiesBase::default();
        let cap_flags = CapabilityFlags::default();
        let cap_12 = GetCapabilitiesV12 {
            data_transfer_size: crate::protocol::MIN_DATA_TRANSFER_SIZE_V12 - 1,
            max_spdm_msg_size: crate::protocol::MIN_DATA_TRANSFER_SIZE_V12,
        };
        let mut msg = prepare_response(&mut msg_buf, cap_base, cap_flags, 10, cap_12);

        let res = handle_capabilities_response(&mut context, header.clone(), &mut msg);
        if let Err((_, e)) = res {
            assert_eq!(
                e,
                CommandError::InvalidResponse,
                "Expected invalid response error, got {e:?}"
            );
        } else {
            panic!("Expected invalid response error, got OK(())")
        }

        let mut msg_buf = [0; MAX_MCTP_SPDM_MSG_SIZE];
        let cap_base = GetCapabilitiesBase::default();
        let cap_flags = CapabilityFlags::default();
        let cap_12 = GetCapabilitiesV12 {
            data_transfer_size: crate::protocol::MIN_DATA_TRANSFER_SIZE_V12,
            max_spdm_msg_size: crate::protocol::MIN_DATA_TRANSFER_SIZE_V12 - 1,
        };
        let mut msg = prepare_response(&mut msg_buf, cap_base, cap_flags, 10, cap_12);

        let res = handle_capabilities_response(&mut context, header, &mut msg);
        if let Err((_, e)) = res {
            assert_eq!(
                e,
                CommandError::InvalidResponse,
                "Expected invalid response error, got {e:?}"
            );
        } else {
            panic!("Expected invalid response error, got OK(())")
        }
    }

    fn prepare_response<'a>(
        buf: &'a mut [u8],
        cap_base: GetCapabilitiesBase,
        cap_flags: CapabilityFlags,
        ct_exp: u8,
        cap_12: GetCapabilitiesV12,
    ) -> MessageBuf<'a> {
        let mut msg = MessageBuf::new(buf);
        let mut len = 0;

        len += cap_base.encode(&mut msg).unwrap();
        len += GetCapabilitiesV11::new(ct_exp, cap_flags)
            .encode(&mut msg)
            .unwrap();
        len += cap_12.encode(&mut msg).unwrap();

        msg.push_data(len).unwrap();

        msg
    }
}
