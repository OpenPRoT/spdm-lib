// Licensed under the Apache-2.0 license

use crate::commands::error_rsp::ErrorCode;
use crate::protocol::CapabilityFlags;
use crate::{codec::MessageBuf, context::SpdmContext, error::CommandResult, protocol::SpdmMsgHdr};

use crate::commands::capabilities::{
    Capabilities, CapabilitiesBase, CapabilitiesV12, GetCapabilitiesBase, GetCapabilitiesV11,
    GetCapabilitiesV12,
};
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

    let _base_resp = CapabilitiesBase::decode(resp)
        .map_err(|_| ctx.generate_error_response(resp, ErrorCode::OperationFailed, 0, None))?;

    // Based on the negotiated version, try to decode the rest of the response.
    // If the response misses expected fields, return an error.
    // See src/commands/capabilities/response.rs for more details.

    let mut peer_capabilities = DeviceCapabilities::default();

    let resp_11 = Capabilities::decode(resp)
        .map_err(|_| ctx.generate_error_response(resp, ErrorCode::InvalidRequest, 0, None))?;
    peer_capabilities.ct_exponent = resp_11.ct_exponent;

    let flags = resp_11.flags;
    if !resp_flags_compatible(version, &flags) {
        Err(ctx.generate_error_response(resp, ErrorCode::InvalidPolicy, 0, None))?;
    }
    peer_capabilities.flags = resp_11.flags;

    if version >= SpdmVersion::V12 {
        let resp_12 = CapabilitiesV12::decode(resp)
            .map_err(|_| ctx.generate_error_response(resp, ErrorCode::InvalidRequest, 0, None))?;

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
    // TODO: Since v1.3 an additional optional Supported Algorithms block was added.

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
    // ctx.append_message_to_transcript(req_buf, TranscriptContext::M1)
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

/// Checks that the flags in a capabilites response are compatible with the provided version
///
/// Checks for reserved values and consistency of flags as far as required.
fn resp_flags_compatible(version: SpdmVersion, flags: &CapabilityFlags) -> bool {
    // Most checks are the same but its a bit of a mess with some exceptions,
    // so we just do a complete check for every version.
    match version {
        SpdmVersion::V10 => check_flags_v10(flags),
        SpdmVersion::V11 => check_flags_v11(flags),
        SpdmVersion::V12 => check_flags_v12(flags),
        SpdmVersion::V13 => check_flags_v13(flags),
    }
}

/// Check flags to be compatible with version 1.0
///
/// Checks that all flags known to v1.0 have valid values.
/// Reserved fields are ignored.
fn check_flags_v10(flags: &CapabilityFlags) -> bool {
    // Check for reserved values
    !(flags.meas_cap() == 0b11)
}

/// Check flags to be compatible with version 1.1
///
/// Checks that all flags known to v1.1 have valid values.
/// Reserved fields are ignored.
fn check_flags_v11(flags: &CapabilityFlags) -> bool {
    // Check for reserved values
    if flags.meas_cap() == 0b11 {
        return false;
    }
    if flags.psk_cap() == 0b11 {
        return false;
    }
    // Check for conditionally needed flags
    if flags.encrypt_cap() == 1 {
        // One or more of MAC_CAP or KEY_EX_CAP must be set
        if flags.mac_cap() == 0 && flags.key_ex_cap() == 0 {
            return false;
        }
    }
    if flags.mac_cap() == 1 {
        // One or more of PSK_CAP or KEY_EX_CAP must be set
        if flags.psk_cap() == 0 && flags.key_ex_cap() == 0 {
            return false;
        }
    }
    if flags.key_ex_cap() == 1 {
        // One or more of MAC_CAP or ENCRYPT_CAP must be set
        if flags.mac_cap() == 0 && flags.encrypt_cap() == 0 {
            return false;
        }
    }
    if flags.psk_cap() == 1 {
        // One or more of MAC_CAP or ENCRYPT_CAP must be set
        if flags.mac_cap() == 0 && flags.encrypt_cap() == 0 {
            return false;
        }
    }
    if flags.mut_auth_cap() == 1 {
        if flags.encap_cap() == 0 {
            return false;
        }
    }
    if flags.handshake_in_the_clear_cap() == 1 {
        if flags.key_ex_cap() == 0 {
            return false;
        }
    }
    if flags.pub_key_id_cap() == 1 {
        if flags.cert_cap() == 1 {
            return false;
        }
    }
    true
}

/// Check flags to be compatible with version 1.2
///
/// Checks that all flags known to v1.2 have valid values.
/// Reserved fields are ignored.
fn check_flags_v12(flags: &CapabilityFlags) -> bool {
    // Check for reserved values
    if flags.meas_cap() == 0b11 {
        return false;
    }
    if flags.psk_cap() == 0b11 {
        return false;
    }
    // Check for conditionally needed flags
    if flags.encrypt_cap() == 1 {
        // One or more of MAC_CAP or KEY_EX_CAP must be set
        if flags.mac_cap() == 0 && flags.key_ex_cap() == 0 {
            return false;
        }
    }
    if flags.mac_cap() == 1 {
        // One or more of PSK_CAP or KEY_EX_CAP must be set
        if flags.psk_cap() == 0 && flags.key_ex_cap() == 0 {
            return false;
        }
    }
    if flags.key_ex_cap() == 1 {
        // One or more of MAC_CAP or ENCRYPT_CAP must be set
        if flags.mac_cap() == 0 && flags.encrypt_cap() == 0 {
            return false;
        }
    }
    if flags.psk_cap() == 1 {
        // One or more of MAC_CAP or ENCRYPT_CAP must be set
        if flags.mac_cap() == 0 && flags.encrypt_cap() == 0 {
            return false;
        }
    }
    if flags.mut_auth_cap() == 1 {
        if flags.encap_cap() == 0 {
            return false;
        }
    }
    if flags.handshake_in_the_clear_cap() == 1 {
        if flags.key_ex_cap() == 0 {
            return false;
        }
    }
    if flags.pub_key_id_cap() == 1 {
        // In this case, CERT_CAP and ALIAS_CERT_CAP of the responder
        // shall be 0.
        if flags.cert_cap() == 1 || flags.alias_cert_cap() == 1 {
            return false;
        }
    }
    if flags.csr_cap() == 1 {
        if flags.set_certificate_cap() == 0 {
            return false;
        }
    }
    if flags.cert_install_reset_cap() == 1 {
        // If this bit is set, CSR_CAP and/or SET_CERT_CAP shall be set.
        if flags.csr_cap() == 0 && flags.set_certificate_cap() == 0 {
            return false;
        }
    }
    true
}

/// Check flags to be compatible with version 1.3
///
/// Checks that all flags known to v1.3 have valid values.
/// Reserved fields are ignored.
fn check_flags_v13(flags: &CapabilityFlags) -> bool {
    // Check for reserved values
    if flags.meas_cap() == 0b11 {
        return false;
    }
    if flags.psk_cap() == 0b11 {
        return false;
    }
    if flags.ep_info_cap() == 0b11 {
        return false;
    }
    // Check for conditionally needed flags
    if flags.encrypt_cap() == 1 {
        // One or more of MAC_CAP or KEY_EX_CAP shall be set
        if flags.mac_cap() == 0 && flags.key_ex_cap() == 0 {
            return false;
        }
    }
    if flags.mac_cap() == 1 {
        // One or more of PSK_CAP or KEY_EX_CAP shall be set
        if flags.psk_cap() == 0 && flags.key_ex_cap() == 0 {
            return false;
        }
    }
    if flags.key_ex_cap() == 1 {
        // One or more of MAC_CAP or ENCRYPT_CAP shall be set
        if flags.mac_cap() == 0 && flags.encrypt_cap() == 0 {
            return false;
        }
    }
    if flags.psk_cap() == 1 {
        // One or more of MAC_CAP or ENCRYPT_CAP shall be set
        if flags.mac_cap() == 0 && flags.encrypt_cap() == 0 {
            return false;
        }
    }
    if flags.mut_auth_cap() == 1 {
        if flags.encap_cap() == 0 {
            return false;
        }
    }
    if flags.handshake_in_the_clear_cap() == 1 {
        if flags.key_ex_cap() == 0 {
            return false;
        }
    }
    if flags.pub_key_id_cap() == 1 {
        // In this case, CERT_CAP and ALIAS_CERT_CAP and MULTI_KEY_CAP of the responder
        // shall be 0.
        if flags.cert_cap() == 1 || flags.alias_cert_cap() == 1 || flags.multi_key_cap() == 1 {
            return false;
        }
    }
    if flags.csr_cap() == 1 {
        if flags.set_certificate_cap() == 0 {
            return false;
        }
    }
    if flags.cert_install_reset_cap() == 1 {
        // If this bit is set, SET_CERT_CAP shall be set and CSR_CAP can be set.
        // Note: This was changed. In v1.2 one of both was required
        if flags.set_certificate_cap() == 0 {
            return false;
        }
    }
    if flags.multi_key_cap() == 1 {
        if flags.get_key_pair_info_cap() == 0 {
            return false;
        }
    }
    true
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
        let cap_base = CapabilitiesBase::default();
        len += cap_base.encode(&mut msg).unwrap();
        let cap_10 = Capabilities::new(10, CapabilityFlags::default());
        len += cap_10.encode(&mut msg).unwrap();
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
        let cap_base = CapabilitiesBase::default();
        let mut cap_flags = CapabilityFlags::default();
        cap_flags.set_meas_cap(0b11); // 0x11 is reserved
        let cap_12 = CapabilitiesV12::default();
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
        let cap_base = CapabilitiesBase::default();
        let cap_flags = CapabilityFlags::default();
        let cap_12 = CapabilitiesV12 {
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
        let cap_base = CapabilitiesBase::default();
        let cap_flags = CapabilityFlags::default();
        let cap_12 = CapabilitiesV12 {
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
        cap_base: CapabilitiesBase,
        cap_flags: CapabilityFlags,
        ct_exp: u8,
        cap_12: CapabilitiesV12,
    ) -> MessageBuf<'a> {
        let mut msg = MessageBuf::new(buf);
        let mut len = 0;

        len += cap_base.encode(&mut msg).unwrap();
        len += Capabilities::new(ct_exp, cap_flags)
            .encode(&mut msg)
            .unwrap();
        len += cap_12.encode(&mut msg).unwrap();

        msg.push_data(len).unwrap();

        msg
    }
}
