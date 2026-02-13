// Licensed under the Apache-2.0 license

use crate::{
    codec::{Codec, MessageBuf},
    commands::capabilities::req_flag_compatible,
    context::SpdmContext,
    error::{CommandError, CommandResult},
    protocol::SpdmMsgHdr,
    state::ConnectionState,
    transcript::TranscriptContext,
};

use crate::commands::error_rsp::ErrorCode;
use crate::commands::version::{VersionNumberEntry, VersionReqPayload, VersionRespCommon};

use crate::protocol::SpdmVersion;

/// Generate the GET_VERSION command with Header and payload and append it to the transcript context
/// See [crate::transcript::TranscriptContext::Vca] and [crate::transcript::TranscriptContext::M1] for details on the transcript context used.
pub fn generate_get_version<'a>(
    ctx: &mut SpdmContext<'a>,
    req_buf: &mut MessageBuf<'a>,
    payload: VersionReqPayload,
) -> CommandResult<()> {
    SpdmMsgHdr::new(
        ctx.state.connection_info.version_number(),
        crate::protocol::ReqRespCode::GetVersion,
    )
    .encode(req_buf)
    .map_err(|e| (false, CommandError::Codec(e)))?;

    let len = payload
        .encode(req_buf)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    req_buf
        .push_data(len)
        .map_err(|_| (false, CommandError::BufferTooSmall))?;

    // ctx.append_message_to_transcript(req_buf, TranscriptContext::Vca)
    ctx.append_message_to_transcript(req_buf, TranscriptContext::M1)
}

/// Requester function for processing a VERSION response
///
/// Updates the state of the context to match the selected version.
///
/// # Returns
/// - The selected latest common supported version on success
/// - [CommandError::UnsupportedResponse] when no common version is found
/// - [CommandError::Codec] when decoding fails
fn process_version<'a>(
    ctx: &mut SpdmContext<'a>,
    spdm_hdr: SpdmMsgHdr,
    resp_payload: &mut MessageBuf<'a>,
) -> CommandResult<SpdmVersion> {
    // VERSION response must use version 1.0 per spec
    match spdm_hdr.version() {
        Ok(SpdmVersion::V10) => {}
        _ => {
            Err((false, CommandError::UnsupportedResponse))?;
        }
    }

    // Decode the VERSION response common header
    let resp =
        VersionRespCommon::decode(resp_payload).map_err(|e| (false, CommandError::Codec(e)))?;

    let entry_count = resp.version_num_entry_count as usize;

    // Validate entry count
    if entry_count == 0 {
        Err((false, CommandError::UnsupportedResponse))?;
    }

    // Decode all version entries from the response
    let mut latest_version = None;
    for _ in 0..entry_count {
        let ver = VersionNumberEntry::decode(resp_payload)
            .map_err(|e| (false, CommandError::Codec(e)))?;
        if let Ok(ver) = SpdmVersion::try_from(ver) {
            if let Some(lv) = latest_version.as_mut() {
                if *lv < ver {
                    *lv = ver;
                }
            } else {
                latest_version = Some(ver);
            }
        }
    }

    if let Some(ver) = latest_version {
        ctx.state.connection_info.set_version_number(ver);
        Ok(ver)
    } else {
        Err((false, CommandError::UnsupportedResponse))
    }
}

/// Requester function handling the parsing of the VERSION response sent by the Responder.
/// Updates the context with the selected version and appends the response to the transcript context.
/// See [crate::transcript::TranscriptContext::Vca] for details on the transcript context used.
pub(crate) fn handle_version_response<'a>(
    ctx: &mut SpdmContext<'a>,
    resp_header: SpdmMsgHdr,
    resp: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    // Verify state is correct for VERSION response
    if ctx.state.connection_info.state() != ConnectionState::NotStarted {
        Err((false, CommandError::UnsupportedResponse))?;
        // TODO: is there a better error for this?
        Err(ctx.generate_error_response(resp, ErrorCode::InvalidResponseCode, 0, None))?;
    }

    process_version(ctx, resp_header, resp)?;

    ctx.state
        .connection_info
        .set_state(ConnectionState::AfterVersion);

    // ctx.append_message_to_transcript(resp, TranscriptContext::Vca)
    ctx.append_message_to_transcript(resp, TranscriptContext::M1)
}

// tests
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{protocol::MAX_MCTP_SPDM_MSG_SIZE, test::*};

    #[test]
    fn test_process_version_happy_path() {
        let versions = versions_default();
        let mut stack = MockResources::new();
        let algorithms = crate::protocol::LocalDeviceAlgorithms::default();
        let mut context = create_context(&mut stack, &versions, algorithms);

        let header = SpdmMsgHdr::new(SpdmVersion::V10, crate::protocol::ReqRespCode::Version);

        let mut msg_buf = [0; MAX_MCTP_SPDM_MSG_SIZE];
        let mut msg = MessageBuf::new(&mut msg_buf);
        let version_response = VersionRespCommon::new(2);
        let resp_common_size = version_response.encode(&mut msg).unwrap();
        let entr_1 = VersionNumberEntry::new(SpdmVersion::V11);
        let e1_size = entr_1.encode(&mut msg).unwrap();
        let entr_2 = VersionNumberEntry::new(SpdmVersion::V12);
        let e2_size = entr_2.encode(&mut msg).unwrap();
        msg.push_data(resp_common_size + e1_size + e2_size).unwrap(); // This has to be done at the end of encoding for some reason
        assert_eq!(msg.data_len(), (resp_common_size + e1_size + e2_size));

        let rsp = process_version(&mut context, header, &mut msg);
        assert!(
            rsp.is_ok(),
            "process_version returned error: {:?}",
            rsp.unwrap_err()
        );

        let rsp = rsp.unwrap();

        assert_eq!(rsp, SpdmVersion::V12);
    }

    #[test]
    fn test_process_version_malformed_response() {
        let versions = versions_default();
        let mut stack = MockResources::new();
        let algorithms = crate::protocol::LocalDeviceAlgorithms::default();
        let mut context = create_context(&mut stack, &versions, algorithms);

        // Test wrong header
        let header = SpdmMsgHdr::new(SpdmVersion::V12, crate::protocol::ReqRespCode::Version);

        let mut msg_buf = [0; MAX_MCTP_SPDM_MSG_SIZE];
        let mut msg = MessageBuf::new(&mut msg_buf);
        let version_response = VersionRespCommon::new(2);
        let resp_common_size = version_response.encode(&mut msg).unwrap();
        let entr_1 = VersionNumberEntry::new(SpdmVersion::V11);
        let e1_size = entr_1.encode(&mut msg).unwrap();
        msg.push_data(resp_common_size + e1_size).unwrap();
        assert_eq!(msg.data_len(), (resp_common_size + e1_size));

        let rsp = process_version(&mut context, header, &mut msg);
        assert!(rsp.is_err_and(|e| e.1 == CommandError::UnsupportedResponse));

        // Test response without entries
        let header = SpdmMsgHdr::new(SpdmVersion::V12, crate::protocol::ReqRespCode::Version);

        let mut msg_buf = [0; MAX_MCTP_SPDM_MSG_SIZE];
        let mut msg = MessageBuf::new(&mut msg_buf);
        let version_response = VersionRespCommon::new(0);
        let resp_common_size = version_response.encode(&mut msg).unwrap();
        msg.push_data(resp_common_size).unwrap();

        let rsp = process_version(&mut context, header, &mut msg);
        assert!(rsp.is_err_and(|e| e.1 == CommandError::UnsupportedResponse));

        // Test unsupported version
        let header = SpdmMsgHdr::new(SpdmVersion::V12, crate::protocol::ReqRespCode::Version);

        let mut msg_buf = [0; MAX_MCTP_SPDM_MSG_SIZE];
        let mut msg = MessageBuf::new(&mut msg_buf);
        let version_response = VersionRespCommon::new(1);
        let resp_common_size = version_response.encode(&mut msg).unwrap();
        let mut entr_1 = VersionNumberEntry::new(SpdmVersion::V10);
        entr_1.set_major(9); // unsupported version
        let e1_size = entr_1.encode(&mut msg).unwrap();
        msg.push_data(resp_common_size + e1_size).unwrap();
        assert_eq!(msg.data_len(), (resp_common_size + e1_size));

        let rsp = process_version(&mut context, header, &mut msg);
        assert!(rsp.is_err_and(|e| e.1 == CommandError::UnsupportedResponse));
    }

    #[test]
    fn validate_get_version_request() {
        let versions = versions_default();
        let mut stack = MockResources::new();
        let algorithms = crate::protocol::LocalDeviceAlgorithms::default();
        let mut context = create_context(&mut stack, &versions, algorithms);

        let mut msg_buf = [0; MAX_MCTP_SPDM_MSG_SIZE];
        let mut msg = MessageBuf::new(&mut msg_buf);

        assert!(generate_get_version(&mut context, &mut msg, VersionReqPayload::new(0, 0)).is_ok());

        let data = msg.total_message();
        assert_eq!(data.len(), 4, "GET_VERSION command length mismatch");
        let req_version: SpdmVersion = data[0].try_into().unwrap();
        assert_eq!(req_version, SpdmVersion::V10);

        assert_eq!(data[1], 0x84, "Command code doesn't match GET_VERSION");
    }
}
