// Licensed under the Apache-2.0 license

use crate::{
    codec::{Codec, MessageBuf},
    context::SpdmContext,
    error::{CommandError, CommandResult},
    protocol::SpdmMsgHdr,
    transcript::TranscriptContext,
};

use crate::commands::error_rsp::ErrorCode;
use crate::commands::version::{VersionReqPayload, VersionRespCommon};

use crate::protocol::SpdmVersion;

// Generate the GET_VERSION command with all the contexts information
pub(crate) fn send_get_version<'a>(
    ctx: &mut SpdmContext<'a>,
    req_buf: &mut MessageBuf<'a>,
    payload: VersionReqPayload,
) -> CommandResult<()> {
    let len = payload
        .encode(req_buf)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    req_buf
        .push_data(len)
        .map_err(|_| (false, CommandError::BufferTooSmall))?;

    ctx.append_message_to_transcript(req_buf, TranscriptContext::Vca)?;
    Ok(())
}

// Requester function for processing a VERSION response
fn process_version<'a>(
    ctx: &mut SpdmContext<'a>,
    spdm_hdr: SpdmMsgHdr,
    resp_payload: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    // VERSION response must use version 1.0 per spec
    match spdm_hdr.version() {
        Ok(SpdmVersion::V10) => {}
        _ => {
            Err(ctx.generate_error_response(resp_payload, ErrorCode::VersionMismatch, 0, None))?;
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
    Ok(())
}

/// Requester function handling the parsing of the VERSION response sent by the Responder.
pub(crate) fn handle_version_response<'a>(
    ctx: &mut SpdmContext<'a>,
    resp_header: SpdmMsgHdr,
    resp: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    todo!();
}

// tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore]
    fn test_process_version() {
        todo!();
    }
}
