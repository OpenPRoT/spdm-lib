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

use crate::codec::{Codec, MessageBuf};
use crate::commands::error_rsp::ErrorCode;
use crate::commands::version::{VersionNumberEntry, VersionReqPayload, VersionRespCommon};
use crate::context::SpdmContext;
use crate::error::{CommandError, CommandResult};
use crate::protocol::{ReqRespCode, SpdmMsgHdr, SpdmVersion};
use crate::state::ConnectionState;
use crate::transcript::TranscriptContext;

fn generate_version_response<'a>(
    ctx: &mut SpdmContext<'a>,
    rsp_buf: &mut MessageBuf<'a>,
    supported_versions: &[SpdmVersion],
) -> CommandResult<()> {
    let entry_count = supported_versions.len() as u8;
    // Fill SpdmHeader first
    let spdm_resp_hdr = SpdmMsgHdr::new(SpdmVersion::V10, ReqRespCode::Version);
    let mut payload_len = spdm_resp_hdr
        .encode(rsp_buf)
        .map_err(|_| (false, CommandError::BufferTooSmall))?;

    // Fill VersionRespCommon
    let resp_common = VersionRespCommon::new(entry_count);
    payload_len += resp_common
        .encode(rsp_buf)
        .map_err(|_| (false, CommandError::BufferTooSmall))?;

    for &version in supported_versions.iter() {
        let entry = VersionNumberEntry::new(version);
        payload_len += entry
            .encode(rsp_buf)
            .map_err(|_| (false, CommandError::BufferTooSmall))?;
    }

    // Push data offset up by total payload length
    rsp_buf
        .push_data(payload_len)
        .map_err(|_| (false, CommandError::BufferTooSmall))?;

    // Append response to VCA transcript
    ctx.append_message_to_transcript(rsp_buf, TranscriptContext::Vca)
}

fn process_get_version<'a>(
    ctx: &mut SpdmContext<'a>,
    spdm_hdr: SpdmMsgHdr,
    req_payload: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    match spdm_hdr.version() {
        Ok(SpdmVersion::V10) => {}
        _ => {
            Err(ctx.generate_error_response(req_payload, ErrorCode::VersionMismatch, 0, None))?;
        }
    }

    VersionReqPayload::decode(req_payload).map_err(|e| (false, CommandError::Codec(e)))?;

    // Reset Transcript
    ctx.transcript_mgr.reset();

    // Append request to VCA transcript
    ctx.append_message_to_transcript(req_payload, TranscriptContext::Vca)
}

pub(crate) fn handle_get_version<'a>(
    ctx: &mut SpdmContext<'a>,
    spdm_hdr: SpdmMsgHdr,
    req_payload: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    // Process GET_VERSION request
    process_get_version(ctx, spdm_hdr, req_payload)?;

    // Generate VERSION response
    ctx.prepare_response_buffer(req_payload)?;
    generate_version_response(ctx, req_payload, ctx.supported_versions)?;

    // Set connection state
    ctx.state.reset();
    ctx.state
        .connection_info
        .set_state(ConnectionState::AfterVersion);
    Ok(())
}
