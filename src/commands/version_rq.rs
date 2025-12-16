// Licensed under the Apache-2.0 license

use crate::{
    codec::{Codec, CommonCodec, MessageBuf},
    context::SpdmContext,
    error::{CommandError, CommandResult, SpdmResult},
    protocol::{version, SpdmMsgHdr},
    transcript::TranscriptContext,
};

use crate::commands::error_rsp::ErrorCode;

use crate::protocol::{ReqRespCode, SpdmVersion};
use bitfield::bitfield;
use zerocopy::{FromBytes, Immutable, IntoBytes};

const VERSION_ENTRY_SIZE: usize = 2;

// 4.9.1.1 GET_VERSION request message and VERSION response message
#[derive(FromBytes, IntoBytes, Immutable)]
pub struct GetVersionPayload {
    Param1: u8,
    Param2: u8,
}

impl GetVersionPayload {
    pub fn new(param1: u8, param2: u8) -> Self {
        GetVersionPayload {
            Param1: param1,
            Param2: param2,
        }
    }
}

impl CommonCodec for GetVersionPayload {}

// copy until refactored
#[allow(dead_code)]
#[derive(FromBytes, IntoBytes, Immutable)]
struct VersionRespCommon {
    param1: u8,
    param2: u8,
    reserved: u8,
    version_num_entry_count: u8,
}

impl CommonCodec for VersionReqPayload {}

impl Default for VersionRespCommon {
    fn default() -> Self {
        VersionRespCommon::new(0)
    }
}

impl VersionRespCommon {
    pub fn new(entry_count: u8) -> Self {
        VersionRespCommon {
            param1: 0,
            param2: 0,
            reserved: 0,
            version_num_entry_count: entry_count,
        }
    }
}

impl CommonCodec for VersionRespCommon {}

bitfield! {
#[repr(C)]
#[derive(FromBytes, IntoBytes, Immutable)]
pub struct VersionNumberEntry(MSB0 [u8]);
impl Debug;
u8;
    pub update_ver, set_update_ver: 3, 0;
    pub alpha, set_alpha: 7, 4;
    pub major, set_major: 11, 8;
    pub minor, set_minor: 15, 12;
}

impl Default for VersionNumberEntry<[u8; VERSION_ENTRY_SIZE]> {
    fn default() -> Self {
        VersionNumberEntry::new(SpdmVersion::default())
    }
}

impl VersionNumberEntry<[u8; VERSION_ENTRY_SIZE]> {
    pub fn new(version: SpdmVersion) -> Self {
        let mut entry = VersionNumberEntry([0u8; VERSION_ENTRY_SIZE]);
        entry.set_major(version.major());
        entry.set_minor(version.minor());
        entry
    }
}

impl CommonCodec for VersionNumberEntry<[u8; VERSION_ENTRY_SIZE]> {}

// Generate the GET_VERSION command with all the contexts information
pub(crate) fn send_get_version<'a>(
    ctx: &mut SpdmContext<'a>,
    req_buf: &mut MessageBuf<'a>,
    payload: GetVersionPayload,
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
    req_buf: &mut MessageBuf<'a>,
    payload: GetVersionPayload,
) -> CommandResult<()> {
    let req = req_buf;

    let req_msg_header: SpdmMsgHdr =
        SpdmMsgHdr::decode(req).map_err(|e| (false, CommandError::Codec(e)))?;

    let req_code = req_msg_header
        .req_resp_code()
        .map_err(|_| (false, CommandError::UnsupportedResponse));

    Ok(())
}

// tests
#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::SpdmVersion;

    #[test]
    #[ignore]
    fn test_process_version() {
        todo!();
    }
}
