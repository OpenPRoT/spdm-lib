// Licensed under the Apache-2.0 license

use crate::codec::{Codec, MessageBuf};
use crate::commands::certificate::{
    CertificateReqAttributes, CertificateRespCommon, GetCertificateReq, SlotId,
};
use crate::context::SpdmContext;
use crate::error::{CommandError, CommandResult};
use crate::protocol::{CertModel, ReqRespCode, SpdmMsgHdr, SpdmVersion};
use crate::state::ConnectionState;
use crate::transcript::TranscriptContext;

/// Generate the GET_CERTIFICATE request
///
/// # Arguments
/// * `ctx`: The SPDM context
/// * `req_buf`: Buffer to write the request into
/// * `slot_id`: Certificate slot identifier (0-7)
/// * `offset`: Byte offset into the certificate chain
/// * `length`: Number of bytes to request
/// * `slot_size_requested`: If true, request the slot size instead of certificate data (SPDM v1.3+)
///
/// # Returns
/// - () on success
/// - [CommandError] on failure
///
/// # Connection State Requirements
/// - Connection state must be >= AlgorithmsNegotiated
///
/// # Transcript
/// - Appends request to the transcript context
pub fn generate_get_certificate<'a>(
    ctx: &mut SpdmContext<'a>,
    req_buf: &mut MessageBuf<'a>,
    slot_id: u8,
    offset: u16,
    length: u16,
    slot_size_requested: bool,
) -> CommandResult<()> {
    // Validate connection state - algorithms must be negotiated first
    if ctx.state.connection_info.state() < ConnectionState::AlgorithmsNegotiated {
        return Err((false, CommandError::UnsupportedRequest));
    }

    // Get connection version
    let connection_version = ctx.state.connection_info.version_number();

    // Create and encode SPDM message header
    let spdm_hdr = SpdmMsgHdr::new(connection_version, ReqRespCode::GetCertificate);
    let mut payload_len = spdm_hdr
        .encode(req_buf)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    // Create SlotId bitfield
    let mut slot_id_field = SlotId(0);
    slot_id_field.set_slot_id(slot_id);

    // Create CertificateReqAttributes bitfield
    let mut req_attributes = CertificateReqAttributes(0);
    if slot_size_requested {
        req_attributes.set_slot_size_requested(1);
    }

    // Create GET_CERTIFICATE request payload
    let get_cert_req = GetCertificateReq {
        slot_id: slot_id_field,
        param2: req_attributes,
        offset,
        length,
    };

    // Encode request payload
    payload_len += get_cert_req
        .encode(req_buf)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    // Finalize message by pushing total payload length
    req_buf
        .push_data(payload_len)
        .map_err(|_| (false, CommandError::BufferTooSmall))?;

    // Append to transcript
    // (TODO: M1 is incorrect here,
    // this is a requester functionality so this has to go into M2.
    // Change this once the TranscriptManager has been refactored.)
    ctx.append_message_to_transcript(req_buf, TranscriptContext::M1)
}

/// Process CERTIFICATE response payload (private helper)
///
/// # Arguments
/// * `ctx`: The SPDM context
/// * `spdm_hdr`: The SPDM message header from the response
/// * `resp_payload`: Buffer containing the response payload
///
/// # Returns
/// - () on success
/// - [CommandError] on failure
///
/// # Current Implementation
/// - Validates version matches connection version
/// - Decodes CertificateRespCommon structure
/// - Reads certificate portion data (validates buffer size)
///
/// # Future Extensions
/// - TODO: Validate slot_id matches request when slot tracking is implemented
/// - TODO: Parse certificate chain metadata when offset is 0
/// - TODO: Store certificate data in peer cert store
/// - TODO: Implement multi-part transfer support with dedicated reassembly context
/// - TODO: Validate root certificate hash against trust anchor
fn process_certificate<'a>(
    ctx: &mut SpdmContext<'a>,
    spdm_hdr: SpdmMsgHdr,
    resp_payload: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    // Validate version matches connection version
    let connection_version = ctx.state.connection_info.version_number();
    if spdm_hdr.version().ok() != Some(connection_version) {
        return Err((false, CommandError::InvalidResponse));
    }

    // Decode CertificateRespCommon structure
    let cert_resp =
        CertificateRespCommon::decode(resp_payload).map_err(|e| (false, CommandError::Codec(e)))?;

    // Decode CertModel from param2
    // Seems to be available since v1.3
    if connection_version >= SpdmVersion::V13 {
        // Fails if a unknown CertModel is send
        // (so we consider this to be a bug on the responder side).
        let _cert_info: CertModel = cert_resp
            .param2
            .certificate_info()
            .try_into()
            .map_err(|_| (false, CommandError::InvalidResponse))?;
    }

    let portion_len = cert_resp.portion_length;
    let _remainder_len = cert_resp.remainder_length; // TODO: Track for multi-part transfers

    // Read the certificate portion from the payload (if any)
    if portion_len > 0 {
        // Validate that the buffer contains the expected certificate data
        let _cert_data = resp_payload
            .data(portion_len as usize)
            .map_err(|e| (false, CommandError::Codec(e)))?;

        // Advance the buffer pointer past the certificate data
        resp_payload
            .pull_data(portion_len as usize)
            .map_err(|e| (false, CommandError::Codec(e)))?;

        // TODO: When certificate storage is implemented:
        // - Parse certificate chain metadata if this is the first chunk (offset=0)
        // - Store certificate data in peer cert store or reassembly context
        // - If remainder_len > 0, coordinate with reassembly context for next chunk
    }

    Ok(())
}

/// Requester function handling the parsing of the CERTIFICATE response sent by the Responder.
///
/// # Arguments
/// * `ctx`: The SPDM context
/// * `resp_header`: The SPDM message header from the response
/// * `resp`: Buffer containing the complete response message
///
/// # Returns
/// - () on success
/// - [CommandError] on failure
///
/// # Connection State
/// - Requires: ConnectionState >= AlgorithmsNegotiated
/// - Sets: ConnectionState::AfterCertificate
///
/// # Transcript
/// - Appends response to TranscriptContext::M1
pub(crate) fn handle_certificate_response<'a>(
    ctx: &mut SpdmContext<'a>,
    resp_header: SpdmMsgHdr,
    resp: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    // Validate connection state - algorithms must be negotiated
    if ctx.state.connection_info.state() < ConnectionState::AlgorithmsNegotiated {
        return Err((false, CommandError::UnsupportedResponse));
    }

    // Process the certificate response payload
    process_certificate(ctx, resp_header, resp)?;

    // Append response to transcript (M1 context for certificate exchange)
    ctx.append_message_to_transcript(resp, TranscriptContext::M1)?;

    // Update connection state to AfterCertificate if needed
    if ctx.state.connection_info.state() < ConnectionState::AfterCertificate {
        ctx.state
            .connection_info
            .set_state(ConnectionState::AfterCertificate);
    }

    Ok(())
}
