// Licensed under the Apache-2.0 license

use crate::codec::{Codec, MessageBuf};
use crate::commands::certificate::{CertificateReqAttributes, GetCertificateReq, SlotId};
use crate::context::SpdmContext;
use crate::error::{CommandError, CommandResult};
use crate::protocol::{ReqRespCode, SpdmMsgHdr};
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
/// # TODO
/// Implement CERTIFICATE response processing including:
/// - Validate version matches connection version
/// - Decode CertificateRespCommon
/// - Validate slot_id matches request
/// - Extract and store certificate chain portion
/// - Handle certificate chain metadata if offset is 0
/// - Track remainder_length for multi-part transfers
fn _process_certificate<'a>(
    _ctx: &mut SpdmContext<'a>,
    _spdm_hdr: SpdmMsgHdr,
    _resp_payload: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    todo!("Implement CERTIFICATE response processing")
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
/// # TODO
/// Implement CERTIFICATE response handler including:
/// - Verify connection state (should be >= AlgorithmsNegotiated)
/// - Call process_certificate to parse and validate response
/// - Append response to transcript (TranscriptContext::M1)
/// - Update connection state to AfterCertificate if needed
pub(crate) fn _handle_certificate_response<'a>(
    _ctx: &mut SpdmContext<'a>,
    _resp_header: SpdmMsgHdr,
    _resp: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    todo!("Implement CERTIFICATE response handler")
}
