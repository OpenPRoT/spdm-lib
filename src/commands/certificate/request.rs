// Licensed under the Apache-2.0 license

use crate::codec::MessageBuf;
use crate::context::SpdmContext;
use crate::error::CommandResult;
use crate::protocol::SpdmMsgHdr;

/// Generate the GET_CERTIFICATE request
///
/// # Arguments
/// * `ctx`: The SPDM context
/// * `req_buf`: Buffer to write the request into
/// * `slot_id`: Certificate slot identifier (0-7)
/// * `offset`: Byte offset into the certificate chain
/// * `length`: Number of bytes to request
///
/// # Returns
/// - () on success
/// - [CommandError] on failure
///
/// # TODO
/// Implement GET_CERTIFICATE request generation including:
/// - Create and encode SpdmMsgHdr with ReqRespCode::GetCertificate
/// - Create and encode GetCertificateReq payload
/// - Append to transcript (TranscriptContext::M1)
pub fn generate_get_certificate<'a>(
    _ctx: &mut SpdmContext<'a>,
    _req_buf: &mut MessageBuf<'a>,
    _slot_id: u8,
    _offset: u16,
    _length: u16,
) -> CommandResult<()> {
    todo!("Implement GET_CERTIFICATE request generation")
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
fn process_certificate<'a>(
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
pub(crate) fn handle_certificate_response<'a>(
    _ctx: &mut SpdmContext<'a>,
    _resp_header: SpdmMsgHdr,
    _resp: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    todo!("Implement CERTIFICATE response handler")
}
