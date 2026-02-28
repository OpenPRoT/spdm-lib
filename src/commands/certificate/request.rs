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
use crate::commands::certificate::{
    CertificateReqAttributes, CertificateRespCommon, GetCertificateReq, SlotId,
};
use crate::context::SpdmContext;
use crate::error::{CommandError, CommandResult};
use crate::protocol::{CertModel, ReqRespCode, SpdmMsgHdr, SpdmVersion};
use crate::state::{ConnectionState, GetCertificateState};
use crate::transcript::TranscriptContext;

/// Generate a GET_CERTIFICATE request
///
/// If the state is `DuringCertificate` the following parameters will be ignored
/// and instead be calculated from the state:
/// `slot_id`, `offset`.
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
/// - Updates the state to `DuringCertificate` (only if `slot_size_requested` == `false`)
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

    let state = match ctx.state.connection_info.state() {
        ConnectionState::DuringCertificate(s) => s,
        _ => GetCertificateState {
            current_slot_id: slot_id,
            offset,
            ..Default::default()
        },
    };
    if !slot_size_requested {
        ctx.state
            .connection_info
            .set_state(ConnectionState::DuringCertificate(state));
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
    slot_id_field.set_slot_id(state.current_slot_id);

    // Create CertificateReqAttributes bitfield
    let mut req_attributes = CertificateReqAttributes(0);
    if slot_size_requested {
        req_attributes.set_slot_size_requested(1);
    }

    // Create GET_CERTIFICATE request payload
    let get_cert_req = GetCertificateReq {
        slot_id: slot_id_field,
        param2: req_attributes,
        offset: state.offset,
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

    // Message M1.B = Concatenate(GET_DIGESTS, DIGESTS, GET_CERTIFICATE, CERTIFICATE)
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
/// - Validates returned slot_id against expected slot_id
/// - Reads certificate portion data (validates buffer size)
/// - Stores certificate portion in peer cert. store
/// - Updates state
///
/// # Future Extensions
/// - TODO: Add support for SlotSizeRequested responses
fn process_certificate<'a>(
    ctx: &mut SpdmContext<'a>,
    spdm_hdr: SpdmMsgHdr,
    resp_payload: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    // Validate version matches connection version
    let connection_version = ctx.state.connection_info.version_number();
    if spdm_hdr.version().ok() != Some(connection_version) {
        return Err((true, CommandError::InvalidResponse));
    }

    let ConnectionState::DuringCertificate(mut state) = ctx.state.connection_info.state() else {
        // TODO: Add support for SlotSizeRequested
        return Err((false, CommandError::InvalidState));
    };

    // Decode CertificateRespCommon structure
    let cert_resp =
        CertificateRespCommon::decode(resp_payload).map_err(|e| (true, CommandError::Codec(e)))?;

    // Check slot_id
    let slot_id = cert_resp.slot_id.slot_id();
    if slot_id != state.current_slot_id {
        return Err((true, CommandError::InvalidResponse));
    }

    // Decode CertModel from param2
    // Seems to be available since v1.3
    if connection_version >= SpdmVersion::V13 {
        // Fails if a unknown CertModel is send
        // (so we consider this to be a bug on the responder side).
        let _cert_info: CertModel = cert_resp
            .param2
            .certificate_info()
            .try_into()
            .map_err(|_| (true, CommandError::InvalidResponse))?;
    }

    let portion_len = cert_resp.portion_length;

    // Read the certificate portion from the payload (if any)
    if portion_len > 0 {
        // Validate that the buffer contains the expected certificate data
        let cert_data = resp_payload
            .data(portion_len as usize)
            .map_err(|e| (true, CommandError::Codec(e)))?;

        let Some(cert_store) = ctx.state.peer_cert_store.as_deref_mut() else {
            return Err((true, CommandError::InvalidState));
        };

        match cert_store.assemble(state.current_slot_id, cert_data) {
            Ok(_s) => {
                // TODO: match s against remainder length
            }
            Err(e) => return Err((true, CommandError::CertStore(e))),
        }

        // Advance the buffer pointer past the certificate data
        resp_payload
            .pull_data(portion_len as usize)
            .map_err(|e| (true, CommandError::Codec(e)))?;
    }

    state.offset += portion_len;
    state.remainder_length = Some(cert_resp.remainder_length);

    if cert_resp.remainder_length > 0 {
        ctx.state
            .connection_info
            .set_state(ConnectionState::DuringCertificate(state));
    } else {
        ctx.state
            .connection_info
            .set_state(ConnectionState::AfterCertificate);
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
/// - Updates: ConnectionState to DuringCertificate or AfterCertificate
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
        return Err((true, CommandError::UnsupportedResponse));
    }

    // Process the certificate response payload
    process_certificate(ctx, resp_header, resp)?;

    // Append response to transcript (M1 context for certificate exchange)
    ctx.append_message_to_transcript(resp, TranscriptContext::M1)
}
