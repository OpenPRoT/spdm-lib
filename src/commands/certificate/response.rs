// Licensed under the Apache-2.0 license

use crate::cert_store::{cert_slot_mask, MAX_CERT_SLOTS_SUPPORTED};
use crate::codec::{Codec, MessageBuf};
use crate::commands::certificate::{
    encode_certchain_metadata, CertificateRespAttributes, CertificateRespCommon, GetCertificateReq,
    SlotId,
};
use crate::commands::error_rsp::ErrorCode;
use crate::context::SpdmContext;
use crate::error::{CommandError, CommandResult};
use crate::protocol::*;
use crate::state::ConnectionState;
use crate::transcript::TranscriptContext;

fn generate_certificate_response<'a>(
    ctx: &mut SpdmContext<'a>,
    slot_id: u8,
    offset: u16,
    length: u16,
    rsp: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    // Ensure the selected hash algorithm is SHA384 and retrieve the asymmetric algorithm (currently only ECC-P384 is supported)
    ctx.verify_selected_hash_algo()
        .map_err(|_| ctx.generate_error_response(rsp, ErrorCode::Unspecified, 0, None))?;
    let asym_algo = ctx
        .selected_base_asym_algo()
        .map_err(|_| ctx.generate_error_response(rsp, ErrorCode::Unspecified, 0, None))?;

    let connection_version = ctx.state.connection_info.version_number();

    // Start filling the response payload
    let spdm_hdr = SpdmMsgHdr::new(connection_version, ReqRespCode::Certificate);
    let mut payload_len = spdm_hdr
        .encode(rsp)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    let mut resp_attr = CertificateRespAttributes::default();
    if connection_version >= SpdmVersion::V13 && ctx.state.connection_info.multi_key_conn_rsp() {
        let cert_info = ctx
            .device_certs_store
            .cert_info(slot_id)
            .unwrap_or_default();
        resp_attr.set_certificate_info(cert_info.cert_model());
    }

    // Get total cert chain length in SPDM cert chain format
    let cert_chain_len = ctx
        .device_certs_store
        .cert_chain_len(asym_algo, slot_id)
        .map_err(|_| ctx.generate_error_response(rsp, ErrorCode::InvalidRequest, 0, None))?;
    let total_cert_chain_len = cert_chain_len as u16 + SPDM_CERT_CHAIN_METADATA_LEN;

    if offset >= total_cert_chain_len {
        return Err(ctx.generate_error_response(rsp, ErrorCode::InvalidRequest, 0, None));
    }

    let mut remainder_len = total_cert_chain_len.saturating_sub(offset);

    let portion_len = if length > SPDM_MAX_CERT_CHAIN_PORTION_LEN
    // && ctx.local_capabilities.flags.chunk_cap() == 1
    {
        SPDM_MAX_CERT_CHAIN_PORTION_LEN.min(remainder_len)
    } else {
        length.min(remainder_len)
    };

    remainder_len = remainder_len.saturating_sub(portion_len);
    let slot_id_struct = SlotId(slot_id);
    let certificate_rsp_common =
        CertificateRespCommon::new(slot_id_struct, resp_attr, portion_len, remainder_len);
    payload_len += certificate_rsp_common
        .encode(rsp)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    let mut rem_len = portion_len;
    let cert_offset: usize;

    if portion_len > 0 {
        // Encode the certificate chain metadata first if it the beginning of the certificate chain
        if offset < SPDM_CERT_CHAIN_METADATA_LEN {
            let read_len = encode_certchain_metadata(
                ctx.device_certs_store,
                total_cert_chain_len,
                slot_id,
                asym_algo,
                offset as usize,
                portion_len as usize,
                rsp,
            )?;
            payload_len += read_len;
            rem_len = portion_len.saturating_sub(read_len as u16);
            cert_offset = 0;
        } else {
            cert_offset = (offset - SPDM_CERT_CHAIN_METADATA_LEN) as usize;
        }

        // Read the certificate chain portion if there is remaining length
        if rem_len > 0 {
            rsp.put_data(rem_len as usize)
                .map_err(|e| (false, CommandError::Codec(e)))?;
            let cert_chain_buf = rsp
                .data_mut(rem_len as usize)
                .map_err(|e| (false, CommandError::Codec(e)))?;
            let read_len = ctx
                .device_certs_store
                .get_cert_chain(slot_id, asym_algo, cert_offset, cert_chain_buf)
                .map_err(|e| (false, CommandError::CertStore(e)))?;
            payload_len += read_len;
            rsp.pull_data(read_len)
                .map_err(|e| (false, CommandError::Codec(e)))?;
        }
    }

    rsp.push_data(payload_len)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    // Append the response message to the M1 transcript
    ctx.append_message_to_transcript(rsp, TranscriptContext::M1)
}

fn process_get_certificate<'a>(
    ctx: &mut SpdmContext<'a>,
    spdm_hdr: SpdmMsgHdr,
    req_payload: &mut MessageBuf<'a>,
) -> CommandResult<(u8, u16, u16)> {
    // Validate the version
    let connection_version = ctx.state.connection_info.version_number();
    if spdm_hdr.version().ok() != Some(connection_version) {
        Err(ctx.generate_error_response(req_payload, ErrorCode::VersionMismatch, 0, None))?;
    }

    // Decode the GET_CERTIFICATE request payload
    let req = GetCertificateReq::decode(req_payload).map_err(|_| {
        ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None)
    })?;

    let slot_id = req.slot_id.slot_id();
    if slot_id >= MAX_CERT_SLOTS_SUPPORTED {
        Err(ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None))?;
    }

    // Check if the slot is provisioned. Otherwise, return an InvalidRequest error.
    let slot_mask = 1 << slot_id;
    let (_, provisioned_slot_mask) = cert_slot_mask(ctx.device_certs_store);

    if provisioned_slot_mask & slot_mask == 0 {
        Err(ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None))?;
    }

    let mut offset = req.offset;
    let mut length = req.length;

    // When SlotSizeRequested=1b in the GET_CERTIFICATE request, the Responder shall return
    // the number of bytes available for certificate chain storage in the RemainderLength field of the response.
    if connection_version >= SpdmVersion::V13 && req.param2.slot_size_requested() != 0 {
        offset = 0;
        length = 0;
    }

    // Reset the transcript context
    ctx.reset_transcript_via_req_code(ReqRespCode::GetCertificate);

    // Append the request to the M1 transcript
    ctx.append_message_to_transcript(req_payload, TranscriptContext::M1)?;

    Ok((slot_id, offset, length))
}

pub(crate) fn handle_get_certificate<'a>(
    ctx: &mut SpdmContext<'a>,
    spdm_hdr: SpdmMsgHdr,
    req_payload: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    // Validate the state
    if ctx.state.connection_info.state() < ConnectionState::AlgorithmsNegotiated {
        Err(ctx.generate_error_response(req_payload, ErrorCode::UnexpectedRequest, 0, None))?;
    }

    // Check if the certificate capability is supported.
    if ctx.local_capabilities.flags.cert_cap() == 0 {
        Err(ctx.generate_error_response(req_payload, ErrorCode::UnsupportedRequest, 0, None))?;
    }

    // Process the GET_CERTIFICATE request
    let (slot_id, offset, length) = process_get_certificate(ctx, spdm_hdr, req_payload)?;

    // Generate the CERTIFICATE response
    ctx.prepare_response_buffer(req_payload)?;
    generate_certificate_response(
        ctx,
        // connection_version,
        slot_id,
        offset,
        length,
        req_payload,
    )?;

    // Set the connection state to AfterCertificate
    if ctx.state.connection_info.state() < ConnectionState::AfterCertificate {
        ctx.state
            .connection_info
            .set_state(ConnectionState::AfterCertificate);
    }

    Ok(())
}
