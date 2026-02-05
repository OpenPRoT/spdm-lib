// Licensed under the Apache-2.0 license

use crate::codec::Codec;
use crate::context::SpdmContext;
use crate::error::{CommandError, CommandResult};
use crate::protocol::certs::{CertificateInfo, KeyUsageMask};
use crate::protocol::{SpdmMsgHdr, SpdmVersion, SHA384_HASH_SIZE};
use crate::state::ConnectionState;
use crate::transcript::TranscriptContext;
use zerocopy::FromBytes;

use super::*;

pub fn generate_digest_request(
    ctx: &mut SpdmContext,
    message_buffer: &mut MessageBuf,
) -> CommandResult<()> {
    SpdmMsgHdr::new(
        ctx.state.connection_info.version_number(),
        crate::protocol::ReqRespCode::GetDigests,
    )
    .encode(message_buffer)
    .map_err(|e| (false, CommandError::Codec(e)))?;

    let payload = GetDigestsReq::default();
    payload
        .encode(message_buffer)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    ctx.append_message_to_transcript(message_buffer, crate::transcript::TranscriptContext::L1)
}

pub(crate) fn handle_digests_response<'a>(
    ctx: &mut SpdmContext<'a>,
    spdm_hdr: SpdmMsgHdr,
    resp_payload: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    if ctx.state.connection_info.state() < ConnectionState::AlgorithmsNegotiated {
        return Err((false, CommandError::UnsupportedRequest));
    }

    let con_version = ctx.state.connection_info.version_number();
    let version = match spdm_hdr.version() {
        Ok(version) if version == con_version => version,
        _ => return Err((false, CommandError::InvalidResponse)),
    };

    let digests_resp_common =
        GetDigestsRespCommon::decode(resp_payload).map_err(|e| (false, CommandError::Codec(e)))?;

    // ATM we do not care, since we only support slot 0.
    // Also this is a hacky way of representing the the remote slots
    let _supported_slot_mask = digests_resp_common.supported_slot_mask;
    let provisioned_slot_mask = digests_resp_common.provisioned_slot_mask;

    let slot_n = provisioned_slot_mask.count_ones() as usize;
    if slot_n == 0 {
        return Err((false, CommandError::InvalidResponse));
    }

    for _slot_id in 0..slot_n {
        if resp_payload.data_len() < SHA384_HASH_SIZE {
            return Err((false, CommandError::InvalidResponse));
        }

        let _digest = resp_payload
            .data(SHA384_HASH_SIZE)
            .map_err(|e| (false, CommandError::Codec(e)))?;

        // TODO: Store the digest in context for later verification

        resp_payload
            .pull_data(SHA384_HASH_SIZE)
            .map_err(|e| (false, CommandError::Codec(e)))?;
    }

    if version >= SpdmVersion::V13 && ctx.state.connection_info.multi_key_conn_rsp() {
        for _slot_id in 0..slot_n {
            if resp_payload.data_len() < size_of::<u8>() {
                return Err((false, CommandError::InvalidResponse));
            }
            let _key_pair_id = resp_payload
                .data(size_of::<u8>())
                .map_err(|e| (false, CommandError::Codec(e)))?[0];

            // TODO: Store key_pair_id in context

            resp_payload
                .pull_data(size_of::<u8>())
                .map_err(|e| (false, CommandError::Codec(e)))?;
        }

        for _slot_id in 0..slot_n {
            if resp_payload.data_len() < size_of::<CertificateInfo>() {
                return Err((false, CommandError::InvalidResponse));
            }
            let data = resp_payload
                .data(size_of::<CertificateInfo>())
                .map_err(|e| (false, CommandError::Codec(e)))?;
            let _cert_info = CertificateInfo::read_from_bytes(data)
                .map_err(|_| (false, CommandError::InvalidResponse))?;

            // TODO: Store cert_info in context

            resp_payload
                .pull_data(size_of::<CertificateInfo>())
                .map_err(|e| (false, CommandError::Codec(e)))?;
        }

        // Decode KeyUsageMasks (one per slot)
        for _slot_id in 0..slot_n {
            if resp_payload.data_len() < size_of::<KeyUsageMask>() {
                return Err((false, CommandError::InvalidResponse));
            }
            let data = resp_payload
                .data(size_of::<KeyUsageMask>())
                .map_err(|e| (false, CommandError::Codec(e)))?;
            let _key_usage_mask = KeyUsageMask::read_from_bytes(data)
                .map_err(|_| (false, CommandError::InvalidResponse))?;

            // TODO: Store key_usage_mask in context

            resp_payload
                .pull_data(size_of::<KeyUsageMask>())
                .map_err(|e| (false, CommandError::Codec(e)))?;
        }
    }

    if ctx.state.connection_info.state() < ConnectionState::AfterDigest {
        ctx.state
            .connection_info
            .set_state(ConnectionState::AfterDigest);
    }

    ctx.append_message_to_transcript(resp_payload, TranscriptContext::L1)
}

#[cfg(test)]
pub mod tests {

    #[test]
    fn test_generate_digest_request() {
        todo!();
    }
}
