// Licensed under the Apache-2.0 license

use crate::cert_store::PeerCertStore;
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
        return Err((true, CommandError::UnsupportedRequest));
    }

    let con_version = ctx.state.connection_info.version_number();
    let version = match spdm_hdr.version() {
        Ok(version) if version == con_version => version,
        _ => return Err((false, CommandError::InvalidResponse)),
    };

    let digests_resp_common =
        GetDigestsRespCommon::decode(resp_payload).map_err(|e| (true, CommandError::Codec(e)))?;

    let peer_cert_store = ctx
        .state
        .peer_cert_store
        .as_mut()
        .ok_or((true, CommandError::InvalidResponse))?;

    peer_cert_store
        .set_supported_slots(digests_resp_common.supported_slot_mask)
        .map_err(|e| (true, CommandError::CertStore(e)))?;

    for b in 0..digests_resp_common.supported_slot_mask.count_ones() {
        if (digests_resp_common.supported_slot_mask & (1 << b)) == 1 {}
    }

    peer_cert_store
        .set_provisioned_slots(digests_resp_common.provisioned_slot_mask)
        .map_err(|e| (true, CommandError::CertStore(e)))?;

    let slot_n = digests_resp_common.provisioned_slot_mask.count_ones() as usize;
    if slot_n == 0 {
        return Err((true, CommandError::InvalidResponse));
    }

    // For now that should only be '0'.
    for slot_id in 0..slot_n {
        if resp_payload.data_len() < SHA384_HASH_SIZE {
            return Err((true, CommandError::BufferTooSmall));
        }

        let digest = resp_payload
            .data(SHA384_HASH_SIZE)
            .map_err(|e| (true, CommandError::Codec(e)))?;

        peer_cert_store
            .set_digest(slot_id as u8, digest)
            .map_err(|e| (true, CommandError::CertStore(e)))?;

        resp_payload
            .pull_data(SHA384_HASH_SIZE)
            .map_err(|e| (true, CommandError::Codec(e)))?;
    }

    if version >= SpdmVersion::V13 && ctx.state.connection_info.multi_key_conn_rsp() {
        for slot_id in 0..slot_n {
            if resp_payload.data_len() < size_of::<u8>() {
                return Err((true, CommandError::InvalidResponse));
            }

            let key_pair_id = resp_payload
                .data(size_of::<u8>())
                .map_err(|e| (true, CommandError::Codec(e)))?[0];

            peer_cert_store
                .set_keypair(slot_id as u8, key_pair_id)
                .map_err(|e| (true, CommandError::CertStore(e)))?;

            resp_payload
                .pull_data(size_of::<u8>())
                .map_err(|e| (true, CommandError::Codec(e)))?;
        }

        for slot_id in 0..slot_n {
            if resp_payload.data_len() < size_of::<CertificateInfo>() {
                return Err((true, CommandError::InvalidResponse));
            }

            let data = resp_payload
                .data(size_of::<CertificateInfo>())
                .map_err(|e| (true, CommandError::Codec(e)))?;

            let cert_info = CertificateInfo::read_from_bytes(data)
                .map_err(|_| (true, CommandError::InvalidResponse))?;

            peer_cert_store
                .set_cert_info(slot_id as u8, cert_info)
                .map_err(|e| (true, CommandError::CertStore(e)))?;

            resp_payload
                .pull_data(size_of::<CertificateInfo>())
                .map_err(|e| (true, CommandError::Codec(e)))?;
        }

        for slot_id in 0..slot_n {
            if resp_payload.data_len() < size_of::<KeyUsageMask>() {
                return Err((true, CommandError::InvalidResponse));
            }

            let data = resp_payload
                .data(size_of::<KeyUsageMask>())
                .map_err(|e| (true, CommandError::Codec(e)))?;

            let key_usage_mask = KeyUsageMask::read_from_bytes(data)
                .map_err(|_| (true, CommandError::InvalidResponse))?;

            peer_cert_store
                .set_key_usage_mask(slot_id as u8, key_usage_mask)
                .map_err(|e| (true, CommandError::CertStore(e)))?;

            resp_payload
                .pull_data(size_of::<KeyUsageMask>())
                .map_err(|e| (true, CommandError::Codec(e)))?;
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
