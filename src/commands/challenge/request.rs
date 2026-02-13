use crate::cert_store::{CertStoreError, CertStoreResult, PeerCertStore, SpdmCertStore};
// Licensed under the Apache-2.0 license
use crate::codec::{Codec, CommonCodec, MessageBuf};
use crate::commands::challenge::{
    ChallengeAuthRspBase, ChallengeReq, MeasurementSummaryHashType, CONTEXT_LEN, NONCE_LEN,
    OPAQUE_DATA_MAX,
};
use crate::context::SpdmContext;
use crate::error::{CommandError, CommandResult, PlatformError};
use crate::protocol::*;
use crate::state::ConnectionState;
use crate::transcript::TranscriptContext;

/// Generates an SPDM `CHALLENGE` request message.
///
/// Constructs a [`ChallengeReq`] with the given parameters and encodes it into `buf`
/// as an SPDM message, using the negotiated version from the connection state.
///
/// # Arguments
///
/// * `ctx` - The SPDM context holding connection state (used to obtain the negotiated version).
/// * `buf` - The output buffer into which the encoded request message is written.
/// * `slot_id` - Slot number (`0..=7`) of the Responder certificate chain to use for
///   authentication, or `0xFF` if the public key was provisioned in a trusted environment.
/// * `measurement_hash_type` - The type of measurement summary hash requested from the
///   Responder (`None`, `Tcb`, or `All`).
/// * `nonce` - A 32-byte random value chosen by the Requester for freshness.
/// * `context` - Optional 8-byte application-specific context. Defaults to all zeros when
///   `None`.
///
/// # Errors
///
/// Returns a [`CommandError`] if encoding the header or request body into the buffer fails.
pub fn generate_challenge_request<'a>(
    ctx: &mut SpdmContext<'a>,
    message_buffer: &mut MessageBuf<'a>,
    slot_id: u8,
    measurement_hash_type: MeasurementSummaryHashType,
    nonce: [u8; NONCE_LEN],
    context: Option<[u8; CONTEXT_LEN]>,
) -> CommandResult<()> {
    SpdmMsgHdr::new(
        ctx.state.connection_info.version_number(),
        ReqRespCode::Challenge,
    )
    .encode(message_buffer)
    .map_err(|e| (false, CommandError::Codec(e)))?;

    ChallengeReq::new(slot_id, measurement_hash_type.clone(), nonce, context)
        .encode(message_buffer)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    ctx.state
        .peer_cert_store
        .as_mut()
        .unwrap()
        .set_requested_msh_type(slot_id, measurement_hash_type.clone())
        .map_err(|e| (false, CommandError::CertStore(e)))?;

    // Message M1.C = Concatenate(CHALLENGE, CHALLENGE_AUTH without signature)
    ctx.append_message_to_transcript(message_buffer, TranscriptContext::M1)
}

/// Handle the challenge response and apppend the message to the transcript context.
/// See [crate::transcript::TranscriptContext::M1] for details on the transcript context used.
///
/// # Warning
/// Contrary to the other messages, `CHALLENGE_AUTH` is **NOT** entirely parsed here.
/// The variable-length field `Signature` has to be parsed in the application. This has two reasons:
/// 1. The generate the transcript hash, the entire message, **except the signature!**
///  has to be appended to the transcript context before signature verification, as required by SPDM 1.2 and later.
/// 2. The signature verification has to be done in the application, as it requires
/// access to the public key from the responder's certificate chain (which we already verified) and the transcript hash.
pub fn handle_challenge_auth_response<'a>(
    ctx: &mut SpdmContext<'a>,
    spdm_hdr: SpdmMsgHdr,
    resp_payload: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    if ctx.state.connection_info.state() < ConnectionState::AlgorithmsNegotiated {
        return Err((true, CommandError::UnsupportedRequest));
    }

    if spdm_hdr.version().unwrap() != ctx.connection_info().version_number() {
        return Err((true, CommandError::InvalidState));
    }

    let challenge_auth_resp_base: ChallengeAuthRspBase =
        ChallengeAuthRspBase::decode(resp_payload).map_err(|e| (true, CommandError::Codec(e)))?;

    // Parse the variable length fields:
    // - MeasurementSummaryHash
    // - OpaqueDataLength
    // - OpaqueData
    // - RequesterContext
    // - Signature

    // - MeasurementSummaryHash
    // If the Responder does not support measurements ( MEAS_CAP=00b in its CAPABILITIES response)
    // or if the requested Param2 = 0x0 , this field shall be absent.

    let param2 = ctx
        .state
        .peer_cert_store
        .as_mut()
        .unwrap()
        .get_requested_msh_type(0)
        .map_err(|e| (true, CommandError::CertStore(e)))?;

    let hash_size_bytes = ctx.hash.algo().hash_size();
    let mut hash = [0u8; SHA384_HASH_SIZE];

    if challenge_auth_resp_base.slot_mask != 0
        && ctx.connection_info().peer_capabilities().flags.meas_cap() != 0
    {
        // If the Responder supports both raw bit stream and digest representations
        // for a given measurement index, the Responder shall use the digest form.
        match param2 {
            MeasurementSummaryHashType::None => {}

            // The combined hash of measurements of all measurable components
            // considered to be in the TCB required to generate this response
            MeasurementSummaryHashType::Tcb | MeasurementSummaryHashType::All => {
                hash[..hash_size_bytes].copy_from_slice(
                    resp_payload
                        .data(hash_size_bytes)
                        .map_err(|e| (true, CommandError::Codec(e)))?,
                );

                resp_payload
                    .pull_data(hash_size_bytes)
                    .map_err(|e| (true, CommandError::Codec(e)))?;
            }
        }
    }

    let opaque_data_size = {
        let opaque_data_slice = resp_payload
            .data(2)
            .map_err(|e| (true, CommandError::Codec(e)))?;
        u16::from_le_bytes([opaque_data_slice[0], opaque_data_slice[1]])
    };

    resp_payload
        .pull_data(2)
        .map_err(|e| (true, CommandError::Codec(e)))?;

    // The value should not be greater than 1024 bytes
    // Opaque data size 64939 exceeds maximum allowed 1024
    if opaque_data_size > OPAQUE_DATA_MAX as u16 {
        return Err((true, CommandError::BufferTooSmall));
    }

    // The Responder can include Responder-specific information and/or information
    // that its transport defines. If present, this field shall conform to the selected
    // opaque data format in [OtherParamsSelection].
    if opaque_data_size > 0 {
        let _opaque_data = resp_payload
            .data(opaque_data_size as usize)
            .map_err(|e| (true, CommandError::Codec(e)))?;
        resp_payload
            .pull_data(opaque_data_size as usize)
            .map_err(|e| (true, CommandError::Codec(e)))?;
    }

    // This field shall be identical to the Context field of the corresponding request message.
    // TODO: compare it to the context we sent.
    // See: src/protocol/common.rs [RequesterContext]
    let _requester_context = resp_payload
        .data(8)
        .map_err(|e| (true, CommandError::Codec(e)))?;

    resp_payload
        .pull_data(8)
        .map_err(|e| (true, CommandError::Codec(e)))?;

    // Append the entire message (excluding the signature) to the transcript before signature verification, as required by SPDM 1.2 and later.
    ctx.append_message_to_transcript(resp_payload, TranscriptContext::M1)
}
