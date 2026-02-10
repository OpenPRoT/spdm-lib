// Licensed under the Apache-2.0 license

use crate::{
    codec::{Codec, MessageBuf},
    commands::algorithms::{AlgStructure, AlgorithmsResp, ExtendedAlgo, NegotiateAlgorithmsReq},
    commands::error_rsp::ErrorCode,
    context::SpdmContext,
    error::{CommandError, CommandResult},
    protocol::{DeviceAlgorithms, SpdmMsgHdr},
};

/// Parse and handle the NEGOTIATE_ALGORITHMS response from the Responder.
pub(crate) fn handle_algorithms_response<'a>(
    ctx: &mut SpdmContext<'a>,
    resp_header: SpdmMsgHdr,
    resp: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    let version = resp_header
        .version()
        .map_err(|_| (true, CommandError::UnsupportedRequest))?;

    let req_resp_code = resp_header
        .req_resp_code()
        .map_err(|_| (true, CommandError::UnsupportedRequest))?;

    if version != ctx.state.connection_info.version_number() {
        return Err((true, CommandError::UnsupportedRequest));
    }
    if req_resp_code != crate::protocol::ReqRespCode::Algorithms {
        return Err((true, CommandError::UnsupportedRequest));
    }

    let algo_resp: AlgorithmsResp =
        AlgorithmsResp::decode(resp).map_err(|e| (true, CommandError::Codec(e)))?;

    // Responder MUST set all algorithm fields to non-zero values, otherwise the requester MUST return an error with code SPDM_ERROR_CODE_REQUEST_RESYNCH.
    if algo_resp.measurement_hash_algo.0 == 0
        || algo_resp.base_asym_sel.0 == 0
        || algo_resp.base_hash_sel.0 == 0
    {
        return Err((true, CommandError::ErrorCode(ErrorCode::RequestResynch)));
    }

    // Thus, no more than one bit shall be set
    if algo_resp.measurement_specification_sel.0.count_ones() > 1 {
        return Err((true, CommandError::ErrorCode(ErrorCode::InvalidPolicy)));
    }

    // Thus, no more than one bit shall be set for the opaque data format.
    if algo_resp.other_params_selection.opaque_data_fmt0() == 1
        && algo_resp.other_params_selection.opaque_data_fmt1() == 1
    {
        return Err((true, CommandError::ErrorCode(ErrorCode::InvalidPolicy)));
    }

    let cap = ctx
        .state
        .connection_info
        .peer_capabilities()
        .flags
        .meas_cap();

    // If the Responder supports measurements ( MEAS_CAP=01b or MEAS_CAP=10b in its
    // CAPABILITIES response) and if MeasurementSpecificationSel is non-zero,
    // then exactly one bit in this bit field shall be set.  Otherwise, the Responder
    // shall set this field to 0.
    if cap != 0
        && algo_resp.measurement_specification_sel.0 != 0
        && algo_resp.measurement_specification_sel.0.count_ones() > 1
    {
        return Err((true, CommandError::ErrorCode(ErrorCode::InvalidPolicy)));
    }

    // If the Responder supports measurements in its CAPABILITIES response) and if
    // MeasurementSpecificationSel is non-zero, then exactly one bit in this bit
    // field shall be set. Otherwise, the Responder shall set this field to 0
    if (cap == 0b01 || cap == 0b10) && algo_resp.measurement_specification_sel.0 != 0 {
        if algo_resp.measurement_specification_sel.0.count_ones() > 1 {
            return Err((true, CommandError::ErrorCode(ErrorCode::InvalidPolicy)));
        }
    } else if algo_resp.measurement_specification_sel.0 != 0 {
        return Err((true, CommandError::ErrorCode(ErrorCode::InvalidPolicy)));
    }

    // TODO:  If the Responder does not support any request/response pair that
    // requires hashing operations, this value shall be set to zero. The Responder
    // shall set no more than one bit.

    let peer_device_algorithms = DeviceAlgorithms {
        measurement_spec: algo_resp.measurement_specification_sel,
        other_param_support: algo_resp.other_params_selection,
        base_asym_algo: algo_resp.base_asym_sel,
        base_hash_algo: algo_resp.base_hash_sel,
        mel_specification: algo_resp.mel_specification_sel,
        ..Default::default()
    };

    ctx.state
        .connection_info
        .set_peer_algorithms(peer_device_algorithms);

    // The spec defines this is A' elem of {0, 1}
    // TODO: add them to state?
    let _ext_asym_alog = if algo_resp.ext_asym_sel_count == 1 {
        Some(ExtendedAlgo::decode(resp).map_err(|e| (true, CommandError::Codec(e)))?)
    } else {
        None
    };

    // The spec defines this is E' elem of {0, 1}
    // TODO: add them to state?
    let _ext_hash_algo = if algo_resp.ext_hash_sel_count == 1 {
        Some(ExtendedAlgo::decode(resp).map_err(|e| (true, CommandError::Codec(e)))?)
    } else {
        None
    };

    for _ in 0..algo_resp.num_alg_struct_tables {
        let alg_struct = AlgStructure::decode(resp).map_err(|e| (true, CommandError::Codec(e)))?;

        // For each struct table, we need to decode the variable length fields.
        for _ in 0..alg_struct.ext_alg_count() {
            let _ext_algo =
                ExtendedAlgo::decode(resp).map_err(|e| (true, CommandError::Codec(e)))?;
        }
    }

    ctx.state
        .connection_info
        .set_state(crate::state::ConnectionState::AlgorithmsNegotiated);

    Ok(())
}

/// Generate the NEGOTIATE_ALGORITHMS request with all the contexts local information.
///
/// # Arguments
///
/// - `ctx` - The SPDM context containing local algorithm information.
/// - `req_buf` - The message buffer to encode the request into.
/// - `ext_asym` - Optional slice of extended asymmetric algorithm types.
/// - `ext_hash` - Optional slice of extended hash algorithm types.
/// - `req_alg_struct` - The AlgStructure variable fields.
/// - `alg_external` - Optional extended algorithm structure.
///
/// # Returns
///
/// - `Ok(())` on success.
/// - [CommandError] on failure.
///
/// # References
/// - See libspdm/library/spdm_requester_lib/libspdm_req_negotiate_algorithms.c for reference implementation.
/// - Note: the `spdm_message_header_t` has param1 and param2 fields used for various purposes.
/// - Note: see spdm_responder_test_3_algorithms.c
pub fn generate_negotiate_algorithms_request<'a>(
    ctx: &mut SpdmContext<'a>,
    req_buf: &mut MessageBuf<'a>,
    ext_asym: Option<&'a [ExtendedAlgo]>,
    ext_hash: Option<&'a [ExtendedAlgo]>,
    req_alg_struct: AlgStructure,
    alg_external: Option<&'a [ExtendedAlgo]>, // req_alg_struct.AlgCount.ExtAlgCount many
) -> CommandResult<()> {
    let local_algorithms = &ctx.local_algorithms.device_algorithms;
    let local_state = &ctx.state.connection_info;

    let ext_asym_count = match ext_asym {
        Some(ext) => ext.len() as u8,
        None => 0,
    };
    let ext_hash_count = match ext_hash {
        Some(ext) => ext.len() as u8,
        None => 0,
    };

    // Generate base structure **without** the variable length structures
    let negotiate_algorithms_req = NegotiateAlgorithmsReq::new(
        req_alg_struct.ext_alg_count(),
        0, // param2
        local_algorithms.measurement_spec,
        local_algorithms.other_param_support,
        local_algorithms.base_asym_algo,
        local_algorithms.base_hash_algo,
        ext_asym_count,
        ext_hash_count,
        local_algorithms.mel_specification,
    )
    .map_err(|_| (false, CommandError::UnsupportedRequest))?;

    // Verify that the extended algorithm counts are valid
    negotiate_algorithms_req
        .validate_total_ext_alg_count(
            local_state.version_number(),
            ext_asym_count + ext_hash_count,
        )
        .map_err(|_| (false, CommandError::UnsupportedRequest))?;

    if (negotiate_algorithms_req.min_req_len() as usize) > req_buf.capacity() {
        return Err((false, CommandError::BufferTooSmall));
    }

    // Message Assembly
    // 1. Create Header
    // 2. Encode base NegotiateAlgorithmsReq
    // 3. Encode Variable length fields
    // 3.1 Encode ExtAsym (if present)
    // 3.2 Encode ExtHash (if present)
    // 3.3 Encode ExtAlgo (if present)
    // 3.4 Encode ExtendedAlgorithms (if present)

    // 1.
    SpdmMsgHdr::new(
        ctx.state.connection_info.version_number(),
        crate::protocol::ReqRespCode::NegotiateAlgorithms,
    )
    .encode(req_buf)
    .map_err(|e| (false, CommandError::Codec(e)))?;

    // 2.
    // This encoding does *NOT* yet contain the variable fields.
    negotiate_algorithms_req
        .encode(req_buf)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    // Add variable fields if any. As defined by the size of the struct and the
    // PLMD spec, we know that the offset starts at 32 bytes.
    // The constructor of NegotiateAlgorithmsReq sets the structs length correctly.

    // 3.1
    if let Some(ext_asym_algos) = ext_asym {
        for ext in ext_asym_algos {
            ext.encode(req_buf)
                .map_err(|e| (false, CommandError::Codec(e)))?;
        }
    }

    // 3.2
    if let Some(ext_hash_algos) = ext_hash {
        for ext in ext_hash_algos {
            ext.encode(req_buf)
                .map_err(|e| (false, CommandError::Codec(e)))?;
        }
    }

    // 3.2
    if req_alg_struct.fixed_alg_count() != 0 && !req_alg_struct.is_multiple() {
        return Err((false, CommandError::UnsupportedRequest));
    }

    // If this is 1, we have an additional extended algorithm structure to add.
    if negotiate_algorithms_req.num_alg_struct_tables > 0 {
        // 3.3
        req_alg_struct
            .encode(req_buf)
            .map_err(|e| (false, CommandError::Codec(e)))?;

        // 3.4
        if let Some(extended_algos) = alg_external {
            for ext in extended_algos {
                ext.encode(req_buf)
                    .map_err(|e| (false, CommandError::Codec(e)))?;
            }
        } else {
            // If ext_alg_count > 0, we must have the extended algorithm structure.
            return Err((false, CommandError::UnsupportedRequest));
        }
    }

    ctx.append_message_to_transcript(req_buf, crate::transcript::TranscriptContext::Vca)
}

#[cfg(test)]
mod tests {
    // use crate::test::MockResources;

    // use super::*;

    #[ignore]
    #[test]
    pub fn test_parse_negotiate_algorithms() {
        todo!();
    }
}
