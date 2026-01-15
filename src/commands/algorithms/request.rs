// Licensed under the Apache-2.0 license

use crate::{
    codec::{Codec, MessageBuf},
    commands::algorithms::{AlgStructure, ExtendedAlgo, NegotiateAlgorithmsReq},
    context::SpdmContext,
    error::{CommandError, CommandResult, SpdmError},
    protocol::{
        BaseAsymAlgo, BaseAsymAlgoType, BaseHashAlgo, BaseHashAlgoType, MeasurementSpecification,
        OtherParamSupport, SpdmMsgHdr, SpdmVersion,
    },
};

/// Parse and handle the NEGOTIATE_ALGORITHMS response from the Responder.
pub fn handle_algorithms_response<'a>(
    ctx: &mut SpdmContext<'a>,
    resp_header: SpdmMsgHdr,
    resp: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    Ok(())
}

/// Generate the NEGOTIATE_ALGORITHMS request with all the contexts local information.
///
/// # Arguments
/// - `ctx` - The SPDM context containing local algorithm information.
/// - `req_buf` - The message buffer to encode the request into.
/// - `ext_asym` - Optional slice of extended asymmetric algorithm types.
/// - `ext_hash` - Optional slice of extended hash algorithm types.
/// - `ext_algo` - The AlgStructure variable fields.
/// - `ext_algo_ext` - Optional extended algorithm structure.
///
/// # Returns
/// - `Ok(())` on success.
/// - [CommandError] on failure.
pub fn generate_negotiate_algorithms_request<'a>(
    ctx: &mut SpdmContext<'a>,
    req_buf: &mut MessageBuf<'a>,
    ext_asym: Option<&'a [ExtendedAlgo]>,
    ext_hash: Option<&'a [ExtendedAlgo]>,
    ext_algo: &AlgStructure,
    ext_algo_ext: Option<ExtendedAlgo>,
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

    let negotiate_algorithms_req = NegotiateAlgorithmsReq::new(
        ext_algo.ext_alg_count() as u8,
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
    SpdmMsgHdr::new(
        ctx.state.connection_info.version_number(),
        crate::protocol::ReqRespCode::NegotiateAlgorithms,
    )
    .encode(req_buf)
    .map_err(|e| (false, CommandError::Codec(e)))?;

    // This encoding does *NOT* yet contain the variable fields.
    negotiate_algorithms_req
        .encode(req_buf)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    // Add variable fields if any. As defined by the size of the struct and the
    // PLMD spec, we know that the offset starts at 32 bytes.
    // The constructor of NegotiateAlgorithmsReq sets the structs length correctly.
    if let Some(ext_asym_algos) = ext_asym {
        for ext in ext_asym_algos {
            ext.encode(req_buf)
                .map_err(|e| (false, CommandError::Codec(e)))?;
        }
    }

    if let Some(ext_hash_algos) = ext_hash {
        for ext in ext_hash_algos {
            ext.encode(req_buf)
                .map_err(|e| (false, CommandError::Codec(e)))?;
        }
    }

    if ext_algo.fixed_alg_count() != 0 && !ext_algo.is_multiple() {
        return Err((false, CommandError::UnsupportedRequest));
    }

    // If this is 1, we have an additional extended algorithm structure to add.
    if negotiate_algorithms_req.num_alg_struct_tables > 0 {
        ext_algo
            .encode(req_buf)
            .map_err(|e| (false, CommandError::Codec(e)))?;

        if let Some(ext) = ext_algo_ext {
            ext.encode(req_buf)
                .map_err(|e| (false, CommandError::Codec(e)))?;
        } else {
            // If ext_alg_count > 0, we must have the extended algorithm structure.
            // TODO: fixup AlgStructure with downside of custom encode.
            return Err((false, CommandError::UnsupportedRequest));
        }
    }

    Ok(())
}
