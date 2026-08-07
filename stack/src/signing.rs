// Licensed under the Apache-2.0 license

//! Shared SPDM signing-context + TBS-hash helpers (DSP0274 §15).
//!
//! Both the responder (when signing CHALLENGE_AUTH / MEASUREMENTS) and the
//! requester (when verifying those signatures) must use byte-identical
//! signing-context bytes and the same TBS computation, or the signature will not
//! match. This module is the single source of truth for both roles.
//!
//! The signing context is a fixed 100-byte buffer:
//! `4 × "dmtf-spdm-v<M>.<N>.*"` (64-byte prefix) followed by a left-zero-padded
//! operation string (36-byte context region). TBS = `SHA-384(context ‖ hash)`.

use spdm_codec::{
    SpdmVersion, SHA384_HASH_SIZE, SPDM_CONTEXT_LEN, SPDM_PREFIX_LEN, SPDM_SIGNING_CONTEXT_LEN,
};
use spdm_errors::PalResult;
use spdm_traits::{SpdmPalHash, SpdmPalHashAlgo, SpdmPalIo};

/// SPDM operation string for CHALLENGE_AUTH signing (DSP0274 §15.6).
pub const OP_CHALLENGE_AUTH: &[u8] = b"responder-challenge_auth signing";
/// SPDM operation string for MEASUREMENTS signing.
pub const OP_MEASUREMENTS: &[u8] = b"responder-measurements signing";

/// Builds the 100-byte SPDM signing context for `version` and `op`.
///
/// `op` must be one of the `OP_*` constants (≤ [`SPDM_CONTEXT_LEN`] bytes).
pub fn build_signing_context(
    version: SpdmVersion,
    op: &[u8],
) -> [u8; SPDM_SIGNING_CONTEXT_LEN] {
    let mut ctx = [0u8; SPDM_SIGNING_CONTEXT_LEN];
    let base = b"dmtf-spdm-v";
    let ver: &[u8; 5] = match version {
        SpdmVersion::V10 => b"1.0.*",
        SpdmVersion::V11 => b"1.1.*",
        SpdmVersion::V12 => b"1.2.*",
        SpdmVersion::V13 => b"1.3.*",
    };
    let mut pos = 0;
    for _ in 0..4 {
        ctx[pos..pos + base.len()].copy_from_slice(base);
        pos += base.len();
        ctx[pos..pos + ver.len()].copy_from_slice(ver);
        pos += ver.len();
    }
    // Operation context: left zero-padded, string flush-right in the region.
    let pad = SPDM_CONTEXT_LEN.saturating_sub(op.len());
    let start = SPDM_PREFIX_LEN + pad;
    if start + op.len() <= ctx.len() {
        ctx[start..start + op.len()].copy_from_slice(op);
    }
    ctx
}

/// Computes the TBS digest `SHA-384(signing_context ‖ message_hash)` using the
/// supplied hash backend.
pub fn compute_tbs_hash<H: SpdmPalHash>(
    hash: &H,
    io: &impl SpdmPalIo,
    signing_ctx: &[u8; SPDM_SIGNING_CONTEXT_LEN],
    message_hash: &[u8; SHA384_HASH_SIZE],
) -> PalResult<[u8; SHA384_HASH_SIZE]> {
    let mut state = hash.hash_init(io, SpdmPalHashAlgo::Sha384, signing_ctx)?;
    hash.hash_update(io, &mut state, message_hash)?;
    let mut tbs = [0u8; SHA384_HASH_SIZE];
    hash.hash_finish(io, &mut state, &mut tbs)?;
    Ok(tbs)
}
