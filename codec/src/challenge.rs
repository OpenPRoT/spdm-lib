// Licensed under the Apache-2.0 license

//! CHALLENGE / CHALLENGE_AUTH wire types.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    ReqRespCode, RequestBody, ResponseBody, WireError, WireReader, WireWriter,
    ECC_P384_SIGNATURE_SIZE, REQUESTER_CONTEXT_LEN, SHA384_HASH_SIZE, SPDM_NONCE_LEN,
};

// ---- Request ---------------------------------------------------------------

/// CHALLENGE request body (after SPDM header).
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug)]
#[repr(C)]
pub struct ChallengeReqBody {
    pub slot_id: u8,
    pub meas_summary_hash_type: u8,
    pub nonce: [u8; SPDM_NONCE_LEN],
}

const _: () = assert!(core::mem::size_of::<ChallengeReqBody>() == 34);

// ---- Response builder ------------------------------------------------------

/// CHALLENGE_AUTH response builder.
pub struct ChallengeAuthRsp<'a> {
    pub slot_id: u8,
    pub cert_chain_hash: &'a [u8; SHA384_HASH_SIZE],
    pub nonce: &'a [u8; SPDM_NONCE_LEN],
    /// If Some, a 48-byte measurement summary hash is included.
    pub meas_summary_hash: Option<&'a [u8; SHA384_HASH_SIZE]>,
    pub opaque_len: u16,
    pub requester_context: Option<&'a [u8; REQUESTER_CONTEXT_LEN]>,
    pub signature: &'a [u8],
}

impl ResponseBody for ChallengeAuthRsp<'_> {
    fn response_code(&self) -> ReqRespCode {
        ReqRespCode::CHALLENGE_AUTH
    }

    fn body_size(&self) -> usize {
        1 + 1
            + SHA384_HASH_SIZE
            + SPDM_NONCE_LEN
            + self.meas_hash_len()
            + 2
            + self.requester_context_len()
            + self.signature.len()
    }

    fn encode_body(&self, w: &mut WireWriter<'_>) -> Result<(), WireError> {
        w.write_bytes(&[self.slot_id & 0x0F])?;
        w.write_bytes(&[1u8 << self.slot_id])?;
        w.write_bytes(self.cert_chain_hash)?;
        w.write_bytes(self.nonce)?;
        if let Some(mh) = self.meas_summary_hash {
            w.write_bytes(mh)?;
        }
        w.write_bytes(&self.opaque_len.to_le_bytes())?;
        if let Some(ctx) = self.requester_context {
            w.write_bytes(ctx)?;
        }
        w.write_bytes(self.signature)?;
        Ok(())
    }
}

impl ChallengeAuthRsp<'_> {
    fn requester_context_len(&self) -> usize {
        if self.requester_context.is_some() {
            REQUESTER_CONTEXT_LEN
        } else {
            0
        }
    }

    fn meas_hash_len(&self) -> usize {
        if self.meas_summary_hash.is_some() {
            SHA384_HASH_SIZE
        } else {
            0
        }
    }
}

// ---- CHALLENGE request builder (requester side) ----------------------------

impl ChallengeReqBody {
    /// Construct a CHALLENGE request body.
    pub fn new(slot_id: u8, meas_summary_hash_type: u8, nonce: [u8; SPDM_NONCE_LEN]) -> Self {
        Self {
            slot_id,
            meas_summary_hash_type,
            nonce,
        }
    }
}

/// Builder for a CHALLENGE request.
///
/// V1.3+ appends an 8-byte RequesterContext after the fixed body; set
/// `requester_context` to `Some` for V1.3+.
pub struct ChallengeReq {
    pub slot_id: u8,
    pub meas_summary_hash_type: u8,
    pub nonce: [u8; SPDM_NONCE_LEN],
    pub requester_context: Option<[u8; REQUESTER_CONTEXT_LEN]>,
}

impl RequestBody for ChallengeReq {
    const REQUEST_CODE: ReqRespCode = ReqRespCode::CHALLENGE;

    fn body_size(&self) -> usize {
        core::mem::size_of::<ChallengeReqBody>()
            + if self.requester_context.is_some() {
                REQUESTER_CONTEXT_LEN
            } else {
                0
            }
    }

    fn encode_body(&self, w: &mut WireWriter<'_>) -> Result<(), WireError> {
        w.write(&ChallengeReqBody::new(
            self.slot_id,
            self.meas_summary_hash_type,
            self.nonce,
        ))?;
        if let Some(ctx) = &self.requester_context {
            w.write_bytes(ctx)?;
        }
        Ok(())
    }
}

/// A parsed CHALLENGE_AUTH response.
///
/// `no_sig_prefix` is the response body bytes *excluding* the trailing
/// signature — the exact bytes the requester must append to the M1 transcript
/// before verifying (DSP0274 §10.9: transcript covers the message without its
/// signature).
#[derive(Clone, Copy)]
pub struct ParsedChallengeAuth<'a> {
    pub slot_id: u8,
    pub cert_chain_hash: &'a [u8],
    pub nonce: &'a [u8],
    /// Body bytes excluding the trailing signature.
    pub no_sig_prefix: &'a [u8],
    /// Trailing signature (fixed 96-byte P-384 r‖s).
    pub signature: &'a [u8],
}

impl<'a> ParsedChallengeAuth<'a> {
    /// Parse a CHALLENGE_AUTH response body (everything after the 2-byte SPDM
    /// header). `has_meas_summary` and `has_requester_context` describe the
    /// variable fields negotiated for this connection.
    pub fn parse(
        body: &'a [u8],
        has_meas_summary: bool,
        has_requester_context: bool,
    ) -> Result<Self, WireError> {
        // Fixed leading fields: slot(1) + slotmask(1) + cert_chain_hash(48)
        // + nonce(32) [+ meas_summary(48)] + opaque_len(2) [+ req_ctx(8)]
        // + signature(96).
        if body.len() < ECC_P384_SIGNATURE_SIZE {
            return Err(WireError);
        }
        let no_sig_len = body.len() - ECC_P384_SIGNATURE_SIZE;
        let no_sig_prefix = &body[..no_sig_len];
        let signature = &body[no_sig_len..];

        let mut r = WireReader::new(no_sig_prefix);
        let slot_id = r.take(1)?[0] & 0x0F;
        let _slot_mask = r.take(1)?;
        let cert_chain_hash = r.take(SHA384_HASH_SIZE)?;
        let nonce = r.take(SPDM_NONCE_LEN)?;
        if has_meas_summary {
            r.skip(SHA384_HASH_SIZE)?;
        }
        let opaque_len = u16::from_le_bytes(r.take(2)?.try_into().map_err(|_| WireError)?);
        r.skip(opaque_len as usize)?;
        if has_requester_context {
            r.skip(REQUESTER_CONTEXT_LEN)?;
        }

        Ok(Self {
            slot_id,
            cert_chain_hash,
            nonce,
            no_sig_prefix,
            signature,
        })
    }
}
