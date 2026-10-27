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
        w.write_bytes(&[1u8.checked_shl(self.slot_id.into()).ok_or(WireError)?])?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SpdmVersion;

    const HASH: [u8; SHA384_HASH_SIZE] = [0xC1; SHA384_HASH_SIZE];
    const NONCE: [u8; SPDM_NONCE_LEN] = [0xD2; SPDM_NONCE_LEN];
    const MEAS: [u8; SHA384_HASH_SIZE] = [0xE3; SHA384_HASH_SIZE];
    const CTX: [u8; REQUESTER_CONTEXT_LEN] = [0xF4; REQUESTER_CONTEXT_LEN];
    const SIG: [u8; ECC_P384_SIGNATURE_SIZE] = [0x5A; ECC_P384_SIGNATURE_SIZE];

    // ---- CHALLENGE request -------------------------------------------------

    #[test]
    fn test_challenge_req_v12_encode() {
        let req = ChallengeReq {
            slot_id: 1,
            meas_summary_hash_type: 0x01, // TCB component measurement hash
            nonce: [0x11; SPDM_NONCE_LEN],
            requester_context: None,
        };
        // Body = SlotID (1) + MeasurementSummaryHashType (1) + Nonce (32) = 34.
        assert_eq!(req.body_size(), 34);
        // Wire = 2-byte common header + 34-byte body = 36 bytes.
        assert_eq!(req.encoded_size(), 36);

        let mut buf = [0xFFu8; 36];
        let mut w = WireWriter::new(&mut buf);
        req.encode_with_header(SpdmVersion::V12, &mut w).unwrap();

        assert_eq!(&buf[..4], &[0x12, 0x83, 0x01, 0x01]); // V1.2, CHALLENGE, slot, hash type
        assert_eq!(&buf[4..], &[0x11; 32]);
    }

    #[test]
    fn test_challenge_req_v13_with_requester_context() {
        let req = ChallengeReq {
            slot_id: 0,
            meas_summary_hash_type: 0xFF, // all measurements hash
            nonce: [0x22; SPDM_NONCE_LEN],
            requester_context: Some(CTX),
        };
        // Body = 34 fixed + 8 RequesterContext = 42; wire = 2 + 42 = 44 bytes.
        assert_eq!(req.body_size(), 42);
        let mut buf = [0u8; 44];
        let mut w = WireWriter::new(&mut buf);
        req.encode_with_header(SpdmVersion::V13, &mut w).unwrap();

        assert_eq!(&buf[..4], &[0x13, 0x83, 0x00, 0xFF]);
        assert_eq!(&buf[4..36], &[0x22; 32]);
        assert_eq!(&buf[36..], &CTX);
    }

    #[test]
    fn test_challenge_req_buffer_too_small() {
        let req = ChallengeReq {
            slot_id: 0,
            meas_summary_hash_type: 0,
            nonce: [0; SPDM_NONCE_LEN],
            requester_context: Some(CTX),
        };
        // Needs 44 bytes; 43 fails on the final context write.
        let mut buf = [0u8; 43];
        let mut w = WireWriter::new(&mut buf);
        assert!(req.encode_with_header(SpdmVersion::V13, &mut w).is_err());
    }

    #[test]
    fn test_challenge_req_body_decode() {
        let mut bytes = [0x77u8; 34];
        bytes[0] = 0x03; // slot
        bytes[1] = 0xFF; // hash type
        let mut r = WireReader::new(&bytes);
        let body: &ChallengeReqBody = r.read().unwrap();
        assert_eq!(body.slot_id, 3);
        assert_eq!(body.meas_summary_hash_type, 0xFF);
        assert_eq!(body.nonce, [0x77; 32]);
        assert!(r.is_empty());

        // Body is 34 bytes; 33 is too short.
        assert!(WireReader::new(&bytes[..33])
            .read::<ChallengeReqBody>()
            .is_err());
    }

    // ---- CHALLENGE_AUTH response -------------------------------------------

    #[test]
    fn test_challenge_auth_rsp_minimal_roundtrip() {
        let rsp = ChallengeAuthRsp {
            slot_id: 1,
            cert_chain_hash: &HASH,
            nonce: &NONCE,
            meas_summary_hash: None,
            opaque_len: 0,
            requester_context: None,
            signature: &SIG,
        };
        // Body = slot (1) + slot mask (1) + cert chain hash (48) + nonce (32)
        //      + opaque length (2) + signature (96) = 180.
        assert_eq!(rsp.body_size(), 180);
        // Wire = 2-byte common header + 180 = 182 bytes.
        let mut buf = [0u8; 182];
        let mut w = WireWriter::new(&mut buf);
        rsp.encode_with_header(SpdmVersion::V12, &mut w).unwrap();

        assert_eq!(&buf[..4], &[0x12, 0x03, 0x01, 0x02]); // V1.2, CHALLENGE_AUTH, slot 1, mask 1<<1
        assert_eq!(&buf[4..52], &HASH);
        assert_eq!(&buf[52..84], &NONCE);
        assert_eq!(&buf[84..86], &[0x00, 0x00]); // opaque_len = 0
        assert_eq!(&buf[86..182], &SIG);

        let p = ParsedChallengeAuth::parse(&buf[2..], false, false).unwrap();
        assert_eq!(p.slot_id, 1);
        assert_eq!(p.cert_chain_hash, &HASH);
        assert_eq!(p.nonce, &NONCE);
        // no_sig_prefix = body minus the 96-byte signature = 180 - 96 = 84.
        assert_eq!(p.no_sig_prefix.len(), 84);
        assert_eq!(p.no_sig_prefix, &buf[2..86]);
        assert_eq!(p.signature, &SIG);
    }

    #[test]
    fn test_challenge_auth_rsp_with_meas_hash_and_context() {
        let rsp = ChallengeAuthRsp {
            slot_id: 7,
            cert_chain_hash: &HASH,
            nonce: &NONCE,
            meas_summary_hash: Some(&MEAS),
            opaque_len: 0,
            requester_context: Some(&CTX),
            signature: &SIG,
        };
        // Body = 180 + measurement summary hash (48) + RequesterContext (8) = 236.
        assert_eq!(rsp.body_size(), 236);
        // Wire = 2 + 236 = 238 bytes.
        let mut buf = [0u8; 238];
        let mut w = WireWriter::new(&mut buf);
        rsp.encode_with_header(SpdmVersion::V13, &mut w).unwrap();

        assert_eq!(&buf[..4], &[0x13, 0x03, 0x07, 0x80]); // slot 7, mask 1<<7
        assert_eq!(&buf[84..132], &MEAS); // after hash (4..52) and nonce (52..84)
        assert_eq!(&buf[132..134], &[0x00, 0x00]);
        assert_eq!(&buf[134..142], &CTX);
        assert_eq!(&buf[142..238], &SIG);

        let p = ParsedChallengeAuth::parse(&buf[2..], true, true).unwrap();
        assert_eq!(p.slot_id, 7);
        // no_sig_prefix = 236 - 96 = 140.
        assert_eq!(p.no_sig_prefix.len(), 140);
        assert_eq!(p.signature, &SIG);
    }

    #[test]
    fn test_challenge_auth_rsp_buffer_too_small() {
        let rsp = ChallengeAuthRsp {
            slot_id: 0,
            cert_chain_hash: &HASH,
            nonce: &NONCE,
            meas_summary_hash: None,
            opaque_len: 0,
            requester_context: None,
            signature: &SIG,
        };
        // Needs 182 bytes; 181 fails on the final signature byte.
        let mut buf = [0u8; 181];
        let mut w = WireWriter::new(&mut buf);
        assert!(rsp.encode_with_header(SpdmVersion::V12, &mut w).is_err());
    }

    #[test]
    fn test_challenge_auth_rsp_opaque_len_without_opaque_data() {
        // Pins a gap: the builder has only an `opaque_len` field and never writes
        // opaque bytes, and body_size() ignores it. A non-zero value yields a body
        // whose OpaqueLength promises bytes that are not there.
        let rsp = ChallengeAuthRsp {
            slot_id: 0,
            cert_chain_hash: &HASH,
            nonce: &NONCE,
            meas_summary_hash: None,
            opaque_len: 4,
            requester_context: None,
            signature: &SIG,
        };
        assert_eq!(rsp.body_size(), 180); // unchanged by opaque_len
        let mut buf = [0u8; 182];
        let mut w = WireWriter::new(&mut buf);
        rsp.encode_with_header(SpdmVersion::V12, &mut w).unwrap();
        assert_eq!(&buf[84..86], &[0x04, 0x00]);

        // Parse: prefix is 84 bytes, opaque_len read ends at 84, skip(4) overruns.
        assert!(ParsedChallengeAuth::parse(&buf[2..], false, false).is_err());
    }

    #[test]
    fn test_challenge_auth_rsp_rejects_slot_id_above_7() {
        // The slot mask is one byte, so only slots 0..=7 are representable.
        let rsp = ChallengeAuthRsp {
            slot_id: 8,
            cert_chain_hash: &HASH,
            nonce: &NONCE,
            meas_summary_hash: None,
            opaque_len: 0,
            requester_context: None,
            signature: &SIG,
        };
        let mut buf = [0u8; 182];
        let mut w = WireWriter::new(&mut buf);
        assert!(rsp.encode_with_header(SpdmVersion::V12, &mut w).is_err());
    }

    // ---- ParsedChallengeAuth::parse: malformed input -----------------------

    // Minimal parseable body: slot (1) + mask (1) + hash (48) + nonce (32)
    // + opaque_len (2) + signature (96) = 180 bytes.
    fn minimal_body() -> [u8; 180] {
        let mut b = [0u8; 180];
        b[0] = 2; // slot
        b[2..50].copy_from_slice(&HASH);
        b[50..82].copy_from_slice(&NONCE);
        b[84..].copy_from_slice(&SIG);
        b
    }

    #[test]
    fn test_parse_challenge_auth_rejects_short_body() {
        // Shorter than the 96-byte signature.
        assert!(ParsedChallengeAuth::parse(&[], false, false).is_err());
        assert!(ParsedChallengeAuth::parse(&[0u8; 95], false, false).is_err());
        // Exactly a signature's worth leaves an empty prefix, so the slot read fails.
        assert!(ParsedChallengeAuth::parse(&[0u8; 96], false, false).is_err());
    }

    #[test]
    fn test_parse_challenge_auth_rejects_truncated_prefix() {
        let b = minimal_body();
        // Prefix is 84 bytes. Dropping one byte from before the signature (so the
        // prefix is 83) cuts the opaque length in half.
        let mut short = [0u8; 179];
        short[..83].copy_from_slice(&b[..83]);
        short[83..].copy_from_slice(&b[84..]);
        assert!(ParsedChallengeAuth::parse(&short, false, false).is_err());

        // The full 180 bytes parse.
        assert!(ParsedChallengeAuth::parse(&b, false, false).is_ok());
    }

    #[test]
    fn test_parse_challenge_auth_rejects_oversized_opaque_len() {
        let mut b = minimal_body();
        b[82] = 0xFF;
        b[83] = 0xFF; // opaque_len = 65535, far beyond the body
        assert!(ParsedChallengeAuth::parse(&b, false, false).is_err());
    }

    #[test]
    fn test_parse_challenge_auth_requires_context_when_expected() {
        // 180-byte body carries no RequesterContext, so expecting one overruns
        // the prefix by 8 bytes.
        let b = minimal_body();
        assert!(ParsedChallengeAuth::parse(&b, false, true).is_err());
    }

    #[test]
    fn test_parse_challenge_auth_ignores_slot_mask_and_masks_slot_nibble() {
        // Pins leniency: the slot mask byte is never checked against the slot,
        // and slot_id keeps only the low nibble.
        let mut b = minimal_body();
        b[0] = 0xF5; // slot byte with junk in the high nibble
        b[1] = 0x00; // slot mask that does not include slot 5
        let p = ParsedChallengeAuth::parse(&b, false, false).unwrap();
        assert_eq!(p.slot_id, 5);
    }

    #[test]
    fn test_parse_challenge_auth_accepts_unconsumed_prefix_bytes() {
        // Pins leniency: bytes left in the prefix after the expected fields are not
        // rejected, so a wrong `has_meas_summary` flag goes undetected when the
        // misread OpaqueLength happens to be small. Here an all-zero 48-byte
        // summary hash is misread as opaque_len = 0 plus 46 stray bytes.
        let rsp = ChallengeAuthRsp {
            slot_id: 0,
            cert_chain_hash: &HASH,
            nonce: &NONCE,
            meas_summary_hash: Some(&[0u8; SHA384_HASH_SIZE]),
            opaque_len: 0,
            requester_context: None,
            signature: &SIG,
        };
        // Wire = 2 + (180 + 48) = 230 bytes.
        let mut buf = [0u8; 230];
        let mut w = WireWriter::new(&mut buf);
        rsp.encode_with_header(SpdmVersion::V13, &mut w).unwrap();

        assert!(ParsedChallengeAuth::parse(&buf[2..], true, false).is_ok());
        assert!(ParsedChallengeAuth::parse(&buf[2..], false, false).is_ok()); // wrong flag, still Ok
    }
}
