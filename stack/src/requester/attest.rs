// Licensed under the Apache-2.0 license

//! Requester attestation steps: GET_DIGESTS, GET_CERTIFICATE, CHALLENGE,
//! GET_MEASUREMENTS — with M1/L1 transcript reconstruction and signature
//! verification against the responder's leaf public key.
//!
//! The M1 transcript (CHALLENGE_AUTH signature input) is:
//! `VCA ∥ GET_DIGESTS ∥ DIGESTS ∥ GET_CERTIFICATE* ∥ CERTIFICATE* ∥ CHALLENGE ∥
//! CHALLENGE_AUTH(no sig)`. L1 (MEASUREMENTS signature input) forks from VCA:
//! `VCA ∥ GET_MEASUREMENTS ∥ MEASUREMENTS(no sig)`. The requester must feed
//! byte-identical bytes into the shared [`Transcript`](crate::transcript) so its
//! finalized hash matches the responder's.

use spdm_codec::{
    ChallengeReq, GetCertificateReq, GetDigestsReqBody, GetMeasurementsReq, ParsedCertificateRsp,
    ParsedChallengeAuth, ParsedDigestsRsp, ParsedMeasurementsRsp, ReqRespCode, RequestBody,
    SpdmMsgHdrPdu, SpdmVersion, WireWriter, ECC_P384_SIGNATURE_SIZE, MEAS_ATTR_SIGNATURE_REQUESTED,
    MEAS_OP_ALL, REQUESTER_CONTEXT_LEN, SHA384_HASH_SIZE, SPDM_NONCE_LEN,
};
use spdm_error::{codes::INVARIANT, PalResult};
use spdm_traits::SpdmPalHash;
use zerocopy::FromBytes;

use crate::signing::{build_signing_context, compute_tbs_hash, OP_CHALLENGE_AUTH, OP_MEASUREMENTS};

use super::{NullIo, PeerVerifier, RequesterTransport, SpdmRequester, BUF_LEN};

/// SPDM cert-chain wire header: length(2) | reserved(2) | root_hash(48).
const SPDM_CERT_CHAIN_HDR_LEN: usize = 4 + SHA384_HASH_SIZE;

/// Result of the attestation flow.
pub struct Attestation {
    /// Number of measurement blocks returned.
    pub measurement_blocks: u8,
    /// True once both CHALLENGE_AUTH and MEASUREMENTS signatures verified.
    pub verified: bool,
}

impl<T: RequesterTransport, H: SpdmPalHash, V: PeerVerifier> SpdmRequester<T, H, V> {
    /// Runs GET_DIGESTS → GET_CERTIFICATE → CHALLENGE → GET_MEASUREMENTS,
    /// validating the cert chain and verifying both signatures. Call after
    /// [`negotiate`](Self::negotiate).
    pub fn attest(&mut self, slot_id: u8) -> PalResult<Attestation> {
        self.get_digests()?;
        let pubkey = self.get_certificate(slot_id)?;
        self.challenge(slot_id, &pubkey)?;
        let blocks = self.get_measurements(slot_id, &pubkey)?;
        Ok(Attestation {
            measurement_blocks: blocks,
            verified: true,
        })
    }

    /// GET_DIGESTS → DIGESTS. Seeds M1 with the request+response.
    fn get_digests(&mut self) -> PalResult<()> {
        let (req_buf, req_len) = self.build(&GetDigestsReqBody::default(), self.version)?;
        self.transport.send(&req_buf[..req_len])?;
        self.append_m1_from_scratch(req_len)?;

        let (code, msg, n) = self.recv()?;
        if code != ReqRespCode::DIGESTS {
            return Err(INVARIANT);
        }
        let _ = ParsedDigestsRsp::parse(&msg[SpdmMsgHdrPdu::SIZE..n]).map_err(|_| INVARIANT)?;
        self.append_m1(&msg[..n])?;
        Ok(())
    }

    /// GET_CERTIFICATE (chunked) → reassemble raw DER chain → validate chain →
    /// return leaf public key. Feeds every request/response into M1.
    fn get_certificate(&mut self, slot_id: u8) -> PalResult<V::PubKey> {
        let mut chain = [0u8; BUF_LEN];
        let mut total: usize = 0;
        let mut offset: u16 = 0;
        let version = self.version;

        loop {
            let req = GetCertificateReq {
                slot_id,
                attributes: 0,
                offset,
                length: 0xFFFF, // request as much as the responder will give
            };
            let (req_buf, req_len) = self.build(&req, version)?;
            self.transport.send(&req_buf[..req_len])?;
            self.append_m1_from_scratch(req_len)?;

            let (code, msg, n) = self.recv()?;
            if code != ReqRespCode::CERTIFICATE {
                return Err(INVARIANT);
            }
            self.append_m1(&msg[..n])?;

            let cert =
                ParsedCertificateRsp::parse(&msg[SpdmMsgHdrPdu::SIZE..n]).map_err(|_| INVARIANT)?;
            let end = total + cert.portion.len();
            if end > chain.len() {
                return Err(INVARIANT);
            }
            chain[total..end].copy_from_slice(cert.portion);
            total = end;
            offset = offset.wrapping_add(cert.portion_length);

            if cert.remainder_length == 0 {
                break;
            }
        }

        if total < SPDM_CERT_CHAIN_HDR_LEN {
            return Err(INVARIANT);
        }
        self.verifier.validate_chain(&chain[SPDM_CERT_CHAIN_HDR_LEN..total])
    }

    /// CHALLENGE → CHALLENGE_AUTH, verifying the M1 signature.
    fn challenge(&mut self, slot_id: u8, pubkey: &V::PubKey) -> PalResult<()> {
        let version = self.version;
        let requester_context = (version >= SpdmVersion::V13).then_some([0u8; REQUESTER_CONTEXT_LEN]);
        let req = ChallengeReq {
            slot_id,
            meas_summary_hash_type: 0, // none (this milestone)
            nonce: [0xA5; SPDM_NONCE_LEN],
            requester_context,
        };
        let (req_buf, req_len) = self.build(&req, version)?;
        self.transport.send(&req_buf[..req_len])?;
        self.append_m1_from_scratch(req_len)?;

        let (code, msg, n) = self.recv()?;
        if code != ReqRespCode::CHALLENGE_AUTH {
            return Err(INVARIANT);
        }
        let parsed = ParsedChallengeAuth::parse(
            &msg[SpdmMsgHdrPdu::SIZE..n],
            false,
            requester_context.is_some(),
        )
        .map_err(|_| INVARIANT)?;

        let mut sig = [0u8; ECC_P384_SIGNATURE_SIZE];
        if parsed.signature.len() != ECC_P384_SIGNATURE_SIZE {
            return Err(INVARIANT);
        }
        sig.copy_from_slice(parsed.signature);
        // M1 covers header + body-without-signature.
        let m1_len = SpdmMsgHdrPdu::SIZE + parsed.no_sig_prefix.len();

        let tbs = self.finalize_and_tbs_m1(&msg, m1_len, version)?;
        self.verifier.verify_p384(pubkey, &tbs, &sig)
    }

    /// GET_MEASUREMENTS (signed, all blocks) → MEASUREMENTS, verifying the L1
    /// signature. Returns the number of measurement blocks.
    fn get_measurements(&mut self, slot_id: u8, pubkey: &V::PubKey) -> PalResult<u8> {
        let version = self.version;
        let requester_context = (version >= SpdmVersion::V13).then_some([0u8; REQUESTER_CONTEXT_LEN]);
        let req = GetMeasurementsReq {
            attributes: MEAS_ATTR_SIGNATURE_REQUESTED,
            measurement_operation: MEAS_OP_ALL,
            nonce: Some([0x5A; SPDM_NONCE_LEN]),
            slot_id,
            requester_context,
        };
        let (req_buf, req_len) = self.build(&req, version)?;
        self.transport.send(&req_buf[..req_len])?;
        // L1 forks from VCA; GET_MEASUREMENTS request is first into L1.
        self.append_l1_from_scratch(req_len)?;

        let (code, msg, n) = self.recv()?;
        if code != ReqRespCode::MEASUREMENTS {
            return Err(INVARIANT);
        }
        let parsed = ParsedMeasurementsRsp::parse(
            &msg[SpdmMsgHdrPdu::SIZE..n],
            true,
            requester_context.is_some(),
        )
        .map_err(|_| INVARIANT)?;

        let mut sig = [0u8; ECC_P384_SIGNATURE_SIZE];
        if parsed.signature.len() != ECC_P384_SIGNATURE_SIZE {
            return Err(INVARIANT);
        }
        sig.copy_from_slice(parsed.signature);
        let blocks = parsed.number_of_blocks;
        let l1_len = SpdmMsgHdrPdu::SIZE + parsed.no_sig_prefix.len();

        let tbs = self.finalize_and_tbs_l1(&msg, l1_len, version)?;
        self.verifier.verify_p384(pubkey, &tbs, &sig)?;
        Ok(blocks)
    }

    // ---- helpers ------------------------------------------------------------

    /// Encode `req` with `version` into `self.buf`; return `(buf_copy, len)`.
    fn build<R: RequestBody>(
        &mut self,
        req: &R,
        version: SpdmVersion,
    ) -> PalResult<([u8; BUF_LEN], usize)> {
        let mut w = WireWriter::new(&mut self.buf);
        req.encode_with_header(version, &mut w).map_err(|_| INVARIANT)?;
        let len = w.position();
        let mut out = [0u8; BUF_LEN];
        out[..len].copy_from_slice(&self.buf[..len]);
        Ok((out, len))
    }

    /// Receive one response into an owned buffer; returns `(code, bytes, len)`.
    fn recv(&mut self) -> PalResult<(ReqRespCode, [u8; BUF_LEN], usize)> {
        let n = self.transport.recv(&mut self.buf)?;
        let mut msg = [0u8; BUF_LEN];
        if n > msg.len() {
            return Err(INVARIANT);
        }
        msg[..n].copy_from_slice(&self.buf[..n]);
        let (hdr, _) = SpdmMsgHdrPdu::ref_from_prefix(&msg[..n]).map_err(|_| INVARIANT)?;
        Ok((hdr.code, msg, n))
    }

    /// Append the first `len` bytes currently in `self.buf` to M1. Used right
    /// after `build` (which left the request in `self.buf`) so we don't need to
    /// re-borrow the returned copy while `self` is borrowed for the append.
    fn append_m1_from_scratch(&mut self, len: usize) -> PalResult<()> {
        let mut tmp = [0u8; BUF_LEN];
        tmp[..len].copy_from_slice(&self.buf[..len]);
        self.append_m1(&tmp[..len])
    }

    fn append_l1_from_scratch(&mut self, len: usize) -> PalResult<()> {
        let mut tmp = [0u8; BUF_LEN];
        tmp[..len].copy_from_slice(&self.buf[..len]);
        self.append_l1(&tmp[..len])
    }

    /// Append `msg[..m1_len]` (header + body-without-sig) to M1, finalize M1,
    /// and return the TBS digest for CHALLENGE_AUTH.
    fn finalize_and_tbs_m1(
        &mut self,
        msg: &[u8; BUF_LEN],
        m1_len: usize,
        version: SpdmVersion,
    ) -> PalResult<[u8; SHA384_HASH_SIZE]> {
        let mut prefix = [0u8; BUF_LEN];
        prefix[..m1_len].copy_from_slice(&msg[..m1_len]);
        self.append_m1(&prefix[..m1_len])?;
        let mut m1_hash = [0u8; SHA384_HASH_SIZE];
        self.transcript.finalize_m1(&self.hash, &NullIo, &mut m1_hash)?;
        let ctx = build_signing_context(version, OP_CHALLENGE_AUTH);
        compute_tbs_hash(&self.hash, &NullIo, &ctx, &m1_hash)
    }

    /// Append `msg[..l1_len]` to L1, finalize L1, return the MEASUREMENTS TBS.
    fn finalize_and_tbs_l1(
        &mut self,
        msg: &[u8; BUF_LEN],
        l1_len: usize,
        version: SpdmVersion,
    ) -> PalResult<[u8; SHA384_HASH_SIZE]> {
        let mut prefix = [0u8; BUF_LEN];
        prefix[..l1_len].copy_from_slice(&msg[..l1_len]);
        self.append_l1(&prefix[..l1_len])?;
        let mut l1_hash = [0u8; SHA384_HASH_SIZE];
        self.transcript.finalize_l1(&self.hash, &NullIo, &mut l1_hash)?;
        let ctx = build_signing_context(version, OP_MEASUREMENTS);
        compute_tbs_hash(&self.hash, &NullIo, &ctx, &l1_hash)
    }
}
