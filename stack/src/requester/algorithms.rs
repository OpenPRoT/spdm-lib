// Licensed under the Apache-2.0 license

//! Requester step: `NEGOTIATE_ALGORITHMS` → `ALGORITHMS` (DSP0274 §10.4).

use spdm_codec::{
    AlgStructEntry, NegotiateAlgorithmsReq, ParsedAlgorithmsRsp, ReqRespCode, RequestBody,
    SpdmMsgHdrPdu, SpdmVersion, WireWriter,
};
use spdm_error::{codes::INVARIANT, PalResult};
use spdm_traits::SpdmPalHash;
use zerocopy::FromBytes;

use super::{PeerVerifier, RequesterTransport, SpdmRequester};

impl<T: RequesterTransport, H: SpdmPalHash, V: PeerVerifier> SpdmRequester<T, H, V> {
    /// Sends `NEGOTIATE_ALGORITHMS` offering the requester's configured
    /// algorithms (DHE + AEAD + KeySchedule AlgStructs, no extended algs) and
    /// returns the responder's selections.
    pub fn negotiate_algorithms(
        &mut self,
        version: SpdmVersion,
    ) -> PalResult<ParsedAlgorithmsRsp> {
        let cfg = self.config;
        let req = NegotiateAlgorithmsReq {
            measurement_spec: cfg.measurement_spec,
            other_param_support: cfg.other_param_support,
            base_asym_algo: cfg.base_asym_algo,
            base_hash_algo: cfg.base_hash_algo,
            alg_structs: [
                Some(AlgStructEntry::dhe(cfg.dhe)),
                Some(AlgStructEntry::aead(cfg.aead)),
                Some(AlgStructEntry::key_schedule(cfg.key_schedule)),
                None,
            ],
        };
        let mut w = WireWriter::new(&mut self.buf);
        req.encode_with_header(version, &mut w).map_err(|_| INVARIANT)?;
        let len = w.position();
        // NEGOTIATE_ALGORITHMS is small and bounded; copy out for the send.
        let mut out = [0u8; 64];
        if len > out.len() {
            return Err(INVARIANT);
        }
        out[..len].copy_from_slice(&self.buf[..len]);
        self.transport.send(&out[..len])?;
        // NEGOTIATE_ALGORITHMS request contributes to VCA.
        self.append_vca(&out[..len])?;

        // Receive ALGORITHMS.
        let n = self.transport.recv(&mut self.buf)?;
        let mut resp = [0u8; 128];
        if n > resp.len() {
            return Err(INVARIANT);
        }
        resp[..n].copy_from_slice(&self.buf[..n]);
        let msg = &resp[..n];
        let (hdr, body) = SpdmMsgHdrPdu::ref_from_prefix(msg).map_err(|_| INVARIANT)?;
        if hdr.code != ReqRespCode::ALGORITHMS {
            return Err(INVARIANT);
        }
        let parsed = ParsedAlgorithmsRsp::parse(body).map_err(|_| INVARIANT)?;
        // ALGORITHMS response contributes to VCA.
        self.append_vca(msg)?;
        Ok(parsed)
    }
}
