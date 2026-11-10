// Licensed under the Apache-2.0 license

//! Requester step: `NEGOTIATE_ALGORITHMS` → `ALGORITHMS` (DSP0274 §10.4).

use spdm_codec::{
    AlgStructEntry, NegotiateAlgorithmsReq, ParsedAlgorithmsRsp, PqcAsymAlgos, ReqRespCode,
    RequestBody, SpdmMsgHdrPdu, SpdmVersion, WireWriter,
};
use spdm_errors::{codes::INVARIANT, PalResult};
use spdm_traits::{SpdmPalAsymAlgo, SpdmPalHash, SpdmPalRng};
use zerocopy::FromBytes;

use super::{PeerVerifier, RequesterTransport, SpdmRequester};

impl<T: RequesterTransport, H: SpdmPalHash, R: SpdmPalRng, V: PeerVerifier>
    SpdmRequester<T, H, R, V>
{
    /// Sends `NEGOTIATE_ALGORITHMS` offering the requester's configured
    /// algorithms (DHE + AEAD + KeySchedule AlgStructs, no extended algs) and
    /// returns the responder's selections.
    pub fn negotiate_algorithms(&mut self, version: SpdmVersion) -> PalResult<ParsedAlgorithmsRsp> {
        let cfg = self.config;
        let req = NegotiateAlgorithmsReq {
            measurement_spec: cfg.measurement_spec,
            other_param_support: cfg.other_param_support,
            base_asym_algo: cfg.base_asym_algo,
            base_hash_algo: cfg.base_hash_algo,
            // The PQC field is reserved before 1.4.
            pqc_asym_algo: if version >= SpdmVersion::V14 {
                cfg.pqc_asym_algo
            } else {
                PqcAsymAlgos::EMPTY
            },
            alg_structs: [
                Some(AlgStructEntry::dhe(cfg.dhe)),
                Some(AlgStructEntry::aead(cfg.aead)),
                Some(AlgStructEntry::key_schedule(cfg.key_schedule)),
                None,
            ],
        };
        let mut w = WireWriter::new(&mut self.buf);
        req.encode_with_header(version, &mut w)
            .map_err(|_| INVARIANT)?;
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

        // The connection signs with exactly one algorithm. Accept only what we
        // offered; anything else (or a PQC choice before 1.4) is a protocol error.
        self.sig_algo = if version >= SpdmVersion::V14 && !parsed.pqc_asym_sel.is_empty() {
            if !parsed.base_asym_sel.is_empty()
                || parsed.pqc_asym_sel.into_bits() != PqcAsymAlgos::ML_DSA_87.into_bits()
                || !cfg.pqc_asym_algo.contains(PqcAsymAlgos::ML_DSA_87)
            {
                return Err(INVARIANT);
            }
            SpdmPalAsymAlgo::MlDsa87
        } else {
            SpdmPalAsymAlgo::EccP384
        };
        Ok(parsed)
    }
}
