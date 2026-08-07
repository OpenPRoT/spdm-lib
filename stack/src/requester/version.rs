// Licensed under the Apache-2.0 license

//! Requester step: `GET_VERSION` → `VERSION` (DSP0274 §10.2).

use spdm_codec::{
    GetVersionReqBody, ParsedVersionRsp, ReqRespCode, RequestBody, SpdmMsgHdrPdu, SpdmVersion,
    WireWriter,
};
use spdm_errors::{codes::INVARIANT, PalResult};
use spdm_traits::SpdmPalHash;
use zerocopy::FromBytes;

use super::{PeerVerifier, RequesterTransport, SpdmRequester};

impl<T: RequesterTransport, H: SpdmPalHash, V: PeerVerifier> SpdmRequester<T, H, V> {
    /// Sends `GET_VERSION` and returns the responder's supported version list.
    ///
    /// Per DSP0274 §10.2 the GET_VERSION request carries `SPDMVersion = V1.0`
    /// and `Param1`/`Param2 = 0`. Both the request and the VERSION response
    /// (which is fixed at V1.0) seed the VCA transcript.
    pub fn get_version(&mut self) -> PalResult<ParsedVersionRsp> {
        // Build request.
        let req = GetVersionReqBody::default();
        let mut w = WireWriter::new(&mut self.buf);
        req.encode_with_header(SpdmVersion::V10, &mut w)
            .map_err(|_| INVARIANT)?;
        let len = w.position();
        let mut out = [0u8; SpdmMsgHdrPdu::SIZE + GetVersionReqBody::SIZE];
        out.copy_from_slice(&self.buf[..len]);
        self.transport.send(&out)?;
        // VCA starts with the GET_VERSION request.
        self.append_vca(&out)?;

        // Receive response.
        let n = self.transport.recv(&mut self.buf)?;
        // Copy the response out of the scratch buffer so we can both parse it and
        // feed it to the transcript without aliasing `self`.
        let mut resp = [0u8; 64];
        if n > resp.len() {
            return Err(INVARIANT);
        }
        resp[..n].copy_from_slice(&self.buf[..n]);
        let msg = &resp[..n];

        let (hdr, body) = SpdmMsgHdrPdu::ref_from_prefix(msg).map_err(|_| INVARIANT)?;
        if hdr.code != ReqRespCode::VERSION {
            return Err(INVARIANT);
        }
        let parsed = ParsedVersionRsp::parse(body).map_err(|_| INVARIANT)?;
        // VERSION response contributes to VCA.
        self.append_vca(msg)?;
        Ok(parsed)
    }
}
