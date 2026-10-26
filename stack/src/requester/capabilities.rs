// Licensed under the Apache-2.0 license

//! Requester step: version selection + `GET_CAPABILITIES` → `CAPABILITIES`
//! (DSP0274 §10.3–§10.4).

use spdm_codec::{
    CapFlags, CapabilitiesBody, GetCapabilitiesReq, ParsedVersionRsp, ReqRespCode, RequestBody,
    SpdmMsgHdrPdu, SpdmVersion, WireWriter,
};
use spdm_errors::{codes::INVARIANT, PalResult};
use spdm_traits::SpdmPalHash;
use zerocopy::FromBytes;

use super::{PeerVerifier, RequesterTransport, SpdmRequester};

impl<T: RequesterTransport, H: SpdmPalHash, V: PeerVerifier> SpdmRequester<T, H, V> {
    /// Selects the highest common version from the responder's VERSION list,
    /// then performs `GET_CAPABILITIES`. Returns
    /// `(version, peer_flags, peer_data_transfer_size, peer_max_spdm_msg_size)`.
    pub fn get_capabilities(
        &mut self,
        versions: &ParsedVersionRsp,
    ) -> PalResult<(SpdmVersion, CapFlags, u32, u32)> {
        let version = select_version(self.config.versions, versions).ok_or(INVARIANT)?;
        self.version = version;

        // Build GET_CAPABILITIES.
        let req = GetCapabilitiesReq {
            ct_exponent: self.config.ct_exponent,
            flags: self.config.flags,
            data_transfer_size: self.config.data_transfer_size,
            max_spdm_msg_size: self.config.max_spdm_msg_size,
        };
        let mut w = WireWriter::new(&mut self.buf);
        req.encode_with_header(version, &mut w)
            .map_err(|_| INVARIANT)?;
        let len = w.position();
        let mut out = [0u8; SpdmMsgHdrPdu::SIZE + CapabilitiesBody::SIZE];
        out.copy_from_slice(&self.buf[..len]);
        self.transport.send(&out)?;
        // GET_CAPABILITIES request contributes to VCA.
        self.append_vca(&out)?;

        // Receive CAPABILITIES.
        let n = self.transport.recv(&mut self.buf)?;
        let mut resp = [0u8; SpdmMsgHdrPdu::SIZE + CapabilitiesBody::SIZE];
        if n > resp.len() {
            return Err(INVARIANT);
        }
        resp[..n].copy_from_slice(&self.buf[..n]);
        let msg = &resp[..n];
        let (hdr, body) = SpdmMsgHdrPdu::ref_from_prefix(msg).map_err(|_| INVARIANT)?;
        if hdr.code != ReqRespCode::CAPABILITIES {
            return Err(INVARIANT);
        }
        let caps = CapabilitiesBody::parse(body).map_err(|_| INVARIANT)?;
        let result = (
            version,
            caps.flags,
            caps.data_transfer_size.get(),
            caps.max_spdm_msg_size.get(),
        );
        // CAPABILITIES response contributes to VCA.
        self.append_vca(msg)?;
        Ok(result)
    }
}

/// Picks the highest version present in both `supported` and the
/// responder's advertised list.
fn select_version(supported: &[SpdmVersion], rsp: &ParsedVersionRsp) -> Option<SpdmVersion> {
    let mut best: Option<SpdmVersion> = None;
    for v in rsp.versions.iter().take(rsp.count).flatten() {
        if supported.contains(v) && best.is_none_or(|b| *v > b) {
            best = Some(*v);
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    fn advertised(versions: &[SpdmVersion]) -> ParsedVersionRsp {
        let mut rsp = ParsedVersionRsp {
            count: versions.len(),
            versions: [None; ParsedVersionRsp::MAX_ENTRIES],
        };
        for (slot, v) in rsp.versions.iter_mut().zip(versions) {
            *slot = Some(*v);
        }
        rsp
    }

    const ALL: &[SpdmVersion] = &[SpdmVersion::V14, SpdmVersion::V13, SpdmVersion::V12];

    #[test]
    fn selects_highest_common_version() {
        let rsp = advertised(&[SpdmVersion::V12, SpdmVersion::V14, SpdmVersion::V13]);
        assert_eq!(select_version(ALL, &rsp), Some(SpdmVersion::V14));
    }

    #[test]
    fn local_list_caps_the_selection() {
        let rsp = advertised(&[SpdmVersion::V14, SpdmVersion::V13, SpdmVersion::V12]);
        let local = &[SpdmVersion::V13, SpdmVersion::V12];
        assert_eq!(select_version(local, &rsp), Some(SpdmVersion::V13));
    }

    #[test]
    fn no_common_version_is_rejected() {
        let rsp = advertised(&[SpdmVersion::V10, SpdmVersion::V11]);
        assert_eq!(select_version(ALL, &rsp), None);
    }

    #[test]
    fn entries_past_count_are_ignored() {
        let mut rsp = advertised(&[SpdmVersion::V12, SpdmVersion::V14]);
        rsp.count = 1;
        assert_eq!(select_version(ALL, &rsp), Some(SpdmVersion::V12));
    }
}
