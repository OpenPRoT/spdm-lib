// Licensed under the Apache-2.0 license

//! HEARTBEAT to HEARTBEAT_ACK handler.
//!
//! HEARTBEAT is a session-only keep-alive with no request payload beyond the
//! common header (Param1/Param2 reserved). The responder replies with a
//! HEARTBEAT_ACK whose Param1/Param2 are reserved (zero). The command is only
//! reachable inside an established secure session (enforced by the dispatcher's
//! phase gate); this handler validates the request shape and builds the ACK,
//! which the caller encrypts.

use spdm_codec::{ReqRespCode, SpdmMsgHdrPdu, SpdmVersion};
use zerocopy::FromBytes;

use crate::error::{SpdmResult, SPDM_INVALID_REQUEST, SPDM_VERSION_MISMATCH};

/// Size of the HEARTBEAT_ACK SPDM message (common header + 2 reserved bytes).
pub(crate) const HEARTBEAT_ACK_SPDM_SIZE: usize = SpdmMsgHdrPdu::SIZE + 2;

/// Default HeartbeatPeriod (seconds) advertised in KEY_EXCHANGE_RSP when both
/// endpoints support HEARTBEAT. Not feature-gated so `heartbeat_period_for` can
/// select on it with `cfg!()` (both branches must compile); the value is
/// dead-code-eliminated when the `spdm-set-heartbeat` feature is off.
pub(crate) const DEFAULT_HEARTBEAT_PERIOD_SECS: u8 = 3;

/// Number of successive missed HeartbeatPeriods after which the responder
/// tears the session down.
pub(crate) const HEARTBEAT_TIMEOUT_MULTIPLIER: u64 = 2;

/// Handle a decrypted HEARTBEAT request and produce the HEARTBEAT_ACK bytes.
pub(crate) fn handle_heartbeat(
    version: SpdmVersion,
    spdm_msg: &[u8],
) -> SpdmResult<[u8; HEARTBEAT_ACK_SPDM_SIZE]> {
    let (hdr, rest) = SpdmMsgHdrPdu::ref_from_prefix(spdm_msg).map_err(|_| SPDM_INVALID_REQUEST)?;
    if hdr.version != version.to_u8() {
        return Err(SPDM_VERSION_MISMATCH);
    }
    // The request is exactly the 2-byte common header plus the two reserved
    // Param1/Param2 bytes. Per DSP0274, reserved fields are ignored on read, so
    // their contents are not validated -- but reject a request carrying trailing
    // bytes beyond the fixed layout.
    if rest.len() != 2 {
        return Err(SPDM_INVALID_REQUEST);
    }

    let mut rsp_buf = [0u8; HEARTBEAT_ACK_SPDM_SIZE];
    rsp_buf[0] = version.to_u8();
    rsp_buf[1] = ReqRespCode::HEARTBEAT_ACK.0;
    // rsp_buf[2..4] left zero: Param1/Param2 reserved.
    Ok(rsp_buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A well-formed HEARTBEAT request: [version, HEARTBEAT, Param1=0, Param2=0].
    fn request(version: SpdmVersion) -> [u8; 4] {
        [version.to_u8(), ReqRespCode::HEARTBEAT.0, 0, 0]
    }

    #[test]
    fn well_formed_request_produces_ack() {
        let ack = handle_heartbeat(SpdmVersion::V12, &request(SpdmVersion::V12)).unwrap();
        assert_eq!(
            ack,
            [SpdmVersion::V12.to_u8(), ReqRespCode::HEARTBEAT_ACK.0, 0, 0]
        );
    }

    /// Reserved Param1/Param2 are ignored on read, per DSP0274.
    #[test]
    fn nonzero_reserved_params_are_ignored() {
        let mut req = request(SpdmVersion::V12);
        req[2] = 0xAA;
        req[3] = 0x55;
        let ack = handle_heartbeat(SpdmVersion::V12, &req).unwrap();
        assert_eq!(ack[2..], [0, 0]);
    }

    #[test]
    fn version_mismatch_is_rejected() {
        let err = handle_heartbeat(SpdmVersion::V12, &request(SpdmVersion::V13)).unwrap_err();
        assert_eq!(err, SPDM_VERSION_MISMATCH);
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let req = [SpdmVersion::V12.to_u8(), ReqRespCode::HEARTBEAT.0, 0, 0, 0];
        let err = handle_heartbeat(SpdmVersion::V12, &req).unwrap_err();
        assert_eq!(err, SPDM_INVALID_REQUEST);
    }

    #[test]
    fn truncated_request_is_rejected() {
        let err = handle_heartbeat(SpdmVersion::V12, &[SpdmVersion::V12.to_u8()]).unwrap_err();
        assert_eq!(err, SPDM_INVALID_REQUEST);
    }
}
