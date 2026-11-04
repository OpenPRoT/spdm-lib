// Licensed under the Apache-2.0 license

extern crate std;

use super::*;
use spdm_codec::{
    CapFlags, KeyExchangeReqBodyFixed, ReqRespCode, SpdmVersion, ECDH_P384_EXCHANGE_DATA_SIZE,
    KEY_EXCHANGE_RANDOM_DATA_LEN,
};
use spdm_traits::{NoVdmBackend, SpdmPalAlloc};
use std::vec;
use std::vec::Vec;
use zerocopy::IntoBytes;

use crate::test_support as support;
use support::{negotiated_state, TestHashState, TestIo, TestPal};

fn get_version_request(version: u8, param1: u8, param2: u8) -> Vec<u8> {
    vec![version, ReqRespCode::GET_VERSION.0, param1, param2]
}

/// Dispatches `request` as a cleartext message, routed on its header code.
fn dispatch_request(
    state: &mut ConnectionState<TestHashState, Vec<u8>>,
    sessions: &mut Sessions<TestPal, 1>,
    pal: &TestPal,
    request: Vec<u8>,
) -> SpdmResult<Vec<u8>> {
    let code = ReqRespCode(request[1]);
    let io = TestIo::message(request);
    dispatch(state, sessions, pal, &io, code, &NoVdmBackend)
}

#[test]
fn get_version_advertises_v14_and_resets_valid_connection() {
    let pal = TestPal::default();
    let mut state = ConnectionState {
        phase: Phase::AfterAlgorithms,
        version: SpdmVersion::V13,
        peer_cap_flags: CapFlags::CHUNK,
        ..ConnectionState::default()
    };
    let mut sessions = SessionManager::new();
    let session_id = sessions
        .create_session(0x1234, SpdmVersion::V13, |info| pal.alloc_persistent(info))
        .unwrap();

    let rsp = dispatch_request(
        &mut state,
        &mut sessions,
        &pal,
        get_version_request(SpdmVersion::V10.to_u8(), 0, 0),
    )
    .unwrap();

    assert_eq!(
        rsp,
        [
            SpdmVersion::V10.to_u8(),
            ReqRespCode::VERSION.0,
            0,
            0,
            0,
            3,
            0,
            SpdmVersion::V14.to_u8(),
            0,
            SpdmVersion::V13.to_u8(),
            0,
            SpdmVersion::V12.to_u8(),
        ]
    );
    assert_eq!(state.phase, Phase::AfterVersion);
    assert_eq!(
        state.peer_cap_flags.into_bits(),
        CapFlags::EMPTY.into_bits()
    );
    assert!(sessions.find(session_id).is_none());
}

#[test]
fn invalid_get_version_preserves_connection_and_sessions() {
    let pal = TestPal::default();
    let mut state = ConnectionState {
        phase: Phase::AfterAlgorithms,
        version: SpdmVersion::V13,
        peer_cap_flags: CapFlags::CHUNK,
        ..ConnectionState::default()
    };
    let mut sessions = SessionManager::new();
    let session_id = sessions
        .create_session(0x1234, SpdmVersion::V13, |info| pal.alloc_persistent(info))
        .unwrap();

    let err = dispatch_request(
        &mut state,
        &mut sessions,
        &pal,
        get_version_request(SpdmVersion::V11.to_u8(), 0, 0),
    )
    .unwrap_err();

    assert_eq!(err.spec_byte(), SPDM_VERSION_MISMATCH.spec_byte());
    assert_eq!(state.phase, Phase::AfterAlgorithms);
    assert_eq!(state.version, SpdmVersion::V13);
    assert_eq!(
        state.peer_cap_flags.into_bits(),
        CapFlags::CHUNK.into_bits()
    );
    assert!(sessions.find(session_id).is_some());
}

fn key_exchange_request() -> Vec<u8> {
    let fixed = KeyExchangeReqBodyFixed {
        meas_summary_hash_type: 0,
        slot_id: 0,
        req_session_id: 0x1234u16.to_le_bytes(),
        session_policy: 0,
        _reserved: 0,
        random_data: [0x5a; KEY_EXCHANGE_RANDOM_DATA_LEN],
    };
    let mut request = vec![SpdmVersion::V13.to_u8(), ReqRespCode::KEY_EXCHANGE.0];
    request.extend_from_slice(fixed.as_bytes());
    request.extend_from_slice(&[0x3c; ECDH_P384_EXCHANGE_DATA_SIZE]);
    request.extend_from_slice(&0u16.to_le_bytes()); // no opaque data
    request
}

/// Negotiated V1.3 connection with chunking, small enough that
/// KEY_EXCHANGE_RSP must be staged as a large response.
fn chunked_key_exchange_state(pal: &TestPal) -> ConnectionState<TestHashState, Vec<u8>> {
    let mut state = negotiated_state(SpdmVersion::V13);
    state.peer_cap_flags = CapFlags::CHUNK;
    state.peer_data_transfer_size = 128;
    state.peer_max_spdm_msg_size = 1024;
    let io = TestIo::message(Vec::new());
    state.transcript.append_vca(pal, &io, &[0xaa]).unwrap();
    state
}

/// F003.0 / F006.2: a KEY_EXCHANGE that is never finished leaves a half-open
/// session that blocks every later KEY_EXCHANGE. GET_VERSION must reclaim it,
/// along with any staged chunked KEY_EXCHANGE_RSP.
#[test]
fn get_version_reclaims_abandoned_key_exchange_session() {
    let pal = TestPal {
        mtu: 128,
        large_buffered_msg_capacity: 1024,
        ..Default::default()
    };
    let mut state = chunked_key_exchange_state(&pal);
    let mut sessions = SessionManager::new();

    // Start a handshake and abandon it: no CHUNK_GET, no FINISH.
    let rsp = dispatch_request(&mut state, &mut sessions, &pal, key_exchange_request()).unwrap();
    assert_eq!(rsp[1], ReqRespCode::ERROR.0);
    assert!(sessions.has_handshake_in_progress());
    assert!(state.large_msg_ctx.response_in_progress());

    // The half-open session wedges the slot.
    let err =
        dispatch_request(&mut state, &mut sessions, &pal, key_exchange_request()).unwrap_err();
    assert_eq!(err.spec_byte(), SPDM_UNEXPECTED_REQUEST.spec_byte());
    assert!(sessions.has_handshake_in_progress());

    // GET_VERSION reclaims the slot and drops the staged response.
    dispatch_request(
        &mut state,
        &mut sessions,
        &pal,
        get_version_request(SpdmVersion::V10.to_u8(), 0, 0),
    )
    .unwrap();
    assert_eq!(state.phase, Phase::AfterVersion);
    assert!(!sessions.has_handshake_in_progress());
    assert!(!state.large_msg_ctx.response_in_progress());

    // After renegotiation, a new KEY_EXCHANGE gets the slot.
    state = chunked_key_exchange_state(&pal);
    let rsp = dispatch_request(&mut state, &mut sessions, &pal, key_exchange_request()).unwrap();
    assert_eq!(rsp[1], ReqRespCode::ERROR.0);
    assert!(sessions.has_handshake_in_progress());
}

#[test]
fn get_version_ignores_reserved_parameters() {
    let pal = TestPal::default();
    let mut state = ConnectionState::default();
    let mut sessions = SessionManager::new();

    dispatch_request(
        &mut state,
        &mut sessions,
        &pal,
        get_version_request(SpdmVersion::V10.to_u8(), 0xa5, 0x5a),
    )
    .unwrap();

    assert_eq!(state.phase, Phase::AfterVersion);
}
