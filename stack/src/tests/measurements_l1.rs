// Licensed under the Apache-2.0 license

//! L1/L2 measurement-log lifecycle (DSP0274 1.4 §10.12.2): every
//! GET_MEASUREMENTS/MEASUREMENTS pair accumulates, a signed MEASUREMENTS
//! consumes the log, and any other communication or error re-initializes it.

extern crate std;

use super::*;
use spdm_codec::{ReqRespCode, SpdmVersion};
use spdm_traits::{MeasurementInfo, NoVdmBackend};
use std::vec;
use std::vec::Vec;

use crate::test_support as support;
use support::{negotiated_state, TestHashState, TestIo, TestPal};

static MEASUREMENT_INFO: [MeasurementInfo; 1] = [MeasurementInfo {
    index: 1,
    value_size: 4,
    value_type: 0,
    is_raw: false,
    is_tcb: true,
}];
static MEASUREMENT_VALUE: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];

fn measurement_pal() -> TestPal {
    TestPal {
        measurement_info: &MEASUREMENT_INFO,
        measurement_value: &MEASUREMENT_VALUE,
        ..TestPal::default()
    }
}

/// Negotiated V1.2 connection with the VCA transcript established.
fn measured_state(pal: &TestPal) -> ConnectionState<TestHashState, Vec<u8>> {
    let mut state = negotiated_state(SpdmVersion::V12);
    let io = TestIo::message(Vec::new());
    state.transcript.append_vca(pal, &io, b"vca").unwrap();
    state
}

fn unsigned_request(op: u8) -> Vec<u8> {
    vec![
        SpdmVersion::V12.to_u8(),
        ReqRespCode::GET_MEASUREMENTS.0,
        0,
        op,
    ]
}

fn signed_request(op: u8) -> Vec<u8> {
    let mut req = vec![
        SpdmVersion::V12.to_u8(),
        ReqRespCode::GET_MEASUREMENTS.0,
        0x01,
        op,
    ];
    req.extend_from_slice(&[0xA5; 32]); // requester nonce
    req.push(0); // SlotIDParam
    req
}

fn send(
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
fn unsigned_measurements_start_l1() {
    let pal = measurement_pal();
    let mut state = measured_state(&pal);
    let mut sessions = SessionManager::new();

    send(&mut state, &mut sessions, &pal, unsigned_request(0)).unwrap();
    assert!(state.transcript.l1_active());

    send(&mut state, &mut sessions, &pal, unsigned_request(1)).unwrap();
    assert!(state.transcript.l1_active());
}

#[test]
fn signed_measurements_consume_l1() {
    let pal = measurement_pal();
    let mut state = measured_state(&pal);
    let mut sessions = SessionManager::new();

    send(&mut state, &mut sessions, &pal, unsigned_request(0)).unwrap();
    let rsp = send(&mut state, &mut sessions, &pal, signed_request(1)).unwrap();

    assert_eq!(rsp[1], ReqRespCode::MEASUREMENTS.0);
    assert!(!state.transcript.l1_active());
}

#[test]
fn other_request_resets_l1() {
    let pal = measurement_pal();
    let mut state = measured_state(&pal);
    let mut sessions = SessionManager::new();

    send(&mut state, &mut sessions, &pal, unsigned_request(0)).unwrap();
    assert!(state.transcript.l1_active());

    let get_digests = vec![SpdmVersion::V12.to_u8(), ReqRespCode::GET_DIGESTS.0, 0, 0];
    let _ = send(&mut state, &mut sessions, &pal, get_digests);
    assert!(!state.transcript.l1_active());
}

#[test]
fn malformed_request_resets_l1() {
    let pal = measurement_pal();
    let mut state = measured_state(&pal);
    let mut sessions = SessionManager::new();

    send(&mut state, &mut sessions, &pal, unsigned_request(0)).unwrap();
    assert!(state.transcript.l1_active());

    // Truncated GET_MEASUREMENTS: decode fails and the reply is an ERROR.
    let truncated = vec![SpdmVersion::V12.to_u8(), ReqRespCode::GET_MEASUREMENTS.0];
    assert!(send(&mut state, &mut sessions, &pal, truncated).is_err());
    assert!(!state.transcript.l1_active());
}

#[test]
fn unknown_measurement_index_resets_l1() {
    let pal = measurement_pal();
    let mut state = measured_state(&pal);
    let mut sessions = SessionManager::new();

    send(&mut state, &mut sessions, &pal, unsigned_request(0)).unwrap();
    let err = send(&mut state, &mut sessions, &pal, unsigned_request(0x42)).unwrap_err();

    assert_eq!(err.spec_byte(), SPDM_INVALID_REQUEST.spec_byte());
    assert!(!state.transcript.l1_active());
}

#[test]
fn chunk_get_keeps_l1_but_other_codes_reset_it() {
    let pal = measurement_pal();
    let mut state = measured_state(&pal);
    let mut sessions = SessionManager::new();
    send(&mut state, &mut sessions, &pal, unsigned_request(0)).unwrap();

    reset_l1_unless_measurement(&mut state, ReqRespCode::CHUNK_GET);
    assert!(state.transcript.l1_active());

    reset_l1_unless_measurement(&mut state, ReqRespCode::CHUNK_SEND);
    assert!(!state.transcript.l1_active());
}

#[test]
fn l1_is_dropped_when_context_changes() {
    let pal = measurement_pal();
    let mut state = measured_state(&pal);
    let mut sessions = SessionManager::new();
    send(&mut state, &mut sessions, &pal, unsigned_request(0)).unwrap();

    // Same context (outside any session): the log continues.
    state.transcript.select_l1_session(None);
    assert!(state.transcript.l1_active());

    // A GET_MEASUREMENTS inside a session must not extend the plain log.
    state.transcript.select_l1_session(Some(0x1234));
    assert!(!state.transcript.l1_active());
}
