// Copyright 2025
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![allow(clippy::field_reassign_with_default)]

extern crate std;

use super::*;
use core::mem::offset_of;
use spdm_codec::{
    CapFlags, CapabilitiesBody, ExtCapFlags, ReqRespCode, SpdmMsgHdrPdu, SpdmVersion,
};
use spdm_traits::NoVdmBackend;
use std::vec;
use std::vec::Vec;

use crate::test_support as support;
use support::{TestHashState, TestIo, TestPal};

const BODY_OFFSET: usize = SpdmMsgHdrPdu::SIZE;
const EXT_FLAGS_OFFSET: usize = BODY_OFFSET + offset_of!(CapabilitiesBody, ext_flags);
const FLAGS_OFFSET: usize = BODY_OFFSET + offset_of!(CapabilitiesBody, flags);
const MAX_MSG_SIZE_OFFSET: usize = BODY_OFFSET + offset_of!(CapabilitiesBody, max_spdm_msg_size);

fn rsp_flags(rsp: &[u8]) -> u32 {
    u32::from_le_bytes(rsp[FLAGS_OFFSET..][..size_of::<u32>()].try_into().unwrap())
}

fn capabilities_request(
    version: SpdmVersion,
    param1: u8,
    ext_flags: u16,
    flags: CapFlags,
    data_transfer_size: u32,
    max_spdm_msg_size: u32,
) -> Vec<u8> {
    let mut req = vec![
        version.to_u8(),
        ReqRespCode::GET_CAPABILITIES.0,
        param1,
        0,
        0,
        0,
    ];
    req.extend_from_slice(&ext_flags.to_le_bytes());
    req.extend_from_slice(&flags.into_bits().to_le_bytes());
    req.extend_from_slice(&data_transfer_size.to_le_bytes());
    req.extend_from_slice(&max_spdm_msg_size.to_le_bytes());
    req
}

fn dispatch_request(
    state: &mut ConnectionState<TestHashState, Vec<u8>>,
    sessions: &mut Sessions<TestPal, 1>,
    pal: &TestPal,
    request: Vec<u8>,
) -> SpdmResult<Vec<u8>> {
    let io = TestIo::message(request);
    dispatch(
        state,
        sessions,
        pal,
        &io,
        ReqRespCode::GET_CAPABILITIES,
        &NoVdmBackend,
    )
}

#[test]
fn get_capabilities_negotiates_v14_and_encodes_ext_flags() {
    let pal = TestPal {
        max_inbound_spdm_request_size: 4096,
        ..TestPal::default()
    };
    let mut state = ConnectionState::default();
    state.phase = Phase::AfterVersion;
    let mut sessions = SessionManager::new();
    let peer_flags = CapFlags::CERT
        | CapFlags::KEY_EX
        | CapFlags::ENCRYPT
        | CapFlags::MAC
        | CapFlags::CHUNK
        | CapFlags::LARGE_RESP;

    let rsp = dispatch_request(
        &mut state,
        &mut sessions,
        &pal,
        capabilities_request(SpdmVersion::V14, 0, 0, peer_flags, 1024, 4096),
    )
    .unwrap();

    assert_eq!(rsp.len(), SpdmMsgHdrPdu::SIZE + CapabilitiesBody::SIZE);
    assert_eq!(rsp[0], SpdmVersion::V14.to_u8());
    assert_eq!(rsp[1], ReqRespCode::CAPABILITIES.0);
    assert_eq!(
        &rsp[EXT_FLAGS_OFFSET..][..size_of::<ExtCapFlags>()],
        &[0; size_of::<ExtCapFlags>()]
    );
    assert_eq!(rsp_flags(&rsp), state.advertised_cap_flags.into_bits());
    assert_eq!(
        u32::from_le_bytes(
            rsp[MAX_MSG_SIZE_OFFSET..][..size_of::<u32>()]
                .try_into()
                .unwrap()
        ),
        4096
    );
    assert_eq!(state.version, SpdmVersion::V14);
    assert_eq!(state.phase, Phase::AfterCapabilities);
    assert_eq!(state.peer_cap_flags.into_bits(), peer_flags.into_bits());
    assert_eq!(state.peer_data_transfer_size, 1024);
    assert_eq!(state.peer_max_spdm_msg_size, 4096);
}

#[test]
fn get_capabilities_masks_flags_added_after_v12() {
    let pal = TestPal::default();
    let mut state = ConnectionState::default();
    state.phase = Phase::AfterVersion;
    state.cap_flags |= CapFlags::GET_KEY_PAIR_INFO | CapFlags::LARGE_RESP;
    let mut sessions = SessionManager::new();
    let peer_flags =
        CapFlags::CERT | CapFlags::KEY_EX | CapFlags::ENCRYPT | CapFlags::MAC | CapFlags::CHUNK;

    let rsp = dispatch_request(
        &mut state,
        &mut sessions,
        &pal,
        capabilities_request(SpdmVersion::V12, 0, 0, peer_flags, 1024, 1024),
    )
    .unwrap();
    let advertised = CapFlags::from_bits(rsp_flags(&rsp));

    assert!(!advertised.contains(CapFlags::GET_KEY_PAIR_INFO));
    assert!(!advertised.contains(CapFlags::LARGE_RESP));
}

#[test]
fn v14_capabilities_ignores_reserved_extended_flags() {
    let pal = TestPal::default();
    let mut state = ConnectionState::default();
    state.phase = Phase::AfterVersion;
    let mut sessions = SessionManager::new();
    let peer_flags = CapFlags::CERT | CapFlags::KEY_EX | CapFlags::CHUNK;

    dispatch_request(
        &mut state,
        &mut sessions,
        &pal,
        capabilities_request(SpdmVersion::V14, 0, u16::MAX, peer_flags, 1024, 1024),
    )
    .unwrap();

    assert_eq!(state.phase, Phase::AfterCapabilities);
    assert_eq!(state.version, SpdmVersion::V14);
}

#[test]
fn v14_capabilities_accepts_supported_algorithms_request_with_chunking() {
    let pal = TestPal::default();
    let mut state = ConnectionState::default();
    state.phase = Phase::AfterVersion;
    let mut sessions = SessionManager::new();
    let peer_flags =
        CapFlags::CERT | CapFlags::KEY_EX | CapFlags::ENCRYPT | CapFlags::MAC | CapFlags::CHUNK;

    let rsp = dispatch_request(
        &mut state,
        &mut sessions,
        &pal,
        capabilities_request(SpdmVersion::V14, 1, 0, peer_flags, 1024, 1024),
    )
    .unwrap();

    // The request is valid, but this responder does not implement the
    // optional Supported Algorithms block and therefore clears Param1.
    assert_eq!(rsp[2], 0);
    assert_eq!(state.phase, Phase::AfterCapabilities);
}

#[test]
fn v14_supported_algorithms_request_requires_requester_chunking() {
    let pal = TestPal::default();
    let mut state = ConnectionState::default();
    state.phase = Phase::AfterVersion;
    let mut sessions = SessionManager::new();
    let peer_flags = CapFlags::CERT | CapFlags::KEY_EX;

    let err = dispatch_request(
        &mut state,
        &mut sessions,
        &pal,
        capabilities_request(SpdmVersion::V14, 1, 0, peer_flags, 1024, 1024),
    )
    .unwrap_err();

    assert_eq!(err.spec_byte(), SPDM_INVALID_REQUEST.spec_byte());
    assert_eq!(state.phase, Phase::AfterVersion);
    assert_eq!(state.version, SpdmVersion::V12);
}

#[test]
fn v13_capabilities_masks_v14_responder_flags() {
    let pal = TestPal::default();
    let mut state = ConnectionState::default();
    state.phase = Phase::AfterVersion;
    state.cap_flags |= CapFlags::SET_KEY_PAIR_RESET | CapFlags::LARGE_RESP;
    let mut sessions = SessionManager::new();
    let peer_flags =
        CapFlags::CERT | CapFlags::KEY_EX | CapFlags::ENCRYPT | CapFlags::MAC | CapFlags::CHUNK;

    let rsp = dispatch_request(
        &mut state,
        &mut sessions,
        &pal,
        capabilities_request(SpdmVersion::V13, 0, 0, peer_flags, 1024, 1024),
    )
    .unwrap();
    let advertised = CapFlags::from_bits(rsp_flags(&rsp));

    assert!(!advertised.contains(CapFlags::SET_KEY_PAIR_RESET));
    assert!(!advertised.contains(CapFlags::LARGE_RESP));
}

#[test]
fn v14_capabilities_excludes_sessions_and_preserves_attestation() {
    let pal = TestPal::default();
    let session_caps = CapFlags::KEY_EX
        | CapFlags::ENCRYPT
        | CapFlags::MAC
        | CapFlags::PSK
        | CapFlags::PSK_WITH_CTX
        | CapFlags::HBEAT
        | CapFlags::KEY_UPD
        | CapFlags::HANDSHAKE_IN_THE_CLEAR;
    let attestation_caps = CapFlags::CERT
        | CapFlags::CHAL
        | CapFlags::MEAS_SIG
        | CapFlags::CHUNK
        | CapFlags::LARGE_RESP;
    let mut state = ConnectionState::default();
    state.phase = Phase::AfterVersion;
    state.cap_flags |= session_caps;
    let mut sessions = SessionManager::new();

    let rsp = dispatch_request(
        &mut state,
        &mut sessions,
        &pal,
        capabilities_request(SpdmVersion::V14, 0, 0, CapFlags::CHUNK, 1024, 1024),
    )
    .unwrap();
    let advertised = CapFlags::from_bits(rsp_flags(&rsp));

    assert_eq!(advertised.into_bits() & session_caps.into_bits(), 0);
    assert!(advertised.contains(attestation_caps));
}

#[test]
fn earlier_versions_preserve_supported_session_capabilities() {
    for version in [SpdmVersion::V12, SpdmVersion::V13] {
        for secure_message_supported in [false, true] {
            let pal = TestPal {
                secure_message_supported,
                ..TestPal::default()
            };
            let session_caps = CapFlags::KEY_EX
                | CapFlags::ENCRYPT
                | CapFlags::MAC
                | CapFlags::HBEAT
                | CapFlags::KEY_UPD;
            let mut state = ConnectionState::default();
            state.phase = Phase::AfterVersion;
            state.cap_flags |= session_caps;
            let mut sessions = SessionManager::new();

            let rsp = dispatch_request(
                &mut state,
                &mut sessions,
                &pal,
                capabilities_request(version, 0, 0, CapFlags::CHUNK, 1024, 1024),
            )
            .unwrap();
            let advertised = CapFlags::from_bits(rsp_flags(&rsp));

            assert_eq!(
                advertised.into_bits() & session_caps.into_bits(),
                if secure_message_supported {
                    session_caps.into_bits()
                } else {
                    0
                }
            );
        }
    }
}
