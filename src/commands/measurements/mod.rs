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

//! GET_MEASUREMENTS and MEASURMENTS command types and logic

/// Requester logic for GET_MEASUREMENTS and MEASURMENTS
pub mod request;
/// Responder logic for GET_MEASUREMENTS and MEASURMENTS
pub mod response;

use crate::codec::CommonCodec;
use crate::protocol::*;
use bitfield::bitfield;
use zerocopy::{FromBytes, Immutable, IntoBytes};

const RESPONSE_FIXED_FIELDS_SIZE: usize = 8;
const MAX_RESPONSE_VARIABLE_FIELDS_SIZE: usize =
    NONCE_LEN + size_of::<u32>() + size_of::<RequesterContext>();

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
struct GetMeasurementsReqCommon {
    req_attr: GetMeasurementsReqAttr,
    meas_op: u8,
}
impl CommonCodec for GetMeasurementsReqCommon {}

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
struct GetMeasurementsReqSignature {
    requester_nonce: [u8; NONCE_LEN],
    slot_id: u8,
}
impl CommonCodec for GetMeasurementsReqSignature {}

bitfield! {
    #[derive(FromBytes, IntoBytes, Immutable)]
    #[repr(C)]
    struct GetMeasurementsReqAttr(u8);
    impl Debug;
    u8;
    pub signature_requested, set_signature_requested: 0, 0;
    pub raw_bitstream_requested, set_raw_bitstream_requested: 1, 1;
    pub new_measurement_requested, set_new_measurement_requested: 2, 2;
    reserved, _: 7, 3;
}

bitfield! {
    #[derive(FromBytes, IntoBytes, Immutable)]
    #[repr(C)]
    struct MeasurementsRspFixed([u8]);
    impl Debug;
    u8;
    pub spdm_version, set_spdm_version: 7, 0;
    pub req_resp_code, set_req_resp_code: 15, 8;
    pub total_measurement_indices, set_total_measurement_indices: 23, 16;
    pub slot_id, set_slot_id: 27, 24;
    pub content_changed, set_content_changed: 29, 28;
    reserved, _: 31, 30;
    pub num_blocks, set_num_blocks: 39, 32;
    pub measurement_record_len_byte0, set_measurement_record_len_byte0: 47, 40;
    pub measurement_record_len_byte1, set_measurement_record_len_byte1: 55, 48;
    pub measurement_record_len_byte2, set_measurement_record_len_byte2: 63, 56;
}

impl MeasurementsRspFixed<[u8; RESPONSE_FIXED_FIELDS_SIZE]> {
    pub fn set_measurement_record_len(&mut self, len: u32) {
        self.set_measurement_record_len_byte0((len & 0xFF) as u8);
        self.set_measurement_record_len_byte1(((len >> 8) & 0xFF) as u8);
        self.set_measurement_record_len_byte2(((len >> 16) & 0xFF) as u8);
    }
}

impl Default for MeasurementsRspFixed<[u8; RESPONSE_FIXED_FIELDS_SIZE]> {
    fn default() -> Self {
        Self([0; RESPONSE_FIXED_FIELDS_SIZE])
    }
}

impl CommonCodec for MeasurementsRspFixed<[u8; RESPONSE_FIXED_FIELDS_SIZE]> {}
