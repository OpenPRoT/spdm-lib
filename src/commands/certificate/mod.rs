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

pub mod request;
pub mod response;

pub(crate) use response::*;

use crate::cert_store::SpdmCertStore;
use crate::codec::{CommonCodec, MessageBuf};
use crate::error::{CommandError, CommandResult};
use crate::protocol::*;
use bitfield::bitfield;
use zerocopy::{FromBytes, Immutable, IntoBytes};

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
pub struct GetCertificateReq {
    pub slot_id: SlotId,
    pub param2: CertificateReqAttributes,
    pub offset: u16,
    pub length: u16,
    // TODO: v1.4.0 has two additional fields, LargeOffset and LargeLength, and a new SlotId field.
    //       Strangely they are attributed to v1.3.0 in the Changelog though...
}

bitfield! {
    #[derive(FromBytes, IntoBytes, Immutable)]
    #[repr(C)]
    pub struct SlotId(u8);
    impl Debug;
    u8;
    pub slot_id, set_slot_id: 3,0;
    reserved, _: 7,4;
}

bitfield! {
    #[derive(FromBytes, IntoBytes, Immutable)]
    #[repr(C)]
    pub struct CertificateReqAttributes(u8);
    impl Debug;
    u8;
    pub slot_size_requested, set_slot_size_requested: 0,0;
    reserved, _: 7,1;
}

impl CommonCodec for GetCertificateReq {}

#[derive(IntoBytes, FromBytes, Immutable)]
#[repr(C, packed)]
pub struct CertificateRespCommon {
    pub slot_id: SlotId,
    pub param2: CertificateRespAttributes,
    pub portion_length: u16,
    pub remainder_length: u16,
}

impl CommonCodec for CertificateRespCommon {}

impl CertificateRespCommon {
    pub fn new(
        slot_id: SlotId,
        param2: CertificateRespAttributes,
        portion_length: u16,
        remainder_length: u16,
    ) -> Self {
        Self {
            slot_id,
            param2,
            portion_length,
            remainder_length,
        }
    }
}

bitfield! {
    #[derive(FromBytes, IntoBytes, Immutable, Default)]
    #[repr(C)]
    pub struct CertificateRespAttributes(u8);
    impl Debug;
    u8;
    pub certificate_info, set_certificate_info: 2,0;
    reserved, _: 7,3;
}

pub(crate) fn encode_certchain_metadata(
    cert_store: &mut dyn SpdmCertStore,
    total_certchain_len: u16,
    slot_id: u8,
    asym_algo: AsymAlgo,
    offset: usize,
    length: usize,
    rsp: &mut MessageBuf<'_>,
) -> CommandResult<usize> {
    let mut certchain_metadata = [0u8; SPDM_CERT_CHAIN_METADATA_LEN as usize];

    // Read the cert chain header first
    // Currently only cert chains with length <= `u16::MAX` are supported.
    // (So this should never fail.)
    let cert_chain_hdr = SpdmCertChainHeader::new(total_certchain_len as u32, SpdmVersion::V12)
        .map_err(|_| (false, CommandError::InternalError))?;

    let cert_chain_hdr_bytes = cert_chain_hdr.as_bytes();
    certchain_metadata[..cert_chain_hdr_bytes.len()].copy_from_slice(cert_chain_hdr_bytes);

    // Read the root cert hash next
    let mut root_hash_buf = [0u8; SHA384_HASH_SIZE];
    cert_store
        .root_cert_hash(slot_id, asym_algo, &mut root_hash_buf)
        .map_err(|e| (false, CommandError::CertStore(e)))?;
    certchain_metadata[cert_chain_hdr_bytes.len()..].copy_from_slice(&root_hash_buf[..]);

    let write_len = (SPDM_CERT_CHAIN_METADATA_LEN - offset as u16).min(length as u16) as usize;

    rsp.put_data(write_len)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    let cert_portion = rsp
        .data_mut(write_len)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    cert_portion[..write_len].copy_from_slice(&certchain_metadata[offset..offset + write_len]);
    rsp.pull_data(write_len)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    Ok(write_len)
}
