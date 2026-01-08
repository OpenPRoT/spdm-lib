// Licensed under the Apache-2.0 license
pub mod request;
pub mod response;

pub(crate) use request::*;
pub(crate) use response::*;

use crate::{
    codec::{Codec, CommonCodec, MessageBuf},
    protocol::SpdmVersion,
};
use bitfield::bitfield;
use zerocopy::{FromBytes, Immutable, IntoBytes};

const VERSION_ENTRY_SIZE: usize = 2;

#[allow(dead_code)]
#[derive(FromBytes, IntoBytes, Immutable)]
pub struct VersionReqPayload {
    param1: u8,
    param2: u8,
}

impl VersionReqPayload {
    pub fn new(param1: u8, param2: u8) -> Self {
        Self { param1, param2 }
    }
}

#[allow(dead_code)]
#[derive(FromBytes, IntoBytes, Immutable)]
struct VersionRespCommon {
    param1: u8,
    param2: u8,
    reserved: u8,
    version_num_entry_count: u8,
}

impl CommonCodec for VersionReqPayload {}

impl Default for VersionRespCommon {
    fn default() -> Self {
        VersionRespCommon::new(0)
    }
}

impl VersionRespCommon {
    pub fn new(entry_count: u8) -> Self {
        VersionRespCommon {
            param1: 0,
            param2: 0,
            reserved: 0,
            version_num_entry_count: entry_count,
        }
    }
}

impl CommonCodec for VersionRespCommon {}

bitfield! {
#[repr(C)]
#[derive(FromBytes, IntoBytes, Immutable)]
pub struct VersionNumberEntry(MSB0 [u8]);
impl Debug;
u8;
    pub update_ver, set_update_ver: 3, 0;
    pub alpha, set_alpha: 7, 4;
    pub major, set_major: 11, 8;
    pub minor, set_minor: 15, 12;
}

impl Default for VersionNumberEntry<[u8; VERSION_ENTRY_SIZE]> {
    fn default() -> Self {
        VersionNumberEntry::new(SpdmVersion::default())
    }
}

impl VersionNumberEntry<[u8; VERSION_ENTRY_SIZE]> {
    pub fn new(version: SpdmVersion) -> Self {
        let mut entry = VersionNumberEntry([0u8; VERSION_ENTRY_SIZE]);
        entry.set_major(version.major());
        entry.set_minor(version.minor());
        entry
    }
}

impl CommonCodec for VersionNumberEntry<[u8; VERSION_ENTRY_SIZE]> {}

pub struct FromVersionNumberEntryError;

impl TryFrom<VersionNumberEntry<[u8; VERSION_ENTRY_SIZE]>> for SpdmVersion {
    type Error = FromVersionNumberEntryError;

    fn try_from(value: VersionNumberEntry<[u8; VERSION_ENTRY_SIZE]>) -> Result<Self, Self::Error> {
        match (value.major(), value.minor()) {
            (1, 0) => Ok(SpdmVersion::V10),
            (1, 1) => Ok(SpdmVersion::V11),
            (1, 2) => Ok(SpdmVersion::V12),
            (1, 3) => Ok(SpdmVersion::V13),
            (_, _) => Err(FromVersionNumberEntryError),
        }
    }
}
