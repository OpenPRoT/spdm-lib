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

pub(crate) use request::*;
pub(crate) use response::*;

use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::{codec::CommonCodec, protocol::CapabilityFlags};

use crate::protocol::capabilities::DeviceCapabilities;

#[derive(IntoBytes, FromBytes, Immutable, Default)]
#[repr(C)]
pub struct GetCapabilitiesBase {
    param1: u8,
    param2: u8,
}
/// CAPABILITIES response base
///
/// v1.0 CAPABILITIES response is constructed by `CapabilitiesBase`+`Capabilities`.
pub type CapabilitiesBase = GetCapabilitiesBase;

impl CommonCodec for GetCapabilitiesBase {}

#[derive(IntoBytes, FromBytes, Immutable, Default)]
#[repr(C, packed)]
#[allow(dead_code)]
pub struct GetCapabilitiesV11 {
    /// Reserved.
    reserved: u8,

    /// Shall be exponent of base 2, which is used to calculate CT .
    /// The equation for CT shall be 2^{CTExponent} microseconds (μs).
    /// # Example
    /// CT=10 -> 2^10 = 1024 μs = 1.024 ms
    pub ct_exponent: u8,

    /// Reserved.
    ///
    /// _TODO_: Part of the 16-bit extended flags field added in v1.4.0
    reserved2: u8,

    /// Reserved.
    ///
    /// _TODO_: Part of the 16-bit extended flags field added in v1.4.0
    reserved3: u8,

    /// Capability flags.
    flags: CapabilityFlags,
}
/// CAPABILITIES response
pub type Capabilities = GetCapabilitiesV11;

impl GetCapabilitiesV11 {
    pub fn new(ct_exponent: u8, flags: CapabilityFlags) -> Self {
        Self {
            reserved: 0,
            ct_exponent,
            reserved2: 0,
            reserved3: 0,
            flags,
        }
    }
}

impl CommonCodec for GetCapabilitiesV11 {}

/// DSP0274, Table 11
#[derive(IntoBytes, FromBytes, Immutable)]
#[repr(C, packed)]
pub struct GetCapabilitiesV12 {
    /// This field shall indicate the maximum buffer size, in
    /// bytes, of the Requester for receiving a single and
    /// complete SPDM message whose message size is less
    /// than or equal to the value in this field.
    data_transfer_size: u32,

    ///  If the Requester supports the Large SPDM message
    /// transfer mechanism, this field shall indicate the
    /// maximum size, in bytes, of the internal buffer of a
    /// Requester used to reassemble a single and complete
    /// Large SPDM message.
    max_spdm_msg_size: u32,
}
/// CAPABILITIES response v1.2 additions
pub type CapabilitiesV12 = GetCapabilitiesV12;

impl CommonCodec for GetCapabilitiesV12 {}

/// Although [GetCapabilitiesBase], [GetCapabilitiesV11] and [GetCapabilitiesV12]
/// are more generic, the context currently uses [crate::protocol::capabilities::DeviceCapabilities].
/// Until we refactor the context, this function translates from one to the other.
impl From<&DeviceCapabilities> for GetCapabilitiesV11 {
    fn from(dev_cap: &DeviceCapabilities) -> Self {
        Self::new(dev_cap.ct_exponent, dev_cap.flags)
    }
}

impl From<&DeviceCapabilities> for GetCapabilitiesV12 {
    fn from(dev_cap: &DeviceCapabilities) -> Self {
        Self {
            data_transfer_size: dev_cap.data_transfer_size,
            max_spdm_msg_size: dev_cap.max_spdm_msg_size,
        }
    }
}

impl Default for GetCapabilitiesV12 {
    fn default() -> Self {
        GetCapabilitiesV12 {
            data_transfer_size: crate::protocol::MIN_DATA_TRANSFER_SIZE_V12,
            max_spdm_msg_size: crate::protocol::MIN_DATA_TRANSFER_SIZE_V12,
        }
    }
}
