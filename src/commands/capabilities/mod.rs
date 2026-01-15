// Licensed under the Apache-2.0 license

pub mod request;
pub mod response;

pub(crate) use request::*;
pub(crate) use response::*;

use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::{
    codec::CommonCodec,
    protocol::{CapabilityFlags, EpInfoCapability, PskCapability, SpdmVersion},
};

use crate::protocol::capabilities::DeviceCapabilities;

#[derive(IntoBytes, FromBytes, Immutable, Default)]
#[repr(C)]
pub struct GetCapabilitiesBase {
    param1: u8,
    param2: u8,
}

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
    reserved2: u8,

    /// Reserved.
    reserved3: u8,

    /// Capability flags.
    flags: CapabilityFlags,
}

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

/// Checks if the request capability flags are compatible with the SPDM version
///# Arguments
/// - `version`: SPDM version
/// - `flags`: Capability flags from the request
///
/// # Returns
/// - true if compatible
/// - false if incompatible
pub(crate) fn req_flag_compatible(version: SpdmVersion, flags: &CapabilityFlags) -> bool {
    // Checks specific to 1.1
    if version == SpdmVersion::V11 && flags.mut_auth_cap() == 1 && flags.encap_cap() == 0 {
        return false;
    }

    // Checks common to 1.1 and higher
    if version >= SpdmVersion::V11 {
        // Illegal to return reserved values (2 and 3)
        if flags.psk_cap() >= PskCapability::PskWithContext as u8 {
            return false;
        }

        // Checks that originate from key exchange capabilities
        if flags.key_ex_cap() == 1 || flags.psk_cap() != PskCapability::NoPsk as u8 {
            if flags.mac_cap() == 0 && flags.encrypt_cap() == 0 {
                return false;
            }
        } else {
            if flags.mac_cap() == 1
                || flags.encrypt_cap() == 1
                || flags.handshake_in_the_clear_cap() == 1
                || flags.hbeat_cap() == 1
                || flags.key_upd_cap() == 1
            {
                return false;
            }

            if version >= SpdmVersion::V13 && flags.event_cap() == 1 {
                return false;
            }
        }

        if flags.key_ex_cap() == 0
            && flags.psk_cap() == PskCapability::PskWithNoContext as u8
            && flags.handshake_in_the_clear_cap() == 1
        {
            return false;
        }

        // Checks that originate from certificate or public key capabilities
        if flags.cert_cap() == 1 || flags.pub_key_id_cap() == 1 {
            // Certificate capabilities and public key capabilities can not both be set
            if flags.cert_cap() == 1 && flags.pub_key_id_cap() == 1 {
                return false;
            }

            if flags.chal_cap() == 0 && flags.pub_key_id_cap() == 1 {
                return false;
            }
        } else {
            // If certificates or public keys are not enabled then these capabilities are not allowed
            if flags.chal_cap() == 1 || flags.mut_auth_cap() == 1 {
                return false;
            }

            if version >= SpdmVersion::V13
                && flags.ep_info_cap() == EpInfoCapability::EpInfoWithSignature as u8
            {
                return false;
            }
        }

        // Checks that originate from mutual authentication capabilities
        if flags.mut_auth_cap() == 1 {
            // Mutual authentication with asymmetric keys can only occur through the basic mutual
            // authentication flow (CHAL_CAP == 1) or the session-based mutual authentication flow
            // (KEY_EX_CAP == 1)
            if flags.cert_cap() == 0 && flags.pub_key_id_cap() == 0 {
                return false;
            }
        }
    }

    // Checks specific to 1.3 and higher
    if version >= SpdmVersion::V13 {
        // Illegal to return reserved values
        if flags.ep_info_cap() == EpInfoCapability::Reserved as u8 || flags.multi_key_cap() == 3 {
            return false;
        }

        // Check multi_key_cap and pub_key_id_cap
        if flags.multi_key_cap() != 0 && flags.pub_key_id_cap() == 1 {
            return false;
        }
    }

    true
}
