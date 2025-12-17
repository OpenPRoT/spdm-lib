// Licensed under the Apache-2.0 license

mod request;
mod response;

pub(crate) use request::*;
pub(crate) use response::*;

use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::{
    codec::CommonCodec,
    protocol::{CapabilityFlags, EpInfoCapability, PskCapability, SpdmVersion},
};

#[derive(IntoBytes, FromBytes, Immutable, Default)]
#[repr(C)]
pub(crate) struct GetCapabilitiesBase {
    param1: u8,
    param2: u8,
}

impl CommonCodec for GetCapabilitiesBase {}

#[derive(IntoBytes, FromBytes, Immutable, Default)]
#[repr(C, packed)]
#[allow(dead_code)]
pub(crate) struct GetCapabilitiesV11 {
    reserved: u8,
    ct_exponent: u8,
    reserved2: u8,
    reserved3: u8,
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

#[derive(IntoBytes, FromBytes, Immutable)]
#[repr(C, packed)]
pub(crate) struct GetCapabilitiesV12 {
    data_transfer_size: u32,
    max_spdm_msg_size: u32,
}

impl CommonCodec for GetCapabilitiesV12 {}

fn req_flag_compatible(version: SpdmVersion, flags: &CapabilityFlags) -> bool {
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

    // Checks specific to 1.1
    if version == SpdmVersion::V11 && flags.mut_auth_cap() == 1 && flags.encap_cap() == 0 {
        return false;
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
