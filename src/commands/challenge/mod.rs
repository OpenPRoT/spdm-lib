// Licensed under the Apache-2.0 license

use crate::codec::{Codec, CommonCodec, MessageBuf};
use crate::protocol::{SpdmVersion, SHA384_HASH_SIZE};
use bitfield::bitfield;
use zerocopy::{FromBytes, Immutable, IntoBytes};

pub mod request;
pub mod response;

pub(crate) use request::*;
pub(crate) use response::*;

const NONCE_LEN: usize = 32;
const CONTEXT_LEN: usize = 8;
const OPAQUE_DATA_MAX: usize = 1024;

/// 0x02..0xFE are reserved
#[derive(Debug, PartialEq, Clone)]
#[repr(u8)]
pub enum MeasurementSummaryHashType {
    None = 0x00,
    /// # Trusted Computing Base
    ///
    /// Set of all hardware, firmware, and/or software components that are critical
    /// to its security, in the sense that bugs or vulnerabilities occurring inside
    /// the TCB might jeopardize the security properties of the entire system.
    Tcb = 0x01,
    All = 0xFF,
}

impl TryFrom<u8> for MeasurementSummaryHashType {
    type Error = ();
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::None),
            0x01 => Ok(Self::Tcb),
            0xFF => Ok(Self::All),
            _ => Err(()),
        }
    }
}

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
// TODO: check backwards compatibility of this struct with the original ChallengeReq struct
struct ChallengeReq {
    /// Slot number of the Responder certificate chain that shall be used for authentication.
    /// If the public key of the Responder was provisioned to the Requester in a
    /// trusted environment, the value in this field shall be 0xFF ; otherwise it
    /// shall be between 0 and 7 inclusive.
    slot_id: u8,

    /// Shall be the type of measurement summary hash requested.
    measurement_hash_type: u8,

    /// The Requester should choose a random value.
    nonce: [u8; NONCE_LEN],

    /// The Requester can include application-specific information in Context.
    /// The Requester should fill this field with zeros if it has no context to provide.
    context: [u8; CONTEXT_LEN],
}
impl CommonCodec for ChallengeReq {}

impl ChallengeReq {
    /// Creates a new `CHALLENGE` request message.
    ///
    /// # Arguments
    ///
    /// * `slot_id` - Slot number (0..=7) of the Responder certificate chain to use for
    ///   authentication, or `0xFF` if the public key was provisioned in a trusted environment.
    ///   Stored as a bitmask with the corresponding bit set.
    /// * `measurement_hash_type` - The type of measurement summary hash requested from the
    ///   Responder.
    /// * `nonce` - A random 32-byte value chosen by the Requester for freshness.
    /// * `context` - Optional 8-byte application-specific context. Defaults to all zeros when
    ///   `None`.
    pub fn new(
        slot_id: u8,
        measurement_hash_type: MeasurementSummaryHashType,
        nonce: [u8; NONCE_LEN],
        context: Option<[u8; CONTEXT_LEN]>,
    ) -> Self {
        Self {
            slot_id,
            measurement_hash_type: measurement_hash_type as u8,
            nonce,
            context: context.unwrap_or([0; CONTEXT_LEN]),
        }
    }
}

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
struct ChallengeAuthRspBase {
    challenge_auth_attr: ChallengeAuthAttr,
    slot_mask: u8,

    /// Shall be either the hash of the certificate chain if the public key of the
    /// Responder was provisioned to the Requester in a trusted environment, the
    /// public key used for authentication.
    ///
    /// The Requester can use this value to check that the certificate chain or
    /// public key matches the one requested.
    cert_chain_hash: [u8; SHA384_HASH_SIZE],

    /// Shall be the Responder-selected random value
    nonce: [u8; NONCE_LEN],
    // Followed by:
    // - MeasurementSummaryHash
    // - OpaqueDataLength
    // - OpaqueData
    // - RequesterContext
    // - Signature
}

impl CommonCodec for ChallengeAuthRspBase {}

impl ChallengeAuthRspBase {
    /// Creates a new `ChallengeAuthRspBase` with the specified slot ID.
    ///
    /// # Arguments
    ///
    /// * `slot_id` - The slot ID Bit to be set in the response.
    fn new(slot_id: u8) -> Self {
        Self {
            challenge_auth_attr: ChallengeAuthAttr(slot_id),
            slot_mask: 1 << slot_id,
            cert_chain_hash: [0; SHA384_HASH_SIZE],
            nonce: [0; NONCE_LEN],
        }
    }
}

bitfield! {
    #[derive(FromBytes, IntoBytes, Immutable)]
    #[repr(C)]
    struct ChallengeAuthAttr(u8);
    impl Debug;
    u8;
    /// Shall contain the `SlotID` in the Param1 `field` of the corresponding `CHALLENGE` request.
    /// If the Responder's public key was provisioned to the Requester previously, this field shall
    /// be 0xF. The Requester can use this value to check that the certificate matched what was requested.
    pub slot_id, set_slot_id: 3, 0;
    reserved, _: 7, 4;
}

pub(crate) fn challenge_auth_sig_verify() {}
