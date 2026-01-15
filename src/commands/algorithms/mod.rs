// Licensed under the Apache-2.0 license

//! Commands related to SPDM Algorithms negotiation
//! See DMTF 0274 - SPDM Base Specification v1.3, Section 10.4 ff.
//!
//! The Algorithms negotiation is performed after the Capabilities exchange
//! and before any other commands that depend on the negotiated algorithms.
//!
//! This module contains the request (`NEGOTIATE_ALGORITHMS`) and response
//! (`ALGORITHMS`) handling and generation logic.

pub mod request;
pub mod response;

pub(crate) use request::*;
pub(crate) use response::*;

use crate::codec::{CommonCodec, MessageBuf};
use crate::protocol::LocalDeviceAlgorithms;
use crate::protocol::{algorithms::DheNamedGroup, SpdmMsgHdr, SpdmVersion};
use bitfield::bitfield;
use core::mem::size_of;

use crate::protocol::algorithms::{
    BaseAsymAlgo, BaseHashAlgo, MeasurementHashAlgo, MeasurementSpecification, MelSpecification,
    OtherParamSupport,
};

use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::error::{SpdmError, SpdmResult};

// Max request length shall be 128 bytes (SPDM1.3 Table 10.4)
const MAX_SPDM_REQUEST_LENGTH: u16 = 128;
const MAX_SPDM_EXT_ALG_COUNT_V10: u8 = 8;
const MAX_SPDM_EXT_ALG_COUNT_V11: u8 = 20;
const MAX_SPDM_EXT_ALG_COUNT_V13: u8 = 20;

#[derive(IntoBytes, FromBytes, Immutable, Default, Debug)]
#[repr(C, packed)]
/// This request message shall negotiate cryptographic algorithms. A Requester shall not issue a NEGOTIATE_ALGORITHMS
/// request message until it receives a successful CAPABILITIES response message.
///
/// A Requester shall not issue any other SPDM requests, with the exception of GET_VERSION until it receives a successful
/// ALGORITHMS response message.
///
/// This structure represents the NEGOTIATE_ALGORITHMS request message, **WITHOUT** the variable-length
/// algorithm structure tables and extended algorithm structures that follow this header,
/// namely
/// - ExtAsym (4 * A), see [ExtendedAlgo].
/// - ExtHash (4 * E), see [ExtendedAlgo].
/// - ReqAlgStruct (AlgStructSize), see [AlgStructure].
struct NegotiateAlgorithmsReq {
    /// The number of algorithm structure tables in this request using `ReqAlgStruct`.
    num_alg_struct_tables: u8, // param 1

    /// Reserved.
    param2: u8,

    /// The length of the entire request message, in bytes. Length shall be less
    /// than or equal to 128 bytes.
    length: u16,

    /// For each defined measurement specification a Requester supports, the
    /// Requester can set the appropriate bits.
    ///
    /// See [MeasurementSpecification] for details.
    measurement_specification: MeasurementSpecification,

    /// Bit mask listing other parameters supported by the Requester.
    /// Introduced in v1.2.
    ///
    /// See [OtherParamSupport] for details.
    other_param_support: OtherParamSupport,

    /// Bit mask listing Requester-supported SPDM-enumerated asymmetric key signature
    /// algorithms for the purpose of signature verification. If the Requester does
    /// not support any request/ response pair that requires signature verification,
    /// this value shall be set to zero. If the Requester will not send any requests
    /// that require a signature, this value should be set to zero.
    /// Let SigLen be the size of the signature in bytes.
    ///
    /// See [BaseAsymAlgo] for details.
    base_asym_algo: BaseAsymAlgo,

    /// Bit mask listing Requester-supported SPDM-enumerated cryptographic hashing
    /// algorithms. If the Requester does not support any request/response pair
    /// that requires hashing operations, this value shall be set to zero.
    ///
    /// See [BaseHashAlgo] for details.
    base_hash_algo: BaseHashAlgo,

    /// Reserved.
    reserved_1: [u8; 12],

    /// The number of Requester-supported extended asymmetric key signature algorithms
    /// (=A) for the purpose of signature verification.
    /// A + E + ExtAlgCount2 + ExtAlgCount3 + ExtAlgCount4 + ExtAlgCount5 shall be
    /// less than or equal to `20`. If the Requester does not support any request/response
    /// pair that requires signature verification, this value shall be set to zero.
    ///
    /// See [MAX_SPDM_EXT_ALG_COUNT_V11], [MAX_SPDM_EXT_ALG_COUNT_V13];
    ext_asym_count: u8,

    /// Shall be the number of Requester-supported extended hashing algorithms (=E).
    /// A + E + ExtAlgCount2 + ExtAlgCount3 + ExtAlgCount4 + ExtAlgCount5 shall be
    /// less than or equal to `20`. If the Requester does not support any request/response
    /// pair that requires hashing operations, this value shall be set to zero.
    ///
    /// See [MAX_SPDM_EXT_ALG_COUNT_V11], [MAX_SPDM_EXT_ALG_COUNT_V13];
    ext_hash_count: u8,

    /// Reserved.
    reserved_2: u8,

    /// The Requester shall set the corresponding bit for each supported measurement
    /// extension log (MEL) specification.
    /// Introduced in v1.3.
    ///
    /// See [MelSpecification] for details.
    mel_specification: MelSpecification,
}

impl NegotiateAlgorithmsReq {
    /// Returns a new `NegotiateAlgorithmsReq` with the provided parameters.
    /// IT does **NOT** include the variable-length algorithm structure tables and
    /// extended algorithm structures that follow this header.
    /// Although, the length field is calculated and set as if they were included,
    /// to make it easier to later generate the full request and be compatible with
    /// the SPDM specification description of the fields provided.
    ///
    /// It does *NOT* validate the total extended algorithm count against the SPDM version.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        num_alg_struct_tables: u8,
        param2: u8,
        measurement_specification: MeasurementSpecification,
        other_param_support: OtherParamSupport,
        base_asym_algo: BaseAsymAlgo,
        base_hash_algo: BaseHashAlgo,
        ext_asyn_count: u8,
        ext_hash_count: u8,
        mel_specification: MelSpecification,
    ) -> SpdmResult<NegotiateAlgorithmsReq> {
        let mut req = NegotiateAlgorithmsReq {
            num_alg_struct_tables,
            param2,
            length: 0,
            measurement_specification,
            other_param_support,
            base_asym_algo,
            base_hash_algo,
            reserved_1: [0u8; 12],
            ext_asym_count: ext_asyn_count,
            ext_hash_count,
            reserved_2: 0,
            mel_specification,
        };

        req.length = req.min_req_len();

        if req.length > MAX_SPDM_REQUEST_LENGTH {
            return Err(SpdmError::InvalidParam);
        }

        Ok(req)
    }

    /// Calculate the minimum required length of the request based on the number of
    /// algorithm structure tables and extended algorithm structures in bytes.
    fn min_req_len(&self) -> u16 {
        let total_alg_struct_len = size_of::<AlgStructure>() * self.num_alg_struct_tables as usize;
        let total_ext_asym_len = size_of::<ExtendedAlgo>() * self.ext_asym_count as usize;
        let total_ext_hash_len = size_of::<ExtendedAlgo>() * self.ext_hash_count as usize;
        (size_of::<SpdmMsgHdr>()
            + size_of::<NegotiateAlgorithmsReq>()
            + total_alg_struct_len
            + total_ext_asym_len
            + total_ext_hash_len
            + 4) as u16
    }

    /// Calculate the size of the extended algorithm structures in bytes.
    /// This includes both extended asymmetric and extended hash algorithms.
    pub fn ext_algo_size(&self) -> usize {
        let ext_algo_count = self.ext_asym_count as usize + self.ext_hash_count as usize;
        size_of::<ExtendedAlgo>() * ext_algo_count
    }

    /// Validate that the total number of extended algorithms does not exceed
    /// the maximum allowed for the given SPDM version.
    ///
    /// # Arguments
    /// - `version`: The SPDM version in use.
    /// - `total_ext_alg_count`: The total number of extended algorithms (A + E).
    ///
    /// # Returns
    /// - `Ok(())` if the count is valid.
    /// - `Err(SpdmError::InvalidParam)` if the count exceeds the maximum
    pub fn validate_total_ext_alg_count(
        &self,
        version: SpdmVersion,
        total_ext_alg_count: u8,
    ) -> SpdmResult<()> {
        if total_ext_alg_count
            > match version {
                SpdmVersion::V10 => MAX_SPDM_EXT_ALG_COUNT_V10,
                SpdmVersion::V11 => MAX_SPDM_EXT_ALG_COUNT_V11,
                SpdmVersion::V13 => MAX_SPDM_EXT_ALG_COUNT_V13,
                _ => MAX_SPDM_EXT_ALG_COUNT_V11,
            }
        {
            Err(SpdmError::InvalidParam)
        } else {
            Ok(())
        }
    }
}

impl CommonCodec for NegotiateAlgorithmsReq {}

#[derive(IntoBytes, FromBytes, Immutable, Default)]
#[repr(C, packed)]
#[allow(dead_code)]
/// # NOTE
/// After this response we expect to be present when sent:
/// - ExtAsymSel
/// - ExtHashSel
/// - RespAlgStruct
pub struct AlgorithmsResp {
    /// Shall be the number of algorithm structure tables in this request using RespAlgStruct.
    num_alg_struct_tables: u8,
    reserved_1: u8,

    /// Shall be the length of the response message, in bytes.
    length: u16,

    /// The Responder shall select one of the measurement specifications supported by the
    /// Requester and Responder. Thus, no more than one bit shall be set
    measurement_specification_sel: MeasurementSpecification,

    /// Shall be the selected Parameter Bit Mask. The Responder shall select one
    /// of the opaque data formats supported by the Requester. Thus, no more
    /// than one bit shall be set for the opaque data format.
    other_params_selection: OtherParamSupport,

    measurement_hash_algo: MeasurementHashAlgo,
    base_asym_sel: BaseAsymAlgo,
    base_hash_sel: BaseHashAlgo,
    reserved_2: [u8; 11],
    mel_specification_sel: MelSpecification,
    ext_asym_sel_count: u8,
    ext_hash_sel_count: u8,
    reserved_3: [u8; 2],
    // - ExtAsymSel
    // - ExtHashSel
    // - RespAlgStruct
}

impl CommonCodec for AlgorithmsResp {}

#[derive(IntoBytes, FromBytes, Immutable, Default)]
#[repr(C)]
/// See [DSP0274 v1.3.0, p, 86](https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.3.0.pdf)
pub struct ExtendedAlgo {
    /// Shall represent the registry or standards body.
    ///
    /// See [RegistryId] for details.
    registry_id: u8,

    /// Reserved.
    reserved: u8,

    /// Shall indicate the desired algorithm. The registry or standards body owns
    /// the value of this field. See [RegistryId]. At present, DMTF does not define
    /// any algorithms for use in extended algorithms fields.
    algorithm_id: u16,
}

impl CommonCodec for ExtendedAlgo {}

impl ExtendedAlgo {
    pub fn new(registry_id: RegistryId, algorithm_id: u16) -> Self {
        ExtendedAlgo {
            registry_id: registry_id as u8,
            reserved: 0,
            algorithm_id,
        }
    }
}

/// Registry or standards body ID for algorithm encoding in extended algorithm fields.
/// Consult the respective registry or standards body unless otherwise specified.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryId {
    /// DMTF does not have a Vendor ID registry.
    DMTF = 0x0,

    /// VendorID is identified by using TCG Vendor ID Registry.
    /// For extended algorithms, see TCG Algorithm Registry.
    TCG = 0x1,

    /// VendorID is identified by using the vendor ID assigned by USB.
    USB = 0x2,

    /// VendorID is identified using PCI-SIG Vendor ID.
    PCISIG = 0x3,

    /// The Private Enterprise Number (PEN) assigned by the Internet Assigned
    /// Numbers Authority (IANA) identifies the vendor.
    IANA = 0x4,

    /// VendorID is identified by using HDBaseT HDCD entity.
    HDBASET = 0x5,

    /// The Manufacturer ID assigned by MIPI identifies the vendor.
    MIPI = 0x6,

    /// VendorID is identified by using CXL vendor ID.
    CXL = 0x7,

    /// VendorID is identified by using JEDEC vendor ID.
    JEDEC = 0x8,

    /// For fields and formats defined by the VESA standards body,
    /// there is no Vendor ID registry.
    VESA = 0x9,

    /// The CBOR Tag Registry that identifies the format of the element,
    /// as assigned by the Internet Assigned Numbers Authority (IANA).
    /// The encoding of the CBOR tag indicates the length of the tag.
    /// When a CBOR Tag is used with a standards body or vendor-defined header,
    /// the VendorIDLen field shall be set to the length of the encoded CBOR tag,
    /// followed by the data payload, which starts with an encoded CBOR tag.
    IANACBOR = 0xA,
}

impl RegistryId {
    /// Returns the vendor ID length in bytes for this registry.
    /// Returns None for variable-length registries (IANA CBOR).
    pub const fn vendor_id_length(&self) -> Option<usize> {
        match self {
            Self::DMTF => Some(0),
            Self::TCG => Some(2),
            Self::USB => Some(2),
            Self::PCISIG => Some(2),
            Self::IANA => Some(4),
            Self::HDBASET => Some(4),
            Self::MIPI => Some(2),
            Self::CXL => Some(2),
            Self::JEDEC => Some(2),
            Self::VESA => Some(0),
            Self::IANACBOR => None, // Variable length
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum AlgType {
    // 0x00 and 0x01. Reserved.
    Dhe = 2,
    AeadCipherSuite = 3,
    ReqBaseAsymAlg = 4,
    KeySchedule = 5,
}

impl TryFrom<u8> for AlgType {
    type Error = SpdmError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            2 => Ok(AlgType::Dhe),
            3 => Ok(AlgType::AeadCipherSuite),
            4 => Ok(AlgType::ReqBaseAsymAlg),
            5 => Ok(AlgType::KeySchedule),
            _ => Err(SpdmError::InvalidParam),
        }
    }
}

impl TryFrom<u16> for AlgType {
    type Error = SpdmError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            2 => Ok(AlgType::Dhe),
            3 => Ok(AlgType::AeadCipherSuite),
            4 => Ok(AlgType::ReqBaseAsymAlg),
            5 => Ok(AlgType::KeySchedule),
            _ => Err(SpdmError::InvalidParam),
        }
    }
}

#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, Immutable, Default)]
#[repr(C, packed)]
/// Shall be the Requester-supported fixed algorithms.
pub struct AlgCount(u8);

impl AlgCount {
    pub fn get(&self) -> u8 {
        self.0
    }

    pub fn set(&mut self, count: u8) {
        self.0 = count;
    }

    /// Number of bytes required to describe Requester-supported SPDM-enumerated
    /// fixed algorithms (=FixedAlgCount). FixedAlgCount + 2 shall be a multiple of 4.
    pub fn num_(&self) -> u8 {
        self.0 & 0b11111000
    }

    /// Number of Requester-supported extended algorithms (= ExtAlgCount ).
    pub fn rum_req_supported_algos(&self) -> u8 {
        self.0 & 0b00000111
    }
}

impl From<u8> for AlgCount {
    fn from(value: u8) -> Self {
        Self(value)
    }
}

impl CommonCodec for AlgCount {}

bitfield! {
    #[derive(FromBytes, IntoBytes, Immutable, Default, Clone, Copy)]
    #[repr(C)]
    /// This structure describes an algorithm structure table.
    /// It does **NOT** include the variable-length `AlgExternal` fields that follow this header for the Request.
    ///
    /// The `AlgExternal` fields are of type [ExtendedAlgo] and their number is defined
    /// by the `ExtAlgCount` field.
    /// The existence of `AlgExternal` is optional.
    // TODO: make this a structure with Option?
    pub struct AlgStructure(u32);
    impl Debug;
    u8;
        /// Shall be the type of algorithm.
        ///
        /// See [AlgType] for details.
        pub alg_type, set_alg_type: 7, 0;

        /// Shall be the bit mask listing Responder-supported fixed algorithm requested by the Requester.
        /// This value shall be either 0 or 1.
        /// That means, that there is either 1 or None external algorithm structure following this header.
        pub ext_alg_count, set_ext_alg_count: 11, 8;
        pub fixed_alg_count, set_fixed_alg_count: 15, 12;
    u16;
        // TODO: somehow we can just assume this will fit? and why do we
        pub alg_supported, set_alg_supported: 31, 16;
        // AlgExternal
}

impl AlgStructure {
    // FixedAlgCount + 2 shall be a multiple of 4
    pub fn is_multiple(&self) -> bool {
        ((self.fixed_alg_count() as usize) + 2).is_multiple_of(4)
    }

    /// Create a new [AlgStructure] for the given algorithm type as specified in
    // Tables 17, 18, 19, 20 of DSP0274 v1.3.0
    pub fn new(alg_type: &AlgType, local_algos: &LocalDeviceAlgorithms) -> AlgStructure {
        let mut res = AlgStructure::default();
        res.set_alg_type(*alg_type as u8);

        // Bit [7:4]. Shall be a value of 2.
        res.set_fixed_alg_count(2);

        match alg_type {
            AlgType::Dhe => {
                res.set_alg_supported(local_algos.device_algorithms.dhe_group.0);
            }

            AlgType::AeadCipherSuite => {
                res.set_alg_supported(local_algos.device_algorithms.aead_cipher_suite.0);
            }

            AlgType::ReqBaseAsymAlg => {
                res.set_alg_supported(local_algos.device_algorithms.req_base_asym_algo.0);
            }

            AlgType::KeySchedule => {
                res.set_alg_supported(local_algos.device_algorithms.key_schedule.0);
            }
        }
        res.set_ext_alg_count(res.alg_supported().count_ones() as u8);
        res
    }
}

impl CommonCodec for AlgStructure {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_min_req_len() {
        todo!();
    }
}
