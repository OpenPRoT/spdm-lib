// Licensed under the Apache-2.0 license
use crate::protocol::{SpdmVersion, SHA384_HASH_SIZE};
use bitfield::bitfield;
use zerocopy::{little_endian, FromBytes, Immutable, IntoBytes, KnownLayout};

pub(crate) const SPDM_MAX_CERT_CHAIN_PORTION_LEN: u16 = 512;
pub(crate) const SPDM_CERT_CHAIN_METADATA_LEN: u16 =
    size_of::<SpdmCertChainHeader>() as u16 + SHA384_HASH_SIZE as u16;

#[derive(IntoBytes, FromBytes, Immutable, KnownLayout, Debug, Default)]
#[repr(C, packed)]
pub struct SpdmCertChainHeader {
    /// Length of the CertChain, including this header and the following root hash
    ///
    /// # Versions
    /// ## <= v1.2
    /// Little endian u16 followed by reserved u16.
    /// (this is compatible witht the current >= v1.3 layout)
    /// ## v1.3 and later
    /// Little endian u32.
    length: little_endian::U32,
}
impl SpdmCertChainHeader {
    /// Get the length of the certificate chain
    ///
    /// This includes the length header and root hash.
    pub fn get_length(&self) -> u32 {
        self.length.get()
    }
    /// Checks the version for compatibility and assigns the provided length
    ///
    /// # Versions
    /// ## <= v1.2
    /// Little endian u16 followed by reserved u16.
    /// (this is compatible witht the current >= v1.3 layout)
    /// ## v1.3 and later
    /// Little endian u32.
    pub fn set_length(&mut self, length: u32, version: SpdmVersion) -> Result<(), ()> {
        if length > u16::MAX as u32 && version < SpdmVersion::V13 {
            return Err(());
        }
        self.length.set(length);
        Ok(())
    }
    /// Creates a new certificate chain header with checked version compatibility
    ///
    /// # Versions
    /// ## <= v1.2
    /// Little endian u16 followed by reserved u16.
    /// (this is compatible witht the current >= v1.3 layout)
    /// ## v1.3 and later
    /// Little endian u32.
    pub fn new(length: u32, version: SpdmVersion) -> Result<Self, ()> {
        if length > u16::MAX as u32 && version < SpdmVersion::V13 {
            return Err(());
        }
        Ok(Self {
            length: little_endian::U32::new(length),
        })
    }
}

// SPDM CertificateInfo fields
bitfield! {
#[derive(FromBytes, IntoBytes, Immutable, Default)]
#[repr(C, packed)]
pub struct CertificateInfo(u8);
impl Debug;
u8;
pub cert_model, set_cert_model: 0,2;
reserved, _: 3,7;
}

/// CertModel field used in Certificate Info bitfields in DIGESTS and CERTIFICATE responses
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub(crate) enum CertModel {
    /// Indicates either that the certificate slot does not contain any certificates
    /// or that the corresponding `MULTI_KEY_CONN_REQ` or `MULTI_KEY_CONN_RSP` is false.
    None = 0,
    /// Certificate slot uses the `DeviceCert` model.
    DeviceCert = 1,
    /// Certificate slot uses the `AliasCert` model.
    AliasCert = 2,
    /// Certificate slot uses the `GenericCert` model.
    GenericCert = 3,
    // TODO: Shoud we include a Reserved(u8)
    //       to propagate the error handling further up?
}

#[derive(Debug)]
pub(crate) struct InvalidCertModelError;

impl TryFrom<u8> for CertModel {
    type Error = InvalidCertModelError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(CertModel::None),
            1 => Ok(CertModel::DeviceCert),
            2 => Ok(CertModel::AliasCert),
            3 => Ok(CertModel::GenericCert),
            _ => Err(InvalidCertModelError),
        }
    }
}

// SPDM KeyUsageMask fields
bitfield! {
#[derive(FromBytes, IntoBytes, Immutable, Default)]
#[repr(C)]
pub struct KeyUsageMask(u16);
impl Debug;
u16;
pub key_exch_usage, set_key_exch_usage: 0,0;
pub challenge_usage, set_challenge_usage: 1,1;
pub measurement_usage, set_measurement_usage: 2,2;
pub endpoint_info_usage, set_endpoint_info_usage: 3,3;
reserved, _: 13,4;
pub standards_key_usage, set_standards_key_usage: 14,14;
pub vendor_key_usage, set_vendor_key_usage: 15,15;
}
