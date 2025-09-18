// Licensed under the Apache-2.0 license

//! Linux placeholder certificate store implementation.
//!
//! This provides an empty (unprovisioned) certificate store implementing the
//! `SpdmCertStore` trait so higher level code can compile and exercise flows
//! that query slot counts / provisioning state without requiring real X.509
//! material. All operations return sizes of zero or appropriate errors when
//! attempting to read / sign.

use crate::cert_store::{CertStoreError, CertStoreResult, SpdmCertStore, MAX_CERT_SLOTS_SUPPORTED};
use crate::protocol::algorithms::{AsymAlgo, ECC_P384_SIGNATURE_SIZE, SHA384_HASH_SIZE};
use crate::protocol::certs::{CertificateInfo, KeyUsageMask};

/// Placeholder Linux certificate store with no provisioned slots.
#[derive(Default, Debug)]
pub struct SpdmLinuxCertStore {
    slot_count: u8,
}

impl SpdmLinuxCertStore {
    pub fn new() -> Self { Self { slot_count: 0 } }
}

impl SpdmCertStore for SpdmLinuxCertStore {
    fn slot_count(&self) -> u8 { self.slot_count.min(MAX_CERT_SLOTS_SUPPORTED) }

    fn is_provisioned(&self, _slot_id: u8) -> bool { false }

    fn cert_chain_len(&mut self, _asym_algo: AsymAlgo, slot_id: u8) -> CertStoreResult<usize> {
        if slot_id >= self.slot_count() { return Err(CertStoreError::InvalidSlotId); }
        Ok(0)
    }

    fn get_cert_chain<'a>(
        &mut self,
        slot_id: u8,
        _asym_algo: AsymAlgo,
        offset: usize,
        cert_portion: &'a mut [u8],
    ) -> CertStoreResult<usize> {
        if slot_id >= self.slot_count() { return Err(CertStoreError::InvalidSlotId); }
        if offset != 0 { return Err(CertStoreError::InvalidOffset); }
        for b in cert_portion.iter_mut() { *b = 0; }
        Ok(0)
    }

    fn root_cert_hash<'a>(
        &mut self,
        slot_id: u8,
        _asym_algo: AsymAlgo,
        cert_hash: &'a mut [u8; SHA384_HASH_SIZE],
    ) -> CertStoreResult<()> {
        if slot_id >= self.slot_count() { return Err(CertStoreError::InvalidSlotId); }
        cert_hash.fill(0);
        Err(CertStoreError::CertReadError)
    }

    fn sign_hash<'a>(
        &self,
        slot_id: u8,
        _hash: &'a [u8; SHA384_HASH_SIZE],
        _signature: &'a mut [u8; ECC_P384_SIGNATURE_SIZE],
    ) -> CertStoreResult<()> {
        if slot_id >= self.slot_count() { return Err(CertStoreError::InvalidSlotId); }
        Err(CertStoreError::CertReadError)
    }

    fn key_pair_id(&self, _slot_id: u8) -> Option<u8> { None }

    fn cert_info(&self, _slot_id: u8) -> Option<CertificateInfo> { None }

    fn key_usage_mask(&self, _slot_id: u8) -> Option<KeyUsageMask> { None }
}
