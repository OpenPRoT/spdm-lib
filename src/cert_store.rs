// Licensed under the Apache-2.0 license

use crate::error::{SpdmError, SpdmResult};
use crate::protocol::algorithms::{AsymAlgo, ECC_P384_SIGNATURE_SIZE, SHA384_HASH_SIZE};
use crate::protocol::certs::{CertificateInfo, KeyUsageMask};
use crate::protocol::{BaseHashAlgoType, SpdmCertChainHeader};

pub const MAX_CERT_SLOTS_SUPPORTED: u8 = 2;
pub const SPDM_CERT_CHAIN_METADATA_LEN: u16 =
    size_of::<SpdmCertChainHeader>() as u16 + SHA384_HASH_SIZE as u16;

#[derive(Debug, PartialEq)]
pub enum CertStoreError {
    InitFailed,
    InvalidSlotId(u8),
    UnsupportedHashAlgo,
    BufferTooSmall,
    InvalidOffset,
    CertReadError,
    PlatformError,
}

pub type CertStoreResult<T> = Result<T, CertStoreError>;

pub trait SpdmCertStore {
    /// Get supported certificate slot count
    /// The supported slots are consecutive from 0 to slot_count - 1.
    ///
    /// # Returns
    /// * `u8` - The number of supported certificate slots.
    fn slot_count(&self) -> u8;

    /// Check if the slot is provisioned.
    ///
    /// # Arguments
    /// * `slot_id` - The slot ID of the certificate chain.
    ///
    /// # Returns
    /// * `bool` - True if the slot is provisioned, false otherwise.
    fn is_provisioned(&self, slot_id: u8) -> bool;

    /// Get the length of the certificate chain in bytes.
    /// The certificate chain is in ASN.1 DER-encoded X.509 v3 format.
    /// The type of the certificate chain is indicated by the asym_algo parameter.
    ///
    /// # Arguments
    /// * `slot_id` - The slot ID of the certificate chain.
    /// * `asym_algo` - The asymmetric algorithm to indicate the type of certificate chain.
    ///
    /// # Returns
    /// * `usize` - The length of the certificate chain in bytes or error.
    fn cert_chain_len(&mut self, asym_algo: AsymAlgo, slot_id: u8) -> CertStoreResult<usize>;

    /// Get the certificate chain in portion. The certificate chain is in ASN.1 DER-encoded X.509 v3 format.
    /// The type of the certificate chain is indicated by the asym_algo parameter.
    ///
    /// # Arguments
    /// * `slot_id` - The slot ID of the certificate chain.
    /// * `asym_algo` - The asymmetric algorithm to indicate the type of Certificate chain.
    /// * `offset` - The offset in bytes to start reading from.
    /// * `cert_portion` - The buffer to read the certificate chain into.
    ///
    /// # Returns
    /// * `usize` - The number of bytes read or error.
    /// If the cert portion size is smaller than the buffer size, the remaining bytes in the buffer will be filled with 0,
    /// indicating the end of the cert chain.
    fn get_cert_chain<'a>(
        &mut self,
        slot_id: u8,
        asym_algo: AsymAlgo,
        offset: usize,
        cert_portion: &'a mut [u8],
    ) -> CertStoreResult<usize>;

    /// Get the hash of the root certificate in the certificate chain.
    /// The hash algorithm is always SHA-384. The type of the certificate chain is indicated by the asym_algo parameter.
    ///
    /// # Arguments
    /// * `slot_id` - The slot ID of the certificate chain.
    /// * `asym_algo` - The asymmetric algorithm to indicate the type of Certificate chain.
    /// * `cert_hash` - The buffer to store the hash of the root certificate.
    ///
    /// # Returns
    /// * `()` - Ok if successful, error otherwise.
    fn root_cert_hash<'a>(
        &mut self,
        slot_id: u8,
        asym_algo: AsymAlgo,
        cert_hash: &'a mut [u8; SHA384_HASH_SIZE],
    ) -> CertStoreResult<()>;

    /// Sign hash with leaf certificate key
    ///
    /// # Arguments
    /// * `slot_id` - The slot ID of the certificate chain.
    /// * `hash` - The hash to sign.
    /// * `signature` - The output buffer to store the ECC384 signature.
    ///
    /// # Returns
    /// * `()` - Ok if successful, error otherwise.
    fn sign_hash<'a>(
        &self,
        slot_id: u8,
        hash: &'a [u8; SHA384_HASH_SIZE],
        signature: &'a mut [u8; ECC_P384_SIGNATURE_SIZE],
    ) -> CertStoreResult<()>;

    /// Get the KeyPairID associated with the certificate chain if SPDM responder supports
    /// multiple assymmetric keys in connection.
    ///
    /// # Arguments
    /// * `slot_id` - The slot ID of the certificate chain.
    ///
    /// # Returns
    /// * u8 - The KeyPairID associated with the certificate chain or None if not supported or not found.
    fn key_pair_id(&self, slot_id: u8) -> Option<u8>;

    /// Retrieve the `CertificateInfo` associated with the certificate chain for the given slot.
    /// The `CertificateInfo` structure specifies the certificate model (such as DeviceID, Alias, or General),
    /// and includes reserved bits for future extensions.
    ///
    /// # Arguments
    /// * `slot_id` - The slot ID of the certificate chain.
    ///
    /// # Returns
    /// * `CertificateInfo` - The CertificateInfo associated with the certificate chain or None if not supported or not found.
    fn cert_info(&self, slot_id: u8) -> Option<CertificateInfo>;

    /// Get the KeyUsageMask associated with the certificate chain if SPDM responder supports
    /// multiple asymmetric keys in connection.
    ///
    /// # Arguments
    /// * `slot_id` - The slot ID of the certificate chain.
    ///
    /// # Returns
    /// * `KeyUsageMask` - The KeyUsageMask associated with the certificate chain or None if not supported or not found.
    fn key_usage_mask(&self, slot_id: u8) -> Option<KeyUsageMask>;
}

pub(crate) fn validate_cert_store(cert_store: &dyn SpdmCertStore) -> SpdmResult<()> {
    let slot_count = cert_store.slot_count();
    if slot_count > MAX_CERT_SLOTS_SUPPORTED {
        Err(SpdmError::InvalidParam)?;
    }
    Ok(())
}

pub(crate) fn cert_slot_mask(cert_store: &dyn SpdmCertStore) -> (u8, u8) {
    let slot_count = cert_store.slot_count().min(MAX_CERT_SLOTS_SUPPORTED);
    let supported_slot_mask = (1 << slot_count) - 1;

    let provisioned_slot_mask = (0..slot_count)
        .filter(|&i| cert_store.is_provisioned(i))
        .fold(0, |mask, i| mask | (1 << i));

    (supported_slot_mask, provisioned_slot_mask)
}

pub trait PeerCertStore {
    /// Get supported certificate slot count.
    /// The supported slots are consecutive from 0 to slot_count - 1.
    /// If certificate slot X exists in the responding SPDM endpoint, then all
    /// slots with ID < X must also exist.
    ///
    /// For example, if slot 2 is supported, then slots 0 and 1 must also be supported.
    ///
    /// # Returns
    /// * `u8` - The number of supported certificate slots.
    fn slot_count(&self) -> u8;

    /// Set the number of supported certificate slots.
    /// This function is typically called during SPDM connection setup.
    ///
    /// # Arguments
    /// * `slot_count` - The number of supported certificate slots.
    ///
    /// # Returns
    /// * `CertStoreResult<()>` - Ok if the operation was successful, Err otherwise.
    fn set_supported_slots(&mut self, supported_slot_mask: u8) -> CertStoreResult<()>;

    /// Get the bitmask of supported certificate slots.
    ///
    /// # Returns
    /// * `Ok(u8)` - Bitmask where each set bit indicates a supported slot.
    ///
    /// # Errors
    /// * `CertStoreError::PlatformError` - If there was a platform-specific error.
    fn get_supported_slots(&self) -> CertStoreResult<u8>;

    /// Set the bitmask of provisioned certificate slots.
    ///
    /// # Arguments
    /// * `provisioned_slot_mask` - Bitmask where each set bit indicates a provisioned slot.
    ///
    /// # Returns
    /// * `Ok(())` - If the provisioned slot mask was stored successfully.
    ///
    /// # Errors
    /// * `CertStoreError::PlatformError` - If there was a platform-specific error.
    fn set_provisioned_slots(&mut self, provisioned_slot_mask: u8) -> CertStoreResult<()>;

    /// Get the bitmask of provisioned certificate slots.
    ///
    /// # Returns
    /// * `Ok(u8)` - Bitmask where each set bit indicates a provisioned slot.
    ///
    /// # Errors
    /// * `CertStoreError::PlatformError` - If there was a platform-specific error.
    fn get_provisioned_slots(&self) -> CertStoreResult<u8>;

    /// Get the stored certificate chain for the given slot,
    /// consisting of one or more ASN.1 DER-encoded X.509 v3 certificates.
    ///
    /// # Arguments
    /// * `slot_id` - The slot ID of the certificate chain.
    /// * `hash_algo` - The hash algorithm that was negotiated with the peer.
    ///
    /// # Returns
    /// * `Ok(&[u8])` - The certificate chain bytes, not including the length and root hash header.
    ///
    /// # Errors
    /// * `CertStoreError::InvalidSlotId` - If the slot ID is out of range.
    /// * `CertStoreError::PlatformError` - If there was a platform-specific error.
    fn get_cert_chain(&self, slot_id: u8, hash_algo: BaseHashAlgoType) -> CertStoreResult<&[u8]>;

    /// Store a certificate chain in the given slot.
    ///
    /// # Arguments
    /// * `slot_id` - The slot ID to store the certificate chain in.
    /// * `cert_chain` - The certificate chain bytes to store.
    ///
    /// # Returns
    /// * `Ok(())` - If the certificate chain was stored successfully.
    ///
    /// # Errors
    /// * `CertStoreError::InvalidSlotId` - If the slot ID is out of range.
    /// * `CertStoreError::BufferTooSmall` - If the internal buffer is too small for the certificate chain.
    /// * `CertStoreError::PlatformError` - If there was a platform-specific error.
    fn set_cert_chain(&mut self, slot_id: u8, cert_chain: &[u8]) -> CertStoreResult<()>;

    /// Get the digest of the certificate chain for the given slot.
    ///
    /// # Arguments
    /// * `slot_id` - The slot ID of the certificate chain.
    ///
    /// # Returns
    /// * `Ok(&[u8])` - The digest bytes.
    ///
    /// # Errors
    /// * `CertStoreError::InvalidSlotId` - If the slot ID is out of range.
    /// * `CertStoreError::PlatformError` - If there was a platform-specific error.
    fn get_digest(&self, slot_id: u8) -> CertStoreResult<&[u8]>;

    /// Store the digest of the certificate chain for the given slot.
    ///
    /// # Arguments
    /// * `slot_id` - The slot ID of the certificate chain.
    /// * `digest` - The digest bytes to store.
    ///
    /// # Returns
    /// * `Ok(())` - If the digest was stored successfully.
    ///
    /// # Errors
    /// * `CertStoreError::InvalidSlotId` - If the slot ID is out of range.
    /// * `CertStoreError::BufferTooSmall` - If the internal buffer is too small for the digest.
    /// * `CertStoreError::PlatformError` - If there was a platform-specific error.
    fn set_digest(&mut self, slot_id: u8, digest: &[u8]) -> CertStoreResult<()>;

    /// Get the KeyPairID associated with the certificate chain for the given slot.
    ///
    /// # Arguments
    /// * `slot_id` - The slot ID of the certificate chain.
    ///
    /// # Returns
    /// * `Ok(u8)` - The KeyPairID.
    ///
    /// # Errors
    /// * `CertStoreError::InvalidSlotId` - If the slot ID is out of range.
    /// * `CertStoreError::PlatformError` - If there was a platform-specific error.
    fn get_keypair(&self, slot_id: u8) -> CertStoreResult<u8>;

    /// Set the KeyPairID associated with the certificate chain for the given slot.
    ///
    /// # Arguments
    /// * `slot_id` - The slot ID of the certificate chain.
    /// * `keypair` - The KeyPairID to associate with the slot.
    ///
    /// # Returns
    /// * `Ok(())` - If the KeyPairID was stored successfully.
    ///
    /// # Errors
    /// * `CertStoreError::InvalidSlotId` - If the slot ID is out of range.
    /// * `CertStoreError::PlatformError` - If there was a platform-specific error.
    fn set_keypair(&mut self, slot_id: u8, keypair: u8) -> CertStoreResult<()>;

    /// Get the `CertificateInfo` for the given slot.
    /// The `CertificateInfo` specifies the certificate model (such as DeviceID, Alias, or General).
    ///
    /// # Arguments
    /// * `slot_id` - The slot ID of the certificate chain.
    ///
    /// # Returns
    /// * `Ok(CertificateInfo)` - The certificate info for the slot.
    ///
    /// # Errors
    /// * `CertStoreError::InvalidSlotId` - If the slot ID is out of range.
    /// * `CertStoreError::PlatformError` - If there was a platform-specific error.
    fn get_cert_info(&self, slot_id: u8) -> CertStoreResult<CertificateInfo>;

    /// Set the `CertificateInfo` for the given slot.
    ///
    /// # Arguments
    /// * `slot_id` - The slot ID of the certificate chain.
    /// * `cert_info` - The `CertificateInfo` to store.
    ///
    /// # Returns
    /// * `Ok(())` - If the `CertificateInfo` was stored successfully.
    ///
    /// # Errors
    /// * `CertStoreError::InvalidSlotId` - If the slot ID is out of range.
    /// * `CertStoreError::PlatformError` - If there was a platform-specific error.
    fn set_cert_info(&mut self, slot_id: u8, cert_info: CertificateInfo) -> CertStoreResult<()>;

    /// Get the `KeyUsageMask` associated with the certificate chain for the given slot.
    /// The `KeyUsageMask` indicates the permitted key usages for the certificate's public key.
    ///
    /// # Arguments
    /// * `slot_id` - The slot ID of the certificate chain.
    ///
    /// # Returns
    /// * `Ok(KeyUsageMask)` - The key usage mask for the slot.
    ///
    /// # Errors
    /// * `CertStoreError::InvalidSlotId` - If the slot ID is out of range.
    /// * `CertStoreError::PlatformError` - If there was a platform-specific error.
    fn get_key_usage_mask(&self, slot_id: u8) -> CertStoreResult<KeyUsageMask>;

    /// Set the `KeyUsageMask` associated with the certificate chain for the given slot.
    ///
    /// # Arguments
    /// * `slot_id` - The slot ID of the certificate chain.
    /// * `key_usage_mask` - The `KeyUsageMask` to store.
    ///
    /// # Returns
    /// * `Ok(())` - If the `KeyUsageMask` was stored successfully.
    ///
    /// # Errors
    /// * `CertStoreError::InvalidSlotId` - If the slot ID is out of range.
    /// * `CertStoreError::PlatformError` - If there was a platform-specific error.
    fn set_key_usage_mask(
        &mut self,
        slot_id: u8,
        key_usage_mask: KeyUsageMask,
    ) -> CertStoreResult<()>;

    /// Add a portion of a certificate chain to the given slot
    ///
    /// # Returns
    /// - `Ok(ReassemblyStatus)` when the portion was added successfully
    /// - `Err(ReassemblyError)` when the portion could not be added
    fn assemble(&mut self, slot_id: u8, portion: &[u8])
        -> Result<ReassemblyStatus, CertStoreError>;

    /// Reset a slot
    ///
    /// Removes all certificate data from the given slot.
    fn reset(&mut self, slot_id: u8);

    /// Get the root hash of a peer certificate
    ///
    /// # Arguments
    /// * `slot_id` - The Slot ID of the certificate chain
    /// * `hash_algo` - The hash algorithm that was negotiated with the peer.
    ///
    /// # Returns
    /// * The digest of the Root Certificate if available
    fn get_root_hash(&self, slot_id: u8, hash_algo: BaseHashAlgoType) -> CertStoreResult<&[u8]>;

    /// Get the raw cert chain, including the length header and root hash
    fn get_raw_chain(&self, slot_id: u8) -> CertStoreResult<&[u8]>;
}

pub enum ReassemblyStatus {
    /// Slot is empty
    NotStarted,
    /// Reassembly still in progress
    InProgress,
    /// Reassembly finished
    Done,
}
