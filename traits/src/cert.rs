// Licensed under the Apache-2.0 license

//! SPDM cert-store abstraction (DSP0274 §10.5 / §10.6).
//!
//! All cert-chain methods take an [`SpdmPalAsymAlgo`] parameter
//! so each slot can hold chains for multiple algorithms (e.g.
//! ECC-384 and MLDSA-87). Only ECC-384 is implemented today;
//! MLDSA-87 will be added later using the same interfaces.

use crate::SpdmPalHashAlgo;
use spdm_errors::PalResult;

/// Maximum number of cert-chain slots the responder advertises.
/// DSP0274 §10.5 caps this at 8 (`SlotMask` is one byte).
pub const MAX_SLOTS: u8 = 8;

/// Asymmetric algorithm selector.
///
/// Passed to cert-store and endorsement methods so the
/// implementation can select the right cert chain and signing
/// key for the slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpdmPalAsymAlgo {
    /// ECDSA P-384 / SHA-384 (96-byte signature: r || s).
    EccP384,
    /// ML-DSA-87 (post-quantum). Reserved for future use.
    MlDsa87,
}

/// Endorsement certificate chain provider for a single slot.
///
/// Integrators implement this for each endorsement type:
/// - `ReadOnlyEndorsement` — static root CA certs (slot 0)
/// - `MutableEndorsement` — flash-backed certs (slots 1-2, SET_CERTIFICATE)
///
/// The PAL uses this to compose the full SPDM cert chain:
/// `endorsement (this) + DPE device chain + leaf (CertifyKey)`
pub trait EndorsementCertChain {
    /// Hash of the root certificate under the given algorithm.
    fn root_cert_hash(&self, algo: SpdmPalAsymAlgo, out: &mut [u8]) -> PalResult<()>;

    /// Total byte length of the endorsement cert chain for the
    /// given algorithm.
    fn size(&mut self, algo: SpdmPalAsymAlgo) -> PalResult<usize>;

    /// Read endorsement chain bytes at `offset` into `buf`.
    /// Returns bytes written.
    fn read(&mut self, algo: SpdmPalAsymAlgo, offset: usize, buf: &mut [u8]) -> PalResult<usize>;

    /// Write endorsement cert chain data for the given algorithm.
    /// `ReadOnlyEndorsement` rejects this; `MutableEndorsement`
    /// persists to flash.
    fn write(&mut self, algo: SpdmPalAsymAlgo, data: &[u8]) -> PalResult<()>;

    /// Erase the endorsement cert chain for the given algorithm.
    fn erase(&mut self, algo: SpdmPalAsymAlgo) -> PalResult<()>;
}

/// Slot-indexed cert-store backend.
pub trait SpdmPalCertStore: crate::SpdmPalIoTransport {
    /// Bitmask of supported slots, bits 0..=7.
    fn supported_slots(&self) -> u8;

    /// Bitmask of provisioned slots, bits 0..=7. Drives DIGESTS's
    /// `SupportedSlotMask` / `ProvisionedSlotMask` (DSP0274 §10.5
    /// Table 25).
    fn provisioned_slots(&self) -> u8;

    /// Raw DER capacity/size for a slot-size query.
    fn cert_chain_slot_size(
        &self,
        io: &Self::Io<'_>,
        slot: u8,
        algo: SpdmPalAsymAlgo,
    ) -> PalResult<usize>;

    /// Check whether a specific SET_CERTIFICATE request is authorized.
    #[cfg(feature = "set-certificate")]
    fn set_certificate_authorized(
        &self,
        io: &Self::Io<'_>,
        slot: u8,
        key_pair_id: u8,
        cert_model: u8,
        erase: bool,
    ) -> bool;

    /// Validate an incoming SET_CERTIFICATE chain before it is committed.
    ///
    /// The PAL implementation **must** verify that `SHA-384(first DER
    /// certificate in `cert_chain`) == *root_hash`. The stack no longer
    /// performs this check, since the PAL already has access to hashing
    /// machinery and avoids a duplicate async hash pass at the SPDM
    /// responder layer.
    #[cfg(feature = "set-certificate")]
    fn validate_set_certificate_chain(
        &self,
        io: &Self::Io<'_>,
        slot: u8,
        key_pair_id: u8,
        cert_model: u8,
        root_hash: &[u8; 48],
        cert_chain: &[u8],
    ) -> PalResult<()>;

    /// Length in bytes of slot's raw DER cert chain for the given
    /// algorithm (excludes the 52-byte SPDM cert-chain header).
    fn cert_chain_len(
        &self,
        io: &Self::Io<'_>,
        slot: u8,
        algo: SpdmPalAsymAlgo,
    ) -> PalResult<usize>;

    /// Write the digest of slot's **root certificate** into `out`.
    fn root_cert_hash(
        &self,
        io: &Self::Io<'_>,
        slot: u8,
        algo: SpdmPalAsymAlgo,
        hash_algo: SpdmPalHashAlgo,
        out: &mut [u8],
    ) -> PalResult<()>;

    /// Read at most `dst.len()` bytes from slot's raw cert chain
    /// for the given algorithm at `offset` into `dst`.
    fn read_cert_chain(
        &self,
        io: &Self::Io<'_>,
        slot: u8,
        algo: SpdmPalAsymAlgo,
        offset: usize,
        dst: &mut [u8],
    ) -> PalResult<usize>;

    /// Sign `digest` using the key in `slot` for the given algorithm.
    fn sign_hash(
        &self,
        io: &Self::Io<'_>,
        slot: u8,
        algo: SpdmPalAsymAlgo,
        digest: &[u8],
        signature: &mut [u8],
    ) -> PalResult<usize>;

    /// Write a cert chain into `slot` for the given algorithm.
    /// Used by SET_CERTIFICATE.
    #[cfg(feature = "set-certificate")]
    #[allow(clippy::too_many_arguments)]
    fn write_cert_chain(
        &self,
        io: &Self::Io<'_>,
        slot: u8,
        algo: SpdmPalAsymAlgo,
        key_pair_id: u8,
        cert_info: u8,
        root_hash: &[u8; 48],
        data: &[u8],
    ) -> PalResult<()>;

    /// Begins a non-atomic streaming SET_CERTIFICATE write transaction.
    ///
    /// Implementations may erase/overwrite target storage at begin time. A
    /// request becomes valid only after [`finish_write_cert_chain_stream`](Self::finish_write_cert_chain_stream)
    /// commits metadata; interrupted or invalid requests need not preserve the old chain.
    #[allow(clippy::too_many_arguments)]
    fn begin_write_cert_chain_stream(
        &self,
        _io: &Self::Io<'_>,
        _slot: u8,
        _algo: SpdmPalAsymAlgo,
        _key_pair_id: u8,
        _cert_info: u8,
        _root_hash: &[u8; 48],
        _data_len: usize,
    ) -> PalResult<()> {
        Err(spdm_errors::codes::NOT_IMPLEMENTED)
    }

    /// Writes one DER chunk at `offset` within the streaming cert-chain data.
    fn write_cert_chain_stream_chunk(
        &self,
        _io: &Self::Io<'_>,
        _slot: u8,
        _algo: SpdmPalAsymAlgo,
        _offset: usize,
        _data: &[u8],
    ) -> PalResult<()> {
        Err(spdm_errors::codes::NOT_IMPLEMENTED)
    }

    /// Commits a streaming SET_CERTIFICATE write transaction.
    #[allow(clippy::too_many_arguments)]
    fn finish_write_cert_chain_stream(
        &self,
        _io: &Self::Io<'_>,
        _slot: u8,
        _algo: SpdmPalAsymAlgo,
        _key_pair_id: u8,
        _cert_info: u8,
        _root_hash: &[u8; 48],
        _data_len: usize,
    ) -> PalResult<()> {
        Err(spdm_errors::codes::NOT_IMPLEMENTED)
    }

    /// Aborts a streaming SET_CERTIFICATE write transaction.
    fn abort_write_cert_chain_stream(
        &self,
        _io: &Self::Io<'_>,
        _slot: u8,
        _algo: SpdmPalAsymAlgo,
    ) -> PalResult<()> {
        Ok(())
    }

    /// Erase the cert chain in `slot` for the given algorithm.
    #[cfg(feature = "set-certificate")]
    fn erase_cert_chain(&self, io: &Self::Io<'_>, slot: u8, algo: SpdmPalAsymAlgo)
        -> PalResult<()>;

    /// KeyPairID associated with the slot.
    /// Returns `None` for unprovisioned slots.
    fn key_pair_id(&self, slot: u8) -> Option<u8>;

    /// CertificateInfo for the slot.
    /// Returns `None` for unprovisioned slots.
    fn cert_info(&self, slot: u8) -> Option<u8>;

    /// KeyUsageMask for the slot.
    /// Returns `None` for unprovisioned slots.
    fn key_usage_mask(&self, slot: u8) -> Option<u16>;

    /// Optional cache hook: return a previously stored full
    /// SPDM-cert-chain digest for `(slot, asym_algo, hash_algo)`, or `None` to
    /// force recomputation. Default impl never caches.
    #[inline]
    fn cached_chain_digest(
        &self,
        _slot: u8,
        _asym_algo: SpdmPalAsymAlgo,
        _hash_algo: SpdmPalHashAlgo,
    ) -> Option<[u8; 48]> {
        None
    }

    /// Optional cache hook: store the freshly computed SPDM
    /// cert-chain digest for future
    /// [`cached_chain_digest`](Self::cached_chain_digest) lookups.
    /// Default impl is a no-op.
    #[inline]
    fn cache_chain_digest(
        &self,
        _slot: u8,
        _asym_algo: SpdmPalAsymAlgo,
        _hash_algo: SpdmPalHashAlgo,
        _digest: &[u8],
    ) {
    }

    /// Fill `out` with random bytes from the platform RNG.
    fn generate_nonce(&self, io: &Self::Io<'_>, out: &mut [u8]) -> PalResult<()>;
}
