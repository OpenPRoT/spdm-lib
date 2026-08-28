// Licensed under the Apache-2.0 license

//! Static DER cert chain + P-384 ECDSA signing, ported from the legacy
//! `cert_store.rs` example. Serves raw DER slices to the stack (which prepends
//! the 52-byte SPDM cert-chain header itself) and signs CHALLENGE / MEASUREMENTS
//! transcripts with a P-384 prehash signer.

use core::cell::RefCell;

use p384::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use p384::SecretKey;
use sha2::{Digest, Sha384};

use spdm_errors::{codes::INVARIANT, PalResult};
use spdm_traits::{SpdmPalAsymAlgo, SpdmPalCertStore, SpdmPalHashAlgo};

use super::HostPal;

// DER assets reused from the legacy example (no copy).
pub const ROOT_CA_CERT: &[u8] = include_bytes!("../../../legacy/examples/certs/ca.cert.der");
pub const INTER_CERT: &[u8] = include_bytes!("../../../legacy/examples/certs/inter.cert.der");
pub const END_CERT: &[u8] = include_bytes!("../../../legacy/examples/certs/end_responder.cert.der");
pub const END_KEY_DER: &[u8] =
    include_bytes!("../../../legacy/examples/certs/end_responder.key.der");

const ECC_P384_SIG_SIZE: usize = 96;

/// Metadata recorded alongside a provisioned chain, reported back through
/// `key_pair_id` / `cert_info`.
#[derive(Copy, Clone)]
struct SlotMeta {
    key_pair_id: u8,
    /// DSP0274 CertificateInfo: cert_model in bits 0..3.
    cert_model: u8,
}

/// Cert chain (root ‖ inter ‖ end) plus the end-entity signing key.
///
/// The chain is behind a `RefCell` because SET_CERTIFICATE replaces it while
/// the trait methods only take `&self`. The signing key is *not* replaced:
/// SET_CERTIFICATE provisions a chain for a key pair the device already owns.
pub struct CertState {
    chain: RefCell<Vec<u8>>,
    /// `None` once the slot has been erased and before it is re-provisioned.
    meta: RefCell<Option<SlotMeta>>,
    /// In-flight streaming SET_CERTIFICATE write, staged until it commits.
    pending: RefCell<Option<PendingWrite>>,
    signing_key: SigningKey,
}

/// Staging buffer for a chunked SET_CERTIFICATE. Nothing reaches `chain` until
/// `finish_write_cert_chain_stream` validates and commits it.
struct PendingWrite {
    slot: u8,
    key_pair_id: u8,
    cert_model: u8,
    root_hash: [u8; 48],
    data: Vec<u8>,
}

impl CertState {
    pub fn new() -> Self {
        let mut chain = Vec::new();
        chain.extend_from_slice(ROOT_CA_CERT);
        chain.extend_from_slice(INTER_CERT);
        chain.extend_from_slice(END_CERT);

        // SEC1 ECPrivateKey: skip 8-byte prefix to the raw 48-byte P-384 scalar.
        let raw: &[u8; 48] = END_KEY_DER[8..56]
            .try_into()
            .expect("end-entity key DER too short");
        let secret = SecretKey::from_bytes(raw.into()).expect("parse P-384 private key");
        let signing_key = SigningKey::from(secret);

        Self {
            chain: RefCell::new(chain),
            meta: RefCell::new(Some(SlotMeta {
                key_pair_id: 1,
                cert_model: 1, // DeviceCert
            })),
            pending: RefCell::new(None),
            signing_key,
        }
    }

    fn chain_len(&self) -> usize {
        self.chain.borrow().len()
    }

    fn is_provisioned(&self) -> bool {
        self.meta.borrow().is_some() && !self.chain.borrow().is_empty()
    }
}

/// SHA-384 over `data`.
fn sha384(data: &[u8]) -> [u8; 48] {
    let mut h = Sha384::new();
    h.update(data);
    let mut out = [0u8; 48];
    out.copy_from_slice(&h.finalize());
    out
}

/// Total length of the DER SEQUENCE starting at `input[0]`, or `None` if the
/// input is truncated or is not a SEQUENCE.
fn der_sequence_len(input: &[u8]) -> Option<usize> {
    if input.len() < 2 || input[0] != 0x30 {
        return None;
    }
    let len_byte = input[1];
    let (header_len, content_len) = if len_byte & 0x80 == 0 {
        (2usize, len_byte as usize)
    } else {
        let len_len = (len_byte & 0x7f) as usize;
        if len_len == 0 || len_len > 4 || input.len() < 2 + len_len {
            return None;
        }
        let mut content_len = 0usize;
        for &b in &input[2..2 + len_len] {
            content_len = content_len.checked_shl(8)?.checked_add(b as usize)?;
        }
        (2 + len_len, content_len)
    };
    let total = header_len.checked_add(content_len)?;
    (total <= input.len()).then_some(total)
}

/// Walks `der` as a back-to-back sequence of certificates, returning the length
/// of the first one. Errors if the chain is empty or does not divide cleanly.
fn first_cert_len(der: &[u8]) -> PalResult<usize> {
    let first = der_sequence_len(der).ok_or(INVARIANT)?;
    let mut offset = 0usize;
    while offset < der.len() {
        let n = der_sequence_len(&der[offset..]).ok_or(INVARIANT)?;
        offset = offset.checked_add(n).ok_or(INVARIANT)?;
    }
    if offset != der.len() {
        return Err(INVARIANT);
    }
    Ok(first)
}

impl SpdmPalCertStore for HostPal {
    fn supported_slots(&self) -> u8 {
        0x01 // slot 0 only
    }

    fn provisioned_slots(&self) -> u8 {
        if self.certs.is_provisioned() {
            0x01
        } else {
            0x00
        }
    }

    fn cert_chain_slot_size(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        _algo: SpdmPalAsymAlgo,
    ) -> PalResult<usize> {
        self.slot0(slot).map(|c| c.chain_len())
    }

    fn cert_chain_len(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        _algo: SpdmPalAsymAlgo,
    ) -> PalResult<usize> {
        self.slot0(slot).map(|c| c.chain_len())
    }

    fn root_cert_hash(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        _algo: SpdmPalAsymAlgo,
        hash_algo: SpdmPalHashAlgo,
        out: &mut [u8],
    ) -> PalResult<()> {
        let cert = self.slot0(slot)?;
        match hash_algo {
            SpdmPalHashAlgo::Sha384 => {
                if out.len() < 48 {
                    return Err(INVARIANT);
                }
                // Hash the first certificate of whatever chain is currently
                // provisioned, which may have been replaced by SET_CERTIFICATE.
                let chain = cert.chain.borrow();
                let first_len = first_cert_len(&chain)?;
                out[..48].copy_from_slice(&sha384(&chain[..first_len]));
                Ok(())
            }
        }
    }

    fn read_cert_chain(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        _algo: SpdmPalAsymAlgo,
        offset: usize,
        dst: &mut [u8],
    ) -> PalResult<usize> {
        let cert = self.slot0(slot)?;
        let chain = cert.chain.borrow();
        if offset >= chain.len() {
            return Ok(0);
        }
        let n = (chain.len() - offset).min(dst.len());
        dst[..n].copy_from_slice(&chain[offset..offset + n]);
        Ok(n)
    }

    fn sign_hash(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        algo: SpdmPalAsymAlgo,
        digest: &[u8],
        signature: &mut [u8],
    ) -> PalResult<usize> {
        if algo != SpdmPalAsymAlgo::EccP384 {
            return Err(INVARIANT);
        }
        let cert = self.slot0(slot)?;
        if signature.len() < ECC_P384_SIG_SIZE {
            return Err(INVARIANT);
        }
        let sig: Signature = cert
            .signing_key
            .sign_prehash(digest)
            .map_err(|_| INVARIANT)?;
        let bytes = sig.to_bytes(); // fixed 96-byte r‖s
        signature[..ECC_P384_SIG_SIZE].copy_from_slice(&bytes);
        Ok(ECC_P384_SIG_SIZE)
    }

    // ---- SET_CERTIFICATE (DSP0274 §10.7) --------------------------------

    #[cfg(feature = "set-certificate")]
    fn set_certificate_authorized(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        key_pair_id: u8,
        cert_model: u8,
        erase: bool,
    ) -> bool {
        // This PoC has no owner-authorization policy: slot 0 is the only
        // writable slot, and it accepts the key pair it already holds. A real
        // device would gate this on ownership / debug state.
        if slot != 0 {
            return false;
        }
        if erase {
            return true;
        }
        // DeviceCert(1), AliasCert(2) and GenericCert(3) are the models the
        // stack can negotiate; reject anything else outright.
        if !matches!(cert_model, 1..=3) {
            return false;
        }
        key_pair_id == 1
    }

    #[cfg(feature = "set-certificate")]
    fn validate_set_certificate_chain(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        _key_pair_id: u8,
        _cert_model: u8,
        root_hash: &[u8; 48],
        cert_chain: &[u8],
    ) -> PalResult<()> {
        let _ = self.slot0(slot)?;
        // Contract: the PAL, not the stack, checks the root hash.
        let first_len = first_cert_len(cert_chain)?;
        if sha384(&cert_chain[..first_len]) != *root_hash {
            return Err(INVARIANT);
        }
        Ok(())
    }

    #[cfg(feature = "set-certificate")]
    fn write_cert_chain(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        _algo: SpdmPalAsymAlgo,
        key_pair_id: u8,
        cert_info: u8,
        _root_hash: &[u8; 48],
        data: &[u8],
    ) -> PalResult<()> {
        let cert = self.slot0(slot)?;
        cert.chain.replace(data.to_vec());
        cert.meta.replace(Some(SlotMeta {
            key_pair_id,
            cert_model: cert_info,
        }));
        Ok(())
    }

    #[cfg(feature = "set-certificate")]
    fn erase_cert_chain(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        _algo: SpdmPalAsymAlgo,
    ) -> PalResult<()> {
        let cert = self.slot0(slot)?;
        cert.chain.borrow_mut().clear();
        cert.meta.replace(None);
        Ok(())
    }

    // ---- Streaming SET_CERTIFICATE --------------------------------------
    //
    // A chunked SET_CERTIFICATE is written fragment-by-fragment. Staging it
    // here rather than committing as it arrives keeps an interrupted or
    // invalid request from destroying the chain already in the slot.

    fn begin_write_cert_chain_stream(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        _algo: SpdmPalAsymAlgo,
        key_pair_id: u8,
        cert_info: u8,
        root_hash: &[u8; 48],
        data_len: usize,
    ) -> PalResult<()> {
        let cert = self.slot0(slot)?;
        cert.pending.replace(Some(PendingWrite {
            slot,
            key_pair_id,
            cert_model: cert_info,
            root_hash: *root_hash,
            data: vec![0u8; data_len],
        }));
        Ok(())
    }

    fn write_cert_chain_stream_chunk(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        _algo: SpdmPalAsymAlgo,
        offset: usize,
        data: &[u8],
    ) -> PalResult<()> {
        let cert = self.slot0(slot)?;
        let mut pending = cert.pending.borrow_mut();
        let write = pending.as_mut().ok_or(INVARIANT)?;
        if write.slot != slot {
            return Err(INVARIANT);
        }
        let end = offset.checked_add(data.len()).ok_or(INVARIANT)?;
        let dst = write.data.get_mut(offset..end).ok_or(INVARIANT)?;
        dst.copy_from_slice(data);
        Ok(())
    }

    fn finish_write_cert_chain_stream(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        _algo: SpdmPalAsymAlgo,
        key_pair_id: u8,
        cert_info: u8,
        root_hash: &[u8; 48],
        data_len: usize,
    ) -> PalResult<()> {
        let cert = self.slot0(slot)?;
        let write = cert.pending.borrow_mut().take().ok_or(INVARIANT)?;
        if write.slot != slot
            || write.key_pair_id != key_pair_id
            || write.cert_model != cert_info
            || write.root_hash != *root_hash
            || write.data.len() != data_len
        {
            return Err(INVARIANT);
        }
        // Same root-hash contract as the non-streaming path; only now is the
        // whole chain in hand to check it against.
        let first_len = first_cert_len(&write.data)?;
        if sha384(&write.data[..first_len]) != *root_hash {
            return Err(INVARIANT);
        }
        cert.chain.replace(write.data);
        cert.meta.replace(Some(SlotMeta {
            key_pair_id,
            cert_model: cert_info,
        }));
        Ok(())
    }

    fn abort_write_cert_chain_stream(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        _algo: SpdmPalAsymAlgo,
    ) -> PalResult<()> {
        // The slot keeps whatever it held before the interrupted write.
        self.slot0(slot)?.pending.replace(None);
        Ok(())
    }

    fn key_pair_id(&self, slot: u8) -> Option<u8> {
        if slot != 0 {
            return None;
        }
        self.certs.meta.borrow().map(|m| m.key_pair_id)
    }

    fn cert_info(&self, slot: u8) -> Option<u8> {
        if slot != 0 {
            return None;
        }
        // cert_model occupies bits 0..3 of CertificateInfo.
        self.certs.meta.borrow().map(|m| m.cert_model & 0x0F)
    }

    fn key_usage_mask(&self, slot: u8) -> Option<u16> {
        if slot != 0 {
            return None;
        }
        // challenge_usage | measurement_usage.
        self.certs.meta.borrow().map(|_| 0x0003)
    }

    fn generate_nonce(&self, _io: &Self::Io<'_>, out: &mut [u8]) -> PalResult<()> {
        use rand::RngCore;
        rand::thread_rng().fill_bytes(out);
        Ok(())
    }
}
