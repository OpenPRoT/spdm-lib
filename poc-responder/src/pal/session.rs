// Licensed under the Apache-2.0 license

//! Session-crypto stub.
//!
//! This PoC targets the non-session handshake only (GET_VERSION …
//! GET_MEASUREMENTS). `SpdmPalSessionCrypto` is required by the `SpdmPal`
//! super-trait, so it is implemented here with error-returning stubs: a peer
//! that attempts KEY_EXCHANGE gets a graceful SPDM ERROR via the stack's
//! dispatch path rather than a panic. Implementing real ECDH/HKDF/AEAD is future
//! work.

use spdm_errors::{codes::NOT_IMPLEMENTED, PalResult};
use spdm_traits::{SpdmPalIo, SpdmPalSessionCrypto};

use super::HostPal;

/// Opaque session-key handle. Never produced by this stub.
#[derive(Clone)]
pub struct SessionKey;

impl SpdmPalSessionCrypto for HostPal {
    type Key = SessionKey;

    fn ecdh_generate(
        &self,
        _io: &impl SpdmPalIo,
        _context: &mut [u8],
        _exchange_data: &mut [u8],
    ) -> PalResult<()> {
        Err(NOT_IMPLEMENTED)
    }

    fn ecdh_finish(
        &self,
        _io: &impl SpdmPalIo,
        _context: &[u8],
        _peer_exchange_data: &[u8],
    ) -> PalResult<Self::Key> {
        Err(NOT_IMPLEMENTED)
    }

    fn hkdf_extract_bytes(
        &self,
        _io: &impl SpdmPalIo,
        _salt: &[u8],
        _ikm: &Self::Key,
    ) -> PalResult<Self::Key> {
        Err(NOT_IMPLEMENTED)
    }

    fn hkdf_extract_key(
        &self,
        _io: &impl SpdmPalIo,
        _salt: &Self::Key,
        _ikm: &Self::Key,
    ) -> PalResult<Self::Key> {
        Err(NOT_IMPLEMENTED)
    }

    fn hkdf_expand(
        &self,
        _io: &impl SpdmPalIo,
        _prk: &Self::Key,
        _key_size: u32,
        _info: &[u8],
    ) -> PalResult<Self::Key> {
        Err(NOT_IMPLEMENTED)
    }

    fn hmac(
        &self,
        _io: &impl SpdmPalIo,
        _key: &Self::Key,
        _data: &[u8],
        _out: &mut [u8],
    ) -> PalResult<usize> {
        Err(NOT_IMPLEMENTED)
    }

    fn import_key(&self, _io: &impl SpdmPalIo, _data: &[u8]) -> PalResult<Self::Key> {
        Err(NOT_IMPLEMENTED)
    }

    fn aead_encrypt(
        &self,
        _io: &impl SpdmPalIo,
        _key: &Self::Key,
        _spdm_version: u8,
        _seq: u64,
        _aad: &[u8],
        _plaintext: &[u8],
        _ciphertext: &mut [u8],
    ) -> PalResult<(usize, [u8; 16])> {
        Err(NOT_IMPLEMENTED)
    }

    fn aead_decrypt(
        &self,
        _io: &impl SpdmPalIo,
        _key: &Self::Key,
        _spdm_version: u8,
        _seq: u64,
        _aad: &[u8],
        _ciphertext: &[u8],
        _tag: &[u8; 16],
        _plaintext: &mut [u8],
    ) -> PalResult<usize> {
        Err(NOT_IMPLEMENTED)
    }
}
