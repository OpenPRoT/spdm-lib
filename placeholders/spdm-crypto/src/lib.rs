// Licensed under the Apache-2.0 license

//! Platform-independent placeholder for `mcu-caliptra-api-lite`.
//!
//! Exposes exactly the crypto API surface the SPDM-Lib crates import
//! (SHA / HMAC / HKDF / ECDH / AES-GCM / DPE / RNG / key types) plus the
//! [`ApiAlloc`] scratch-allocator contract. Every crypto body is a stub
//! (`unimplemented!`) — the shapes/signatures match the real crate so the
//! library type-checks and links standalone; real Caliptra-mailbox backends
//! are wired later.

#![no_std]
#![forbid(unsafe_code)]

use core::ops::{Deref, DerefMut};
use spdm_errors::PalResult;

pub use spdm_errors::{PalErrorCode, PalResult as CryptoResult};

// ----- Allocator contract ----------------------------------------------------

/// Per-call scratch allocator. Mailbox request/response buffers come from
/// here so large payloads never sit on the stack across an ``.
pub trait ApiAlloc {
    type Buf<'a>: DerefMut<Target = [u8]>
    where
        Self: 'a;

    /// Allocate `len` bytes of scratch (uninitialised).
    fn alloc(&self, len: usize) -> PalResult<Self::Buf<'_>>;
}

// ----- Key types -------------------------------------------------------------

/// Size in bytes of a CMK handle.
pub const CMK_SIZE: usize = 128;

/// Encrypted Cryptographic-Manager key blob.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct Cmk(pub [u8; CMK_SIZE]);

impl Default for Cmk {
    fn default() -> Self {
        Self([0u8; CMK_SIZE])
    }
}

/// Key-usage tag controlling which commands accept a given CMK.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CmKeyUsage {
    Reserved = 0,
    Hmac = 1,
    Aes = 2,
    Ecdsa = 3,
    Mldsa = 4,
}

// ----- SHA -------------------------------------------------------------------

/// Opaque SHA context size (bytes).
pub const SHA_CONTEXT_SIZE: usize = 200;
/// Max SHA input chunk (bytes).
pub const SHA_CHUNK_SIZE: usize = 512;

/// Hash algorithm selector.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HashAlgo {
    Sha384,
}

impl HashAlgo {
    #[inline]
    pub const fn hash_size(self) -> usize {
        match self {
            HashAlgo::Sha384 => 48,
        }
    }
}

/// Streaming hash state backed by caller-supplied buffer `B`.
pub struct HashState<B> {
    inner: B,
}

impl<B: Deref<Target = [u8]> + DerefMut> HashState<B> {
    #[inline]
    pub fn from_buf(buf: B) -> Self {
        Self { inner: buf }
    }

    pub fn clone_into<B2: Deref<Target = [u8]> + DerefMut>(&self, mut buf: B2) -> HashState<B2> {
        buf[..SHA_CONTEXT_SIZE].copy_from_slice(&self.inner[..SHA_CONTEXT_SIZE]);
        HashState { inner: buf }
    }
}

pub fn sha_init<A: ApiAlloc, B: Deref<Target = [u8]> + DerefMut>(
    _alloc: &A,
    _buf: B,
    _algo: HashAlgo,
    _seed: &[u8],
) -> PalResult<HashState<B>> {
    unimplemented!("spdm-crypto placeholder: sha_init")
}

pub fn sha_update<A: ApiAlloc, B: Deref<Target = [u8]> + DerefMut>(
    _alloc: &A,
    _state: &mut HashState<B>,
    _data: &[u8],
) -> PalResult<()> {
    unimplemented!("spdm-crypto placeholder: sha_update")
}

pub fn sha_finish<A: ApiAlloc, B: Deref<Target = [u8]> + DerefMut>(
    _alloc: &A,
    _state: &mut HashState<B>,
    _out: &mut [u8],
) -> PalResult<()> {
    unimplemented!("spdm-crypto placeholder: sha_finish")
}

// ----- HMAC / HKDF -----------------------------------------------------------

/// Max HMAC output (bytes).
pub const CMB_HMAC_MAX_SIZE: usize = 64;

/// HKDF salt input — either an existing CMK or raw bytes.
pub enum HkdfSalt<'a> {
    Cmk(&'a Cmk),
    Data(&'a [u8]),
}

pub fn cm_hmac<A: ApiAlloc>(
    _alloc: &A,
    _cmk: &Cmk,
    _data: &[u8],
    _out: &mut [u8],
) -> PalResult<usize> {
    unimplemented!("spdm-crypto placeholder: cm_hmac")
}

pub fn hkdf_extract<A: ApiAlloc>(_alloc: &A, _salt: HkdfSalt<'_>, _ikm: &Cmk) -> PalResult<Cmk> {
    unimplemented!("spdm-crypto placeholder: hkdf_extract")
}

pub fn hkdf_expand<A: ApiAlloc>(
    _alloc: &A,
    _prk: &Cmk,
    _key_usage: CmKeyUsage,
    _key_size: u32,
    _info: &[u8],
) -> PalResult<Cmk> {
    unimplemented!("spdm-crypto placeholder: hkdf_expand")
}

// ----- Key import ------------------------------------------------------------

pub fn cm_import<A: ApiAlloc>(_alloc: &A, _usage: CmKeyUsage, _data: &[u8]) -> PalResult<Cmk> {
    unimplemented!("spdm-crypto placeholder: cm_import")
}

// ----- ECDH ------------------------------------------------------------------

/// Encrypted ECDH context size (bytes).
pub const CMB_ECDH_ENCRYPTED_CONTEXT_SIZE: usize = 76;
/// Max ECDH exchange-data size (bytes).
pub const CMB_ECDH_EXCHANGE_DATA_MAX_SIZE: usize = 96;

pub fn ecdh_generate<A: ApiAlloc>(
    _alloc: &A,
    _context: &mut [u8],
    _exchange_data: &mut [u8],
) -> PalResult<()> {
    unimplemented!("spdm-crypto placeholder: ecdh_generate")
}

pub fn ecdh_finish<A: ApiAlloc>(
    _alloc: &A,
    _context: &[u8],
    _key_usage: CmKeyUsage,
    _peer_exchange_data: &[u8],
) -> PalResult<Cmk> {
    unimplemented!("spdm-crypto placeholder: ecdh_finish")
}

// ----- AES-GCM ---------------------------------------------------------------

/// AES-256-GCM authentication tag.
pub type Aes256GcmTag = [u8; 16];

/// Opaque AES-GCM context (borrowed from the allocator).
pub type AesGcmCtx<'a, A> = <A as ApiAlloc>::Buf<'a>;

pub fn spdm_aes_gcm_encrypt<A: ApiAlloc>(
    _alloc: &A,
    _cmk: &Cmk,
    _spdm_version: u8,
    _seq_number: &[u8; 8],
    _aad: &[u8],
    _plaintext: &[u8],
    _ciphertext: &mut [u8],
) -> PalResult<(usize, Aes256GcmTag)> {
    unimplemented!("spdm-crypto placeholder: spdm_aes_gcm_encrypt")
}

// Mirrors the SPDM AEAD call shape (key, version, sequence number, AAD,
// ciphertext, tag, output); bundling them would obscure it.
#[allow(clippy::too_many_arguments)]
pub fn spdm_aes_gcm_decrypt<A: ApiAlloc>(
    _alloc: &A,
    _cmk: &Cmk,
    _spdm_version: u8,
    _seq_number: &[u8; 8],
    _aad: &[u8],
    _ciphertext: &[u8],
    _tag: &Aes256GcmTag,
    _plaintext: &mut [u8],
) -> PalResult<usize> {
    unimplemented!("spdm-crypto placeholder: spdm_aes_gcm_decrypt")
}

// ----- DPE -------------------------------------------------------------------

/// Label length fed to DPE `CertifyKey`.
pub const DPE_LABEL_LEN: usize = 48;
/// Max bytes returned per DPE cert-chain chunk.
pub const DPE_MAX_CHUNK_SIZE: usize = 1024;
/// DPE context-handle width.
pub const DPE_CONTEXT_HANDLE_SIZE: usize = 16;
/// DPE P-384 signature size.
pub const DPE_P384_SIGNATURE_SIZE: usize = 96;

/// Sink fed successive DPE cert-chain chunks by [`walk_dpe_chain`].
pub trait DpeChainSink {
    fn on_chunk(&mut self, chunk: &[u8]) -> PalResult<()>;
}

pub fn dpe_get_cert_chain_chunk<A: ApiAlloc>(
    _alloc: &A,
    _offset: u32,
    _dst: &mut [u8],
) -> PalResult<usize> {
    unimplemented!("spdm-crypto placeholder: dpe_get_cert_chain_chunk")
}

pub fn dpe_certify_key_cert_size<A: ApiAlloc>(
    _alloc: &A,
    _label: &[u8; DPE_LABEL_LEN],
) -> PalResult<usize> {
    unimplemented!("spdm-crypto placeholder: dpe_certify_key_cert_size")
}

pub fn dpe_certify_key_cert_slice<A: ApiAlloc>(
    _alloc: &A,
    _label: &[u8; DPE_LABEL_LEN],
    _cert_offset: u32,
    _dst: &mut [u8],
) -> PalResult<usize> {
    unimplemented!("spdm-crypto placeholder: dpe_certify_key_cert_slice")
}

pub fn dpe_sign_ecc_p384<A: ApiAlloc>(
    _alloc: &A,
    _label: &[u8; DPE_LABEL_LEN],
    _digest: &[u8],
    _signature: &mut [u8],
) -> PalResult<usize> {
    unimplemented!("spdm-crypto placeholder: dpe_sign_ecc_p384")
}

pub fn walk_dpe_chain<A: ApiAlloc, S: DpeChainSink>(_alloc: &A, _sink: &mut S) -> PalResult<u32> {
    unimplemented!("spdm-crypto placeholder: walk_dpe_chain")
}

// ----- RNG -------------------------------------------------------------------

pub fn rng_generate<A: ApiAlloc>(_alloc: &A, _out: &mut [u8]) -> PalResult<()> {
    unimplemented!("spdm-crypto placeholder: rng_generate")
}
