// Licensed under the Apache-2.0 license

//! SPDM requester driver (VCA milestone).
//!
//! This is the requester-side counterpart to the responder `SpdmStack`. For now
//! it drives only the VCA handshake — `GET_VERSION`, `GET_CAPABILITIES`,
//! `NEGOTIATE_ALGORITHMS` — building requests with the `codec` request builders
//! and parsing responses with the `codec` parsers. Later milestones add
//! DIGESTS / CERTIFICATE / CHALLENGE / MEASUREMENTS and peer verification.
//!
//! # Transport
//!
//! The responder's [`SpdmPalIoTransport`](spdm_traits::SpdmPalIoTransport) is
//! shaped for a responder (`recv_request` then `send_response`). A requester
//! does the opposite, so this module defines its own minimal
//! [`RequesterTransport`] seam (send a request, receive a response). Keeping it
//! separate avoids reshaping the shared responder trait until the full requester
//! lands.

mod algorithms;
mod attest;
mod capabilities;
mod version;

pub use attest::Attestation;

use spdm_codec::{
    AeadAlgos, AsymAlgos, CapFlags, DheAlgos, HashAlgos, KeyScheduleAlgos, MeasHashAlgos, MeasSpec,
    OtherParamSupport, SpdmVersion,
};
use spdm_error::PalResult;
use spdm_traits::{SpdmPalHash, SpdmPalIo, SpdmPalIoKind};

use crate::transcript::Transcript;

/// Transport seam for a requester: send a fully-encoded SPDM request and read
/// back the responder's SPDM response into `buf`, returning its length.
///
/// Implementations own the underlying medium (TCP socket, MCTP, DOE, …) and any
/// transport framing. `send`/`recv` carry raw SPDM message bytes (SPDM common
/// header + body), no transport header.
pub trait RequesterTransport {
    /// Send one SPDM request message (`msg` is the raw SPDM payload).
    fn send(&mut self, msg: &[u8]) -> PalResult<()>;

    /// Receive one SPDM response message into `buf`; returns the byte length.
    fn recv(&mut self, buf: &mut [u8]) -> PalResult<usize>;
}

/// Peer (responder) certificate/signature verification seam.
///
/// The requester uses this to validate the responder's cert chain and verify the
/// ECDSA-P384 signatures on CHALLENGE_AUTH / MEASUREMENTS. Verification needs
/// x509 + ECDSA which live outside the protocol crate, so it is provided by the
/// caller (e.g. host `p384`/`x509-cert`).
pub trait PeerVerifier {
    /// Opaque public-key handle bound to a validated chain.
    type PubKey;

    /// Validate the raw DER cert chain (root ‖ … ‖ leaf) — full x509 path
    /// validation — and return the leaf public key for signature checks.
    ///
    /// `der_chain` is the concatenated DER (the SPDM 52-byte cert-chain header
    /// has already been stripped by the requester).
    fn validate_chain(&self, der_chain: &[u8]) -> PalResult<Self::PubKey>;

    /// Verify an ECDSA-P384 signature over `tbs` (a 48-byte SHA-384 digest that
    /// was signed with the prehash variant) using `key`. `sig` is the fixed
    /// 96-byte r‖s encoding.
    fn verify_p384(&self, key: &Self::PubKey, tbs: &[u8; 48], sig: &[u8]) -> PalResult<()>;
}

/// The requester's local policy — what it offers during VCA.
#[derive(Clone, Copy)]
pub struct RequesterConfig {
    pub ct_exponent: u8,
    pub flags: CapFlags,
    pub data_transfer_size: u32,
    pub max_spdm_msg_size: u32,
    pub measurement_spec: MeasSpec,
    pub other_param_support: OtherParamSupport,
    pub base_asym_algo: AsymAlgos,
    pub base_hash_algo: HashAlgos,
    pub dhe: DheAlgos,
    pub aead: AeadAlgos,
    pub key_schedule: KeyScheduleAlgos,
}

impl Default for RequesterConfig {
    /// Defaults mirror the responder's fixed policy (`ConnectionState::caliptra`)
    /// so a VCA exchange between our own requester and responder negotiates
    /// cleanly: ECDSA-P384 / SHA-384 / SECP384R1 / AES-256-GCM.
    fn default() -> Self {
        Self {
            ct_exponent: 0,
            flags: CapFlags::CERT | CapFlags::CHAL | CapFlags::MEAS_SIG,
            data_transfer_size: 4096,
            max_spdm_msg_size: 4096,
            measurement_spec: MeasSpec::DMTF,
            other_param_support: OtherParamSupport::OPAQUE_DATA_FMT1,
            base_asym_algo: AsymAlgos::ECDSA_ECC_NIST_P384,
            base_hash_algo: HashAlgos::SHA_384,
            dhe: DheAlgos::SECP_384_R1,
            aead: AeadAlgos::AES_256_GCM,
            key_schedule: KeyScheduleAlgos::SPDM,
        }
    }
}

/// Negotiated results captured during VCA.
#[derive(Clone, Copy)]
pub struct Negotiated {
    /// SPDM version selected during `GET_CAPABILITIES` (highest common).
    pub version: SpdmVersion,
    /// Peer (responder) capability flags.
    pub peer_flags: CapFlags,
    pub peer_data_transfer_size: u32,
    pub peer_max_spdm_msg_size: u32,
    /// Negotiated selections from ALGORITHMS.
    pub base_asym_sel: AsymAlgos,
    pub base_hash_sel: HashAlgos,
    pub meas_hash_algo: MeasHashAlgos,
    pub dhe_sel: DheAlgos,
    pub aead_sel: AeadAlgos,
    pub key_schedule_sel: KeyScheduleAlgos,
}

/// Scratch buffer size for building requests / receiving responses.
const BUF_LEN: usize = 4096;

/// Minimal [`SpdmPalIo`] shim for the requester's hash calls.
///
/// The requester drives the transcript hash directly (not through a responder
/// I/O exchange), but `SpdmPalHash` methods take `&impl SpdmPalIo`. Host hash
/// backends ignore the `io` argument, so a no-op stand-in suffices.
pub(crate) struct NullIo;

impl SpdmPalIo for NullIo {
    fn kind(&self) -> SpdmPalIoKind {
        SpdmPalIoKind::Message
    }
    fn request(&self) -> &[u8] {
        &[]
    }
}

/// SPDM requester driver.
///
/// Generic over the transport `T`, a hash backend `H` (transcript + TBS), and a
/// peer verifier `V` (cert-chain validation + signature verify). All three are
/// supplied by the caller.
pub struct SpdmRequester<T: RequesterTransport, H: SpdmPalHash, V: PeerVerifier> {
    transport: T,
    hash: H,
    verifier: V,
    config: RequesterConfig,
    /// Scratch buffer for building requests / receiving responses.
    buf: [u8; BUF_LEN],
    /// Common SPDM version negotiated during VCA (defaults to V1.0 for the
    /// initial GET_VERSION per DSP0274).
    version: SpdmVersion,
    /// VCA/M1/L1 transcript, mirrored byte-for-byte against the responder.
    transcript: Transcript<H::State>,
}

impl<T: RequesterTransport, H: SpdmPalHash, V: PeerVerifier> SpdmRequester<T, H, V> {
    /// Build a requester with the default (responder-matching) config.
    pub fn new(transport: T, hash: H, verifier: V) -> Self {
        Self::with_config(transport, hash, verifier, RequesterConfig::default())
    }

    /// Build a requester with an explicit local policy.
    pub fn with_config(transport: T, hash: H, verifier: V, config: RequesterConfig) -> Self {
        Self {
            transport,
            hash,
            verifier,
            config,
            buf: [0u8; BUF_LEN],
            version: SpdmVersion::V10,
            transcript: Transcript::new(),
        }
    }

    /// Runs the full VCA handshake and returns the negotiated parameters.
    pub fn negotiate(&mut self) -> PalResult<Negotiated> {
        let versions = self.get_version()?;
        let (version, peer_flags, peer_dts, peer_max) = self.get_capabilities(&versions)?;
        let algs = self.negotiate_algorithms(version)?;
        Ok(Negotiated {
            version,
            peer_flags,
            peer_data_transfer_size: peer_dts,
            peer_max_spdm_msg_size: peer_max,
            base_asym_sel: algs.base_asym_sel,
            base_hash_sel: algs.base_hash_sel,
            meas_hash_algo: algs.meas_hash_algo,
            dhe_sel: algs.dhe,
            aead_sel: algs.aead,
            key_schedule_sel: algs.key_schedule,
        })
    }

    /// Append `bytes` to the VCA transcript slot.
    pub(crate) fn append_vca(&mut self, bytes: &[u8]) -> PalResult<()> {
        self.transcript.append_vca(&self.hash, &NullIo, bytes)
    }

    /// Append `bytes` to the M1 transcript slot.
    pub(crate) fn append_m1(&mut self, bytes: &[u8]) -> PalResult<()> {
        self.transcript.append_m1(&self.hash, &NullIo, bytes)
    }

    /// Append `bytes` to the L1 transcript slot.
    pub(crate) fn append_l1(&mut self, bytes: &[u8]) -> PalResult<()> {
        self.transcript.append_l1(&self.hash, &NullIo, bytes)
    }

    /// Consume the requester and return the underlying transport.
    pub fn into_transport(self) -> T {
        self.transport
    }
}
