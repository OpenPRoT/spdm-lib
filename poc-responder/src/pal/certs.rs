// Licensed under the Apache-2.0 license

//! Static DER cert chain + P-384 ECDSA signing, ported from the legacy
//! `cert_store.rs` example. Serves raw DER slices to the stack (which prepends
//! the 52-byte SPDM cert-chain header itself) and signs CHALLENGE / MEASUREMENTS
//! transcripts with a P-384 prehash signer.

use p384::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use p384::SecretKey;
use sha2::{Digest, Sha384};

use spdm_error::{codes::INVARIANT, PalResult};
use spdm_traits::{SpdmPalAsymAlgo, SpdmPalCertStore, SpdmPalHashAlgo};

use super::HostPal;

// DER assets reused from the legacy example (no copy).
pub const ROOT_CA_CERT: &[u8] = include_bytes!("../../../legacy/examples/certs/ca.cert.der");
pub const INTER_CERT: &[u8] = include_bytes!("../../../legacy/examples/certs/inter.cert.der");
pub const END_CERT: &[u8] = include_bytes!("../../../legacy/examples/certs/end_responder.cert.der");
pub const END_KEY_DER: &[u8] =
    include_bytes!("../../../legacy/examples/certs/end_responder.key.der");

const ECC_P384_SIG_SIZE: usize = 96;

/// Static cert chain (root ‖ inter ‖ end) plus the end-entity signing key.
pub struct CertState {
    chain: Vec<u8>,
    signing_key: SigningKey,
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

        Self { chain, signing_key }
    }
}

impl SpdmPalCertStore for HostPal {
    fn supported_slots(&self) -> u8 {
        0x01 // slot 0 only
    }

    fn provisioned_slots(&self) -> u8 {
        0x01
    }

    fn cert_chain_slot_size(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        _algo: SpdmPalAsymAlgo,
    ) -> PalResult<usize> {
        self.slot0(slot).map(|c| c.chain.len())
    }

    fn cert_chain_len(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        _algo: SpdmPalAsymAlgo,
    ) -> PalResult<usize> {
        self.slot0(slot).map(|c| c.chain.len())
    }

    fn root_cert_hash(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        _algo: SpdmPalAsymAlgo,
        hash_algo: SpdmPalHashAlgo,
        out: &mut [u8],
    ) -> PalResult<()> {
        let _ = self.slot0(slot)?;
        match hash_algo {
            SpdmPalHashAlgo::Sha384 => {
                if out.len() < 48 {
                    return Err(INVARIANT);
                }
                let mut h = Sha384::new();
                h.update(ROOT_CA_CERT);
                out[..48].copy_from_slice(&h.finalize());
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
        if offset >= cert.chain.len() {
            return Ok(0);
        }
        let n = (cert.chain.len() - offset).min(dst.len());
        dst[..n].copy_from_slice(&cert.chain[offset..offset + n]);
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

    fn key_pair_id(&self, slot: u8) -> Option<u8> {
        (slot == 0).then_some(1)
    }

    fn cert_info(&self, slot: u8) -> Option<u8> {
        // cert_model = 1 (DeviceCert) in bits 0..3.
        (slot == 0).then_some(1)
    }

    fn key_usage_mask(&self, slot: u8) -> Option<u16> {
        // challenge_usage | measurement_usage.
        (slot == 0).then_some(0x0003)
    }

    fn generate_nonce(&self, _io: &Self::Io<'_>, out: &mut [u8]) -> PalResult<()> {
        use rand::RngCore;
        rand::thread_rng().fill_bytes(out);
        Ok(())
    }
}
