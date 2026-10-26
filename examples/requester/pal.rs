// Licensed under the Apache-2.0 license

//! Host crypto for the PoC requester: a SHA-384 `SpdmPalHash` and a
//! `PeerVerifier` doing full x509 chain validation (root → intermediate → leaf)
//! plus ECDSA-P384 signature verification.

use der::{Decode, Encode};
use p384::ecdsa::signature::hazmat::PrehashVerifier;
use p384::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha384};
use x509_cert::Certificate;

use spdm_errors::{codes::INVARIANT, PalResult};
use spdm_stack::requester::PeerVerifier;
use spdm_traits::{SpdmPalHash, SpdmPalHashAlgo, SpdmPalIo};

/// SHA-384 running-hash backend (same logic as the responder's `HostPal`).
pub struct HostHash;

impl SpdmPalHash for HostHash {
    type State = Sha384;

    fn hash_init(
        &self,
        _io: &impl SpdmPalIo,
        algo: SpdmPalHashAlgo,
        seed: &[u8],
    ) -> PalResult<Self::State> {
        match algo {
            SpdmPalHashAlgo::Sha384 => {
                let mut h = Sha384::new();
                if !seed.is_empty() {
                    h.update(seed);
                }
                Ok(h)
            }
        }
    }

    fn hash_update(
        &self,
        _io: &impl SpdmPalIo,
        state: &mut Self::State,
        data: &[u8],
    ) -> PalResult<()> {
        if !data.is_empty() {
            state.update(data);
        }
        Ok(())
    }

    fn hash_clone(&self, _io: &impl SpdmPalIo, state: &Self::State) -> PalResult<Self::State> {
        Ok(state.clone())
    }

    fn hash_finish(
        &self,
        _io: &impl SpdmPalIo,
        state: &mut Self::State,
        out: &mut [u8],
    ) -> PalResult<()> {
        if out.len() < 48 {
            return Err(INVARIANT);
        }
        out[..48].copy_from_slice(&state.clone().finalize());
        Ok(())
    }
}

/// Host peer verifier: parses the DER chain, validates it end to end, and
/// verifies SPDM signatures with the leaf key.
pub struct HostVerifier;

impl PeerVerifier for HostVerifier {
    type PubKey = VerifyingKey;

    fn validate_chain(&self, der_chain: &[u8]) -> PalResult<Self::PubKey> {
        // Split the concatenated DER into individual certificates.
        let mut certs: Vec<Certificate> = Vec::new();
        let mut rest = der_chain;
        while !rest.is_empty() {
            let cert_len = der_seq_len(rest).ok_or(INVARIANT)?;
            if cert_len > rest.len() {
                return Err(INVARIANT);
            }
            let cert = Certificate::from_der(&rest[..cert_len]).map_err(|_| INVARIANT)?;
            certs.push(cert);
            rest = &rest[cert_len..];
        }
        if certs.is_empty() {
            return Err(INVARIANT);
        }

        // Full chain validation: each cert must be signed by the next one
        // (chain is ordered leaf-last: root, inter..., leaf per SPDM). Verify
        // cert[i] is signed by cert[i-1] (issuer precedes subject).
        for i in 1..certs.len() {
            let issuer_key = p384_key_from_cert(&certs[i - 1])?;
            verify_cert_signature(&certs[i], &issuer_key)?;
        }
        // The root (index 0) is self-signed; verify that too.
        let root_key = p384_key_from_cert(&certs[0])?;
        verify_cert_signature(&certs[0], &root_key)?;

        // Leaf is the last cert; return its public key for SPDM sig checks.
        p384_key_from_cert(certs.last().ok_or(INVARIANT)?)
    }

    fn verify_p384(&self, key: &Self::PubKey, tbs: &[u8; 48], sig: &[u8]) -> PalResult<()> {
        let signature = Signature::from_slice(sig).map_err(|_| INVARIANT)?;
        key.verify_prehash(tbs, &signature).map_err(|_| INVARIANT)
    }
}

/// Total length of the leading DER SEQUENCE (tag + length header + content).
fn der_seq_len(buf: &[u8]) -> Option<usize> {
    if buf.len() < 2 || buf[0] != 0x30 {
        return None;
    }
    if buf[1] & 0x80 == 0 {
        Some(2 + buf[1] as usize)
    } else {
        let n = (buf[1] & 0x7f) as usize;
        if n == 0 || n > 4 || buf.len() < 2 + n {
            return None;
        }
        let mut len = 0usize;
        for &b in &buf[2..2 + n] {
            len = (len << 8) | b as usize;
        }
        Some(2 + n + len)
    }
}

/// Extract the P-384 public key from a certificate's SubjectPublicKeyInfo.
fn p384_key_from_cert(cert: &Certificate) -> PalResult<VerifyingKey> {
    let spki = cert.tbs_certificate().subject_public_key_info();
    let key_bytes = spki.subject_public_key.as_bytes().ok_or(INVARIANT)?;
    VerifyingKey::from_sec1_bytes(key_bytes).map_err(|_| INVARIANT)
}

/// Verify that `cert`'s signature was produced over its TBS by `issuer_key`.
fn verify_cert_signature(cert: &Certificate, issuer_key: &VerifyingKey) -> PalResult<()> {
    let tbs_der = cert.tbs_certificate().to_der().map_err(|_| INVARIANT)?;
    let sig_bytes = cert.signature().as_bytes().ok_or(INVARIANT)?;
    // ECDSA-P384 X.509 signatures are DER-encoded (r,s).
    let signature = Signature::from_der(sig_bytes).map_err(|_| INVARIANT)?;
    let mut h = Sha384::new();
    h.update(&tbs_der);
    let digest = h.finalize();
    issuer_key
        .verify_prehash(&digest, &signature)
        .map_err(|_| INVARIANT)
}
