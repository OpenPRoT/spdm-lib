// Copyright 2025
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Host crypto for the PoC requester: a SHA-384 `SpdmPalHash` and a
//! `PeerVerifier` doing full x509 chain validation (root → intermediate → leaf)
//! plus ECDSA-P384 and ML-DSA-87 signature verification. The key type follows the
//! certificate's SubjectPublicKeyInfo, so a chain of either algorithm validates.

use der::{asn1::ObjectIdentifier, Decode, Encode};
use ml_dsa::{EncodedVerifyingKey, MlDsa87, Signature as PqSignature, VerifyingKey as PqKey};
use p384::ecdsa::signature::hazmat::PrehashVerifier;
use p384::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha384};
use x509_cert::Certificate;

use spdm_errors::{codes::INVARIANT, PalResult};
use spdm_stack::requester::PeerVerifier;
use spdm_traits::{SpdmPalHash, SpdmPalHashAlgo, SpdmPalIo, SpdmPalRng};

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

/// Host random source: OS-seeded thread RNG from `rand`.
pub struct HostRng;

impl SpdmPalRng for HostRng {
    fn fill_random(&self, _io: &impl SpdmPalIo, out: &mut [u8]) -> PalResult<()> {
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), out);
        Ok(())
    }
}

/// Host peer verifier: parses the DER chain, checks that its root is one of the
/// pinned trust anchors, validates it end to end, and verifies SPDM signatures
/// with the leaf key.
///
/// The chain's root is only trusted if it is byte-identical to a trust anchor
/// passed to [`HostVerifier::new`]. A chain that merely verifies against its own
/// root proves nothing.
pub struct HostVerifier {
    trust_anchors: Vec<Vec<u8>>,
}

impl HostVerifier {
    /// Trusts only chains rooted at one of `trust_anchors` (DER certificates).
    pub fn new(trust_anchors: Vec<Vec<u8>>) -> Self {
        Self { trust_anchors }
    }
}

/// The roots of this repository's own demo hierarchies: the static `DEMO CA`
/// (ECDSA P-384) and the ML-DSA-87 root `build.rs` generates on every clean
/// build. Their private keys are public or throwaway, so these anchors are for
/// host testing only. A real Requester pins its own vendor root instead.
pub fn demo_trust_anchors() -> Vec<Vec<u8>> {
    alloc_vecs([
        include_bytes!("../certs/demo-ca.cert.der").as_slice(),
        include_bytes!(concat!(env!("OUT_DIR"), "/pq_root.der")).as_slice(),
    ])
}

fn alloc_vecs<const N: usize>(roots: [&[u8]; N]) -> Vec<Vec<u8>> {
    roots.into_iter().map(<[u8]>::to_vec).collect()
}

/// id-ml-dsa-87 (RFC 9881).
const ML_DSA_87: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.19");

/// A certified public key of either supported algorithm.
pub enum HostKey {
    Ec(VerifyingKey),
    Pq(Box<PqKey<MlDsa87>>),
}

impl PeerVerifier for HostVerifier {
    type PubKey = HostKey;

    fn validate_chain(&self, der_chain: &[u8]) -> PalResult<Self::PubKey> {
        // Split the concatenated DER into individual certificates.
        let mut certs: Vec<Certificate> = Vec::new();
        let mut root_der: &[u8] = &[];
        let mut rest = der_chain;
        while !rest.is_empty() {
            let cert_len = der_seq_len(rest).ok_or(INVARIANT)?;
            if cert_len > rest.len() {
                return Err(INVARIANT);
            }
            let cert = Certificate::from_der(&rest[..cert_len]).map_err(|_| INVARIANT)?;
            if certs.is_empty() {
                root_der = &rest[..cert_len];
            }
            certs.push(cert);
            rest = &rest[cert_len..];
        }
        if certs.is_empty() {
            return Err(INVARIANT);
        }

        // Pin the root: the chain must start at a certificate we already trust.
        if !self.trust_anchors.iter().any(|a| a == root_der) {
            return Err(INVARIANT);
        }

        // Full chain validation: each cert must be signed by the next one
        // (chain is ordered leaf-last: root, inter..., leaf per SPDM). Verify
        // cert[i] is signed by cert[i-1] (issuer precedes subject).
        for i in 1..certs.len() {
            let issuer_key = key_from_cert(&certs[i - 1])?;
            verify_cert_signature(&certs[i], &issuer_key)?;
        }
        // The root (index 0) is self-signed; verify that too.
        let root_key = key_from_cert(&certs[0])?;
        verify_cert_signature(&certs[0], &root_key)?;

        // Leaf is the last cert; return its public key for SPDM sig checks.
        key_from_cert(certs.last().ok_or(INVARIANT)?)
    }

    fn verify_p384(&self, key: &Self::PubKey, tbs: &[u8; 48], sig: &[u8]) -> PalResult<()> {
        let HostKey::Ec(key) = key else {
            return Err(INVARIANT);
        };
        let signature = Signature::from_slice(sig).map_err(|_| INVARIANT)?;
        key.verify_prehash(tbs, &signature).map_err(|_| INVARIANT)
    }

    fn verify_mldsa87(
        &self,
        key: &Self::PubKey,
        context: &[u8],
        message: &[u8],
        sig: &[u8],
    ) -> PalResult<()> {
        let HostKey::Pq(key) = key else {
            return Err(INVARIANT);
        };
        let signature = PqSignature::<MlDsa87>::try_from(sig).map_err(|_| INVARIANT)?;
        key.verify_with_context(message, context, &signature)
            .then_some(())
            .ok_or(INVARIANT)
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

/// Extract the public key from a certificate's SubjectPublicKeyInfo: ML-DSA-87
/// or SEC1 P-384, by the SPKI algorithm OID.
fn key_from_cert(cert: &Certificate) -> PalResult<HostKey> {
    let spki = cert.tbs_certificate().subject_public_key_info();
    let key_bytes = spki.subject_public_key.as_bytes().ok_or(INVARIANT)?;
    if spki.algorithm.oid == ML_DSA_87 {
        let enc = EncodedVerifyingKey::<MlDsa87>::try_from(key_bytes).map_err(|_| INVARIANT)?;
        return Ok(HostKey::Pq(Box::new(PqKey::decode(&enc))));
    }
    VerifyingKey::from_sec1_bytes(key_bytes)
        .map(HostKey::Ec)
        .map_err(|_| INVARIANT)
}

/// Verify that `cert`'s signature was produced over its TBS by `issuer_key`:
/// DER-encoded ECDSA-P384/SHA-384, or pure ML-DSA-87 with an empty context.
fn verify_cert_signature(cert: &Certificate, issuer_key: &HostKey) -> PalResult<()> {
    let tbs_der = cert.tbs_certificate().to_der().map_err(|_| INVARIANT)?;
    let sig_bytes = cert.signature().as_bytes().ok_or(INVARIANT)?;
    match issuer_key {
        HostKey::Ec(key) => {
            let signature = Signature::from_der(sig_bytes).map_err(|_| INVARIANT)?;
            let digest = Sha384::digest(&tbs_der);
            key.verify_prehash(&digest, &signature)
                .map_err(|_| INVARIANT)
        }
        HostKey::Pq(key) => {
            let signature = PqSignature::<MlDsa87>::try_from(sig_bytes).map_err(|_| INVARIANT)?;
            key.verify_with_context(&tbs_der, &[], &signature)
                .then_some(())
                .ok_or(INVARIANT)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEMO_CA: &[u8] = include_bytes!("../certs/demo-ca.cert.der");
    const SIGNING: &[u8] = include_bytes!("../certs/signing-demo.cert.der");
    const IDENTITY_SIGNING: &[u8] = include_bytes!("../certs/identity-signing-demo.cert.der");
    const DEVICE_CHAIN: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/device_chain.der"));
    const PQ_CHAIN: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/pq_chain.der"));

    fn p384_chain() -> Vec<u8> {
        [DEMO_CA, SIGNING, IDENTITY_SIGNING, DEVICE_CHAIN].concat()
    }

    #[test]
    fn accepts_chains_rooted_at_the_demo_anchors() {
        let verifier = HostVerifier::new(demo_trust_anchors());
        assert!(verifier.validate_chain(&p384_chain()).is_ok());
        assert!(verifier.validate_chain(PQ_CHAIN).is_ok());
    }

    #[test]
    fn rejects_a_correctly_signed_chain_with_an_unpinned_root() {
        // Self-consistent chain, but its root is not a trust anchor.
        let verifier = HostVerifier::new(alloc_vecs([SIGNING]));
        assert!(verifier.validate_chain(&p384_chain()).is_err());
        let no_anchors = HostVerifier::new(Vec::new());
        assert!(no_anchors.validate_chain(&p384_chain()).is_err());
    }
}
