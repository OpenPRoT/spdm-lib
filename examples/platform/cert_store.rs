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

//! Certificate Store Platform Implementation
//!
//! Provides certificate management using static certificates with ECDSA signing

use std::sync::Mutex;

use p384::{
    ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey},
    SecretKey,
};
use zerocopy::FromBytes;

use super::certs::{
    STATIC_END_CERT, STATIC_END_RESPONDER_KEY_DER, STATIC_INTER_CERT, STATIC_ROOT_CA_CERT,
};
use spdm_lib::commands::challenge::MeasurementSummaryHashType;
use spdm_lib::protocol::{
    algorithms::{AsymAlgo, ECC_P384_SIGNATURE_SIZE, SHA384_HASH_SIZE},
    SpdmCertChainHeader,
};
use spdm_lib::protocol::{
    certs::{CertificateInfo, KeyUsageMask},
    BaseHashAlgoType,
};
use spdm_lib::{
    cert_store::{CertStoreError, CertStoreResult, PeerCertStore, ReassemblyStatus, SpdmCertStore},
    error::PlatformError,
};

/// Certificate store with proper ECDSA signing
pub struct DemoCertStore {
    cert_chain: Vec<u8>,
    signing_key: Mutex<Option<SigningKey>>,
}

impl DemoCertStore {
    pub fn new() -> Self {
        println!("Loading static certificate chain...");
        let (cert_chain, signing_key) = Self::generate_certificate_chain();
        println!("Static certificate chain loaded successfully");

        Self {
            cert_chain,
            signing_key: Mutex::new(Some(signing_key)),
        }
    }

    fn generate_certificate_chain() -> (Vec<u8>, SigningKey) {
        // Concatenate Root CA + Intermediate + End-entity certificates
        let mut cert_chain = Vec::new();
        cert_chain.extend_from_slice(STATIC_ROOT_CA_CERT);
        cert_chain.extend_from_slice(STATIC_INTER_CERT);
        cert_chain.extend_from_slice(STATIC_END_CERT);

        // Parse the P-384 private key from SEC1 DER format.
        // SEC1 ECPrivateKey: SEQUENCE { version INTEGER, privateKey OCTET STRING(48), ... }
        // For a P-384 key with 2-byte length header: skip 8 bytes to reach the raw 48-byte scalar.
        let raw_key: &[u8; 48] = STATIC_END_RESPONDER_KEY_DER[8..56]
            .try_into()
            .expect("key DER too short");
        let secret_key =
            SecretKey::from_bytes(raw_key.into()).expect("Failed to parse end-entity private key");

        (cert_chain, SigningKey::from(secret_key))
    }

    /// Extract the first certificate from a DER-encoded certificate chain
    #[allow(dead_code)]
    fn extract_first_certificate_der<'a>(&self, cert_chain: &'a [u8]) -> Option<&'a [u8]> {
        if cert_chain.len() < 2 {
            return None;
        }

        let mut offset = 0;

        // Check for SEQUENCE tag (0x30)
        if cert_chain[offset] != 0x30 {
            return None;
        }
        offset += 1;

        // Parse length and calculate total certificate size
        let (content_length, header_size) = if cert_chain[offset] & 0x80 == 0 {
            // Short form length (0-127)
            let content_len = cert_chain[offset] as usize;
            let header_len = 2; // tag + 1 byte length
            (content_len, header_len)
        } else {
            // Long form length
            let length_octets = (cert_chain[offset] & 0x7f) as usize;
            if length_octets == 0 || length_octets > 4 {
                return None;
            }
            offset += 1;

            if offset + length_octets > cert_chain.len() {
                return None;
            }

            let mut content_len = 0;
            for i in 0..length_octets {
                content_len = (content_len << 8) | cert_chain[offset + i] as usize;
            }

            let header_len = 2 + length_octets; // tag + length indicator + length bytes
            (content_len, header_len)
        };

        let total_cert_size = header_size + content_length;

        if total_cert_size > cert_chain.len() {
            return None;
        }

        Some(&cert_chain[0..total_cert_size])
    }
}

impl SpdmCertStore for DemoCertStore {
    fn slot_count(&self) -> u8 {
        1 // Only support slot 0
    }

    fn is_provisioned(&self, slot_id: u8) -> bool {
        slot_id == 0 // Only slot 0 is provisioned
    }

    fn cert_chain_len(&mut self, _asym_algo: AsymAlgo, slot_id: u8) -> CertStoreResult<usize> {
        if slot_id == 0 {
            Ok(self.cert_chain.len())
        } else {
            Err(CertStoreError::InvalidSlotId(slot_id))
        }
    }

    fn get_cert_chain<'a>(
        &mut self,
        slot_id: u8,
        _asym_algo: AsymAlgo,
        offset: usize,
        cert_portion: &'a mut [u8],
    ) -> CertStoreResult<usize> {
        if slot_id != 0 {
            return Err(CertStoreError::InvalidSlotId(slot_id));
        }

        if offset >= self.cert_chain.len() {
            return Ok(0);
        }

        let remaining = self.cert_chain.len() - offset;
        let copy_len = remaining.min(cert_portion.len());

        cert_portion[..copy_len].copy_from_slice(&self.cert_chain[offset..offset + copy_len]);
        //  println!("  Cert Chain Copy: {:02x?}", &cert_portion[..copy_len]);
        Ok(copy_len)
    }

    fn root_cert_hash<'a>(
        &mut self,
        slot_id: u8,
        _asym_algo: AsymAlgo,
        cert_hash: &'a mut [u8; SHA384_HASH_SIZE],
    ) -> CertStoreResult<()> {
        if slot_id != 0 {
            return Err(CertStoreError::InvalidSlotId(slot_id));
        }

        use sha2::{Digest, Sha384};
        // Calculate proper SHA-384 hash of the root certificate
        let mut hasher = Sha384::new();
        hasher.update(STATIC_ROOT_CA_CERT);
        let hash_result = hasher.finalize();
        cert_hash.copy_from_slice(&hash_result);
        // println!("  Fabrizio Root Hash starts: {:02x?}", &cert_hash[..4]);

        Ok(())
    }

    fn sign_hash<'a>(
        &self,
        slot_id: u8,
        hash: &'a [u8; SHA384_HASH_SIZE],
        signature: &'a mut [u8; ECC_P384_SIGNATURE_SIZE],
    ) -> CertStoreResult<()> {
        if slot_id != 0 {
            return Err(CertStoreError::InvalidSlotId(slot_id));
        }

        if let Ok(signing_key_guard) = self.signing_key.lock() {
            if let Some(ref signing_key) = *signing_key_guard {
                let sig: Signature = signing_key.sign_prehash(hash).unwrap();

                let sig_bytes = sig.to_bytes();
                if sig_bytes.len() <= ECC_P384_SIGNATURE_SIZE {
                    signature[..sig_bytes.len()].copy_from_slice(&sig_bytes);
                    return Ok(());
                }
                return Err(CertStoreError::PlatformError);
            }
        }
        Err(CertStoreError::PlatformError)
    }

    fn key_pair_id(&self, slot_id: u8) -> Option<u8> {
        if slot_id == 0 {
            Some(1)
        } else {
            None
        }
    }

    fn cert_info(&self, slot_id: u8) -> Option<CertificateInfo> {
        if slot_id != 0 {
            return None;
        }

        let mut cert_info = CertificateInfo(0);
        cert_info.set_cert_model(1);
        Some(cert_info)
    }

    fn key_usage_mask(&self, slot_id: u8) -> Option<KeyUsageMask> {
        if slot_id != 0 {
            return None;
        }

        let mut key_usage = KeyUsageMask::default();
        key_usage.set_challenge_usage(1);
        key_usage.set_measurement_usage(1);
        Some(key_usage)
    }
}

#[test]
fn test_signing() {
    use p384::ecdsa::signature::SignatureEncoding;

    // Load private key from SEC1 DER (raw 48-byte scalar at offset 8)
    let raw_key: &[u8; 48] = STATIC_END_RESPONDER_KEY_DER[8..56].try_into().unwrap();
    let secret_key = SecretKey::from_bytes(raw_key.into()).unwrap();
    let signing_key = SigningKey::from(secret_key);

    // Your input
    let input = hex::decode("32ac91a55d17db5e537448789486c633ecba4cd49185d0933f3d6561573fb68931f88bef4dc6ef20602df7dbeb51086b").unwrap();

    // Test 1: Sign directly
    let sig_direct: Signature = signing_key.sign(&input);
    println!("Direct signature:");
    let sig_bytes = sig_direct.to_bytes();
    println!("  R: {}", hex::encode(&sig_bytes[..48]));
    println!("  S: {}", hex::encode(&sig_bytes[48..]));

    // Test 2: Hash then sign
    let digest = Sha384::digest(&input);
    let sig_hashed: Signature = signing_key.sign(&digest[..]);
    println!("Hashed signature:");
    let sig_bytes_hashed = sig_hashed.to_bytes();
    println!("  R: {}", hex::encode(&sig_bytes_hashed[..48]));
    println!("  S: {}", hex::encode(&sig_bytes_hashed[48..]));
}

#[test]
fn debug_signing_verification() {
    use hex;
    use p384::ecdsa::signature::SignatureEncoding;

    // Your test data
    let input_hex = "32ac91a55d17db5e537448789486c633ecba4cd49185d0933f3d6561573fb68931f88bef4dc6ef20602df7dbeb51086b";
    let input = hex::decode(input_hex).unwrap();

    // Load private key from SEC1 DER (raw 48-byte scalar at offset 8)
    let raw_key: &[u8; 48] = STATIC_END_RESPONDER_KEY_DER[8..56].try_into().unwrap();
    let secret_key = SecretKey::from_bytes(raw_key.into()).unwrap();
    let signing_key = SigningKey::from(secret_key);

    // Get public key
    let verifying_key = signing_key.verifying_key();
    let public_point = verifying_key.to_encoded_point(false);
    println!("Public key: {}", hex::encode(public_point.as_bytes()));

    // Test 1: Sign directly
    println!("\n=== Test 1: Direct signing ===");
    let sig1: Signature = signing_key.sign(&input);
    let sig1_bytes = sig1.to_bytes();
    println!("Input: {}", input_hex);
    println!("Signature R: {}", hex::encode(&sig1_bytes[..48]));
    println!("Signature S: {}", hex::encode(&sig1_bytes[48..]));

    // Verify with Rust
    let verify_result = verifying_key.verify(&input, &sig1);
    println!("Rust verification: {:?}", verify_result);

    // Test 2: Hash then sign
    println!("\n=== Test 2: Hash then sign ===");
    let hashed = Sha384::digest(&input);
    println!("SHA-384 hash: {}", hex::encode(&hashed));
    let sig2: Signature = signing_key.sign(&hashed);
    let sig2_bytes = sig2.to_bytes();
    println!("Signature R: {}", hex::encode(&sig2_bytes[..48]));
    println!("Signature S: {}", hex::encode(&sig2_bytes[48..]));

    // Verify with Rust
    let verify_result2 = verifying_key.verify(&hashed, &sig2);
    println!("Rust verification of hashed: {:?}", verify_result2);

    // Test 3: What Python expects
    println!("\n=== For Python Testing ===");
    println!("# Test direct signature");
    println!("from cryptography.hazmat.primitives.asymmetric import ec, utils");
    println!("from cryptography.hazmat.primitives import hashes");
    println!("from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature");
    println!("import binascii");
    println!();
    println!(r#"data = binascii.unhexlify("{}")"#, input_hex);
    println!(
        r#"pubkey = binascii.unhexlify("{}")"#,
        hex::encode(public_point.as_bytes())
    );
    println!(r#"r1 = int("{}", 16)"#, hex::encode(&sig1_bytes[..48]));
    println!(r#"s1 = int("{}", 16)"#, hex::encode(&sig1_bytes[48..]));
    println!();
    println!("public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), pubkey)");
    println!("sig1 = encode_dss_signature(r1, s1)");
    println!();
    println!("# Try different verification methods");
    println!("try:");
    println!("    public_key.verify(sig1, data, ec.ECDSA(utils.Prehashed(hashes.SHA384())))");
    println!("    print('✓ Sig1 valid with Prehashed')");
    println!("except: print('✗ Sig1 invalid with Prehashed')");
    println!();
    println!("try:");
    println!("    public_key.verify(sig1, data, ec.ECDSA(hashes.SHA384()))");
    println!("    print('✓ Sig1 valid with SHA384')");
    println!("except: print('✗ Sig1 invalid with SHA384')");
}

#[derive(Debug, Default)]
pub struct PeerSlot {
    /// CertChain[K], retrieved in `CERTIFICATE` response.
    pub cert_chain: Vec<u8>,

    /// Digest[K], retrieved in `DIGESTS` response.
    pub digest: Vec<u8>,

    /// `KeyPairID[K]`, retrieved in `DIGESTS` response if the corresponding `MULTI_KEY_CONN_REQ` or `MULTI_KEY_CONN_RSP` is true.
    pub keypair_id: Option<u8>,

    /// `CertificateInfo[K]`, retrieved in `DIGESTS` response if the corresponding `MULTI_KEY_CONN_REQ` or `MULTI_KEY_CONN_RSP` is true. pub cert_info: Option<CertificateInfo>
    pub certificate_info: Option<CertificateInfo>,

    /// KeyUsageMask[K], retrieved in `DIGESTS` response if the corresponding `MULTI_KEY_CONN_REQ` or `MULTI_KEY_CONN_RSP` is true.
    pub key_usage_mask: Option<KeyUsageMask>,

    pub requested_msh_type: Option<MeasurementSummaryHashType>,
}

impl PeerSlot {
    /// Get the digest for the root certificate of the chain
    ///
    /// # Arguments
    /// * `hash_algo` - The hash algorithm negotiated with the peer.
    fn get_root_hash(&self, hash_algo: BaseHashAlgoType) -> Option<&[u8]> {
        let (length, rest) = SpdmCertChainHeader::ref_from_prefix(&self.cert_chain).ok()?;
        if length.get_length() != self.cert_chain.len() as u32 {
            println!(
                "[Error] cert chain length mismatch (expected {}, got {})",
                length.get_length(),
                self.cert_chain.len()
            );
            return None;
        }
        Some(&rest[..hash_algo.hash_byte_size()])
    }
    /// Get the DER x509 certificate chain
    ///
    /// # Arguments
    /// * `hash_algo` - The hash algorithm negotiated with the peer.
    fn get_cert_chain(&self, hash_algo: BaseHashAlgoType) -> Option<&[u8]> {
        let (length, rest) = SpdmCertChainHeader::ref_from_prefix(&self.cert_chain).ok()?;
        if length.get_length() != self.cert_chain.len() as u32 {
            println!(
                "[Error] cert chain length mismatch (expected {}, got {})",
                length.get_length(),
                self.cert_chain.len()
            );
            return None;
        }
        Some(&rest[hash_algo.hash_byte_size()..])
    }
}

/// Concrete implementation of `PeerCertStore` for demonstration purposes.
/// This example store manages a single certificate slot (slot 0) and allows
/// setting and retrieving the certificate chain, digest, key pair ID, certificate info,
/// and key usage mask for that slot. In a real implementation, you would likely
/// want to support multiple slots and have more robust error handling and storage mechanisms.
#[derive(Debug)]
pub struct ExamplePeerCertStore {
    /// Retrieved from `DIGESTS` response, indicates which certificate slots are supported by the peer.
    supported_slots_mask: u8,

    /// Retrieved from `DIGESTS` response, indicates which certificate slots are provisioned with valid certificate chains.
    provisioned_slots_mask: u8,

    // Since not all existing slots may hold eligible certificate chains, keep the PeerSlot values optional.
    pub peer_slots: Vec<Option<PeerSlot>>,
}

impl Default for ExamplePeerCertStore {
    fn default() -> Self {
        ExamplePeerCertStore {
            supported_slots_mask: 0,
            provisioned_slots_mask: 0,
            peer_slots: vec![None],
        }
    }
}

impl PeerCertStore for ExamplePeerCertStore {
    fn slot_count(&self) -> u8 {
        self.peer_slots.len() as u8
    }

    fn assemble(
        &mut self,
        slot_id: u8,
        portion: &[u8],
    ) -> Result<spdm_lib::cert_store::ReassemblyStatus, CertStoreError> {
        let slot = self
            .peer_slots
            .get_mut(slot_id as usize)
            .ok_or(CertStoreError::InvalidSlotId(slot_id))?
            .as_mut()
            .ok_or(CertStoreError::PlatformError)?;

        slot.cert_chain.extend_from_slice(portion);

        Ok(spdm_lib::cert_store::ReassemblyStatus::InProgress)
    }

    fn reset(&mut self, slot_id: u8) {
        if let Some(Some(slot)) = self.peer_slots.get_mut(slot_id as usize) {
            *slot = PeerSlot::default();
        }
    }

    fn get_raw_chain(&self, slot_id: u8) -> CertStoreResult<&[u8]> {
        let slot = self
            .peer_slots
            .get(slot_id as usize)
            .ok_or(CertStoreError::InvalidSlotId(slot_id))?
            .as_ref()
            .ok_or(CertStoreError::PlatformError)?;
        Ok(&slot.cert_chain)
    }

    fn get_cert_chain(&self, slot_id: u8, hash_algo: BaseHashAlgoType) -> CertStoreResult<&[u8]> {
        let slot = self
            .peer_slots
            .get(slot_id as usize)
            .ok_or(CertStoreError::InvalidSlotId(slot_id))?
            .as_ref()
            .ok_or(CertStoreError::PlatformError)?;
        slot.get_cert_chain(hash_algo)
            .ok_or(CertStoreError::CertReadError)
    }

    /// Set the supported slots bit mask and initialize PeerSlot entries for any newly supported slots.  
    fn set_supported_slots(&mut self, slot_mask: u8) -> CertStoreResult<()> {
        for b in 0..8 {
            if slot_mask & (1 << b) == 1 {
                if let Some(slot) = self.peer_slots.get_mut(b as usize) {
                    if slot.is_none() {
                        *slot = Some(PeerSlot::default());
                    }
                }
            }
        }

        Ok(())
    }

    fn get_supported_slots(&self) -> CertStoreResult<u8> {
        Ok(self.supported_slots_mask)
    }

    fn set_provisioned_slots(&mut self, provisioned_slot_mask: u8) -> CertStoreResult<()> {
        self.provisioned_slots_mask = provisioned_slot_mask;
        Ok(())
    }

    fn get_provisioned_slots(&self) -> CertStoreResult<u8> {
        Ok(self.provisioned_slots_mask)
    }

    /// Set the certificate chain for a given slot. This would typically be called
    /// after successfully reassembling the certificate chain from received portions.
    ///
    /// # Returns
    /// - `Ok(())` if the certificate chain was set successfully
    /// - `Err(CertStoreError)` if there was an error (e.g., invalid slot ID)
    fn set_cert_chain(&mut self, slot_id: u8, cert_chain: &[u8]) -> CertStoreResult<()> {
        let slot = self
            .peer_slots
            .get_mut(slot_id as usize)
            .ok_or(CertStoreError::InvalidSlotId(slot_id))?
            .as_mut()
            .ok_or(CertStoreError::PlatformError)?;

        slot.cert_chain = cert_chain.to_vec();
        Ok(())
    }

    fn get_digest(&self, slot_id: u8) -> CertStoreResult<&[u8]> {
        let slot = self
            .peer_slots
            .get(slot_id as usize)
            .ok_or(CertStoreError::InvalidSlotId(slot_id))?
            .as_ref()
            .ok_or(CertStoreError::PlatformError)?;
        Ok(&slot.digest)
    }

    /// Set the digest for a given slot, provided by the `DIGESTS` response.
    ///
    /// # Parameters
    /// - `slot_id`: The slot ID to set the digest for
    /// - `digest`: The digest value to set
    fn set_digest(&mut self, slot_id: u8, digest: &[u8]) -> CertStoreResult<()> {
        let slot: &mut PeerSlot = self
            .peer_slots
            .get_mut(slot_id as usize)
            .ok_or(CertStoreError::InvalidSlotId(slot_id))?
            .as_mut()
            .ok_or(CertStoreError::PlatformError)?;
        slot.digest = digest.to_vec();
        Ok(())
    }

    fn get_cert_info(&self, slot_id: u8) -> CertStoreResult<CertificateInfo> {
        let slot = self
            .peer_slots
            .get(slot_id as usize)
            .ok_or(CertStoreError::InvalidSlotId(slot_id))?
            .as_ref()
            .ok_or(CertStoreError::PlatformError)?;
        slot.certificate_info
            .ok_or(CertStoreError::InvalidSlotId(slot_id))
    }
    fn set_cert_info(&mut self, slot_id: u8, cert_info: CertificateInfo) -> CertStoreResult<()> {
        let slot = self
            .peer_slots
            .get_mut(slot_id as usize)
            .ok_or(CertStoreError::InvalidSlotId(slot_id))?
            .as_mut()
            .ok_or(CertStoreError::PlatformError)?;
        slot.certificate_info = Some(cert_info);
        Ok(())
    }
    fn get_key_usage_mask(&self, slot_id: u8) -> CertStoreResult<KeyUsageMask> {
        let slot = self
            .peer_slots
            .get(slot_id as usize)
            .ok_or(CertStoreError::InvalidSlotId(slot_id))?
            .as_ref()
            .ok_or(CertStoreError::PlatformError)?;
        slot.key_usage_mask
            .ok_or(CertStoreError::InvalidSlotId(slot_id))
    }

    fn set_key_usage_mask(
        &mut self,
        slot_id: u8,
        key_usage_mask: KeyUsageMask,
    ) -> CertStoreResult<()> {
        let slot = self
            .peer_slots
            .get_mut(slot_id as usize)
            .ok_or(CertStoreError::InvalidSlotId(slot_id))?
            .as_mut()
            .ok_or(CertStoreError::PlatformError)?;
        slot.key_usage_mask = Some(key_usage_mask);
        Ok(())
    }

    fn get_keypair(&self, slot_id: u8) -> CertStoreResult<u8> {
        let slot = self
            .peer_slots
            .get(slot_id as usize)
            .ok_or(CertStoreError::InvalidSlotId(slot_id))?
            .as_ref()
            .ok_or(CertStoreError::PlatformError)?;
        slot.keypair_id
            .ok_or(CertStoreError::InvalidSlotId(slot_id))
    }

    fn set_keypair(&mut self, slot_id: u8, keypair: u8) -> CertStoreResult<()> {
        let slot = self
            .peer_slots
            .get_mut(slot_id as usize)
            .ok_or(CertStoreError::InvalidSlotId(slot_id))?
            .as_mut()
            .ok_or(CertStoreError::PlatformError)?;
        slot.keypair_id = Some(keypair);
        Ok(())
    }

    fn get_root_hash(&self, slot_id: u8, hash_algo: BaseHashAlgoType) -> CertStoreResult<&[u8]> {
        let slot = self
            .peer_slots
            .get(slot_id as usize)
            .ok_or(CertStoreError::InvalidSlotId(slot_id))?
            .as_ref()
            .ok_or(CertStoreError::PlatformError)?;
        slot.get_root_hash(hash_algo)
            .ok_or(CertStoreError::CertReadError)
    }

    fn get_requested_msh_type(&self, slot_id: u8) -> CertStoreResult<MeasurementSummaryHashType> {
        self.peer_slots
            .get(slot_id as usize)
            .ok_or(CertStoreError::InvalidSlotId(slot_id))?
            .as_ref()
            .ok_or(CertStoreError::PlatformError)?
            .requested_msh_type
            .clone()
            .ok_or(CertStoreError::Undefined)
    }

    fn set_requested_msh_type(
        &mut self,
        slot_id: u8,
        msh_type: MeasurementSummaryHashType,
    ) -> CertStoreResult<()> {
        let slot = self
            .peer_slots
            .get_mut(slot_id as usize)
            .ok_or(CertStoreError::InvalidSlotId(slot_id))?
            .as_mut()
            .ok_or(CertStoreError::PlatformError)?;
        slot.requested_msh_type = Some(msh_type);

        Ok(())
    }
}
