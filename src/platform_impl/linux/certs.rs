// Licensed under the Apache-2.0 license

//! Linux Certificate Store Implementation
//! 
//! This module provides a Linux-specific implementation of certificate management
//! for SPDM, including loading certificates and private keys from PEM files.

use std::fs;
use std::path::Path;
use crate::cert_store::{SpdmCertStore, CertificateChain};
use crate::error::{SpdmResult, SpdmError};

/// Linux-specific certificate store implementation
pub struct LinuxCertStore {
    cert_chain: CertificateChain,
    private_key: Vec<u8>,
}

impl LinuxCertStore {
    /// Create a new Linux certificate store
    pub fn new(cert_chain_path: &str, private_key_path: &str) -> SpdmResult<Self> {
        let cert_chain = Self::load_certificate_chain(cert_chain_path)?;
        let private_key = Self::load_private_key(private_key_path)?;

        Ok(Self {
            cert_chain,
            private_key,
        })
    }

    /// Load certificate chain from PEM file
    fn load_certificate_chain(path: &str) -> SpdmResult<CertificateChain> {
        if !Path::new(path).exists() {
            // Create a default certificate for testing
            let default_cert = Self::generate_default_certificate()?;
            fs::write(path, &default_cert)
                .map_err(|e| SpdmError::Platform(format!("Failed to write default certificate to {}: {}", path, e)))?;
            
            println!("Created default certificate file at: {}", path);
        }

        let pem_data = fs::read_to_string(path)
            .map_err(|e| SpdmError::Platform(format!("Failed to read certificate from {}: {}", path, e)))?;

        // Parse PEM data (simplified - in production use a proper PEM parser)
        let cert_data = Self::parse_pem_data(&pem_data)?;
        
        Ok(CertificateChain {
            certificates: vec![cert_data],
        })
    }

    /// Load private key from PEM file
    fn load_private_key(path: &str) -> SpdmResult<Vec<u8>> {
        if !Path::new(path).exists() {
            // Create a default private key for testing
            let default_key = Self::generate_default_private_key()?;
            fs::write(path, &default_key)
                .map_err(|e| SpdmError::Platform(format!("Failed to write default private key to {}: {}", path, e)))?;
            
            println!("Created default private key file at: {}", path);
        }

        let pem_data = fs::read_to_string(path)
            .map_err(|e| SpdmError::Platform(format!("Failed to read private key from {}: {}", path, e)))?;

        // Parse PEM data (simplified - in production use a proper PEM parser)
        let key_data = Self::parse_pem_data(&pem_data)?;
        
        Ok(key_data)
    }

    /// Generate a default certificate for testing purposes
    fn generate_default_certificate() -> SpdmResult<String> {
        // This is a simplified mock certificate for testing
        // In production, use proper certificate generation with OpenSSL or similar
        Ok(format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            base64::encode(&Self::create_mock_cert_der()?)
        ))
    }

    /// Generate a default private key for testing purposes
    fn generate_default_private_key() -> SpdmResult<String> {
        // This is a simplified mock private key for testing
        // In production, use proper key generation with OpenSSL or similar
        Ok(format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            base64::encode(&Self::create_mock_key_der()?)
        ))
    }

    /// Create a mock DER-encoded certificate
    fn create_mock_cert_der() -> SpdmResult<Vec<u8>> {
        // This creates a very basic mock certificate structure
        // In production, use proper ASN.1/DER encoding
        let mut cert = Vec::new();
        
        // Mock certificate data (this is not a valid certificate)
        cert.extend_from_slice(b"MOCK_CERTIFICATE_DATA");
        cert.extend_from_slice(&[0u8; 32]); // Mock public key
        cert.extend_from_slice(b"SPDM_DEVICE_CERT");
        
        // Pad to reasonable certificate size
        while cert.len() < 512 {
            cert.push(0);
        }
        
        Ok(cert)
    }

    /// Create a mock DER-encoded private key
    fn create_mock_key_der() -> SpdmResult<Vec<u8>> {
        // This creates a very basic mock private key structure
        // In production, use proper ASN.1/DER encoding
        let mut key = Vec::new();
        
        // Mock private key data (this is not a valid private key)
        key.extend_from_slice(b"MOCK_PRIVATE_KEY_DATA");
        key.extend_from_slice(&[0u8; 48]); // Mock P-384 private key
        
        // Pad to reasonable key size
        while key.len() < 256 {
            key.push(0);
        }
        
        Ok(key)
    }

    /// Parse PEM data (simplified implementation)
    fn parse_pem_data(pem_data: &str) -> SpdmResult<Vec<u8>> {
        // Find the base64 data between BEGIN and END markers
        let lines: Vec<&str> = pem_data.lines().collect();
        let mut base64_lines = Vec::new();
        let mut in_cert = false;

        for line in lines {
            let trimmed = line.trim();
            if trimmed.starts_with("-----BEGIN") {
                in_cert = true;
                continue;
            }
            if trimmed.starts_with("-----END") {
                break;
            }
            if in_cert && !trimmed.is_empty() {
                base64_lines.push(trimmed);
            }
        }

        if base64_lines.is_empty() {
            return Err(SpdmError::Platform("No valid PEM data found".to_string()));
        }

        let base64_data = base64_lines.join("");
        base64::decode(&base64_data)
            .map_err(|e| SpdmError::Platform(format!("Failed to decode base64 data: {}", e)))
    }
}

impl SpdmCertStore for LinuxCertStore {
    fn get_certificate_chain(&self, slot_id: u8) -> SpdmResult<&CertificateChain> {
        // For simplicity, we only support slot 0
        if slot_id != 0 {
            return Err(SpdmError::InvalidParam);
        }
        Ok(&self.cert_chain)
    }

    fn get_certificate_count(&self) -> u8 {
        self.cert_chain.certificates.len() as u8
    }

    fn sign_data(&self, data: &[u8]) -> SpdmResult<Vec<u8>> {
        // Mock signature implementation
        // In production, use proper ECDSA signing with the private key
        let mut signature = Vec::new();
        signature.extend_from_slice(b"MOCK_SIGNATURE_");
        signature.extend_from_slice(&data[..std::cmp::min(data.len(), 32)]);
        
        // Pad to ECDSA P-384 signature size (96 bytes)
        while signature.len() < 96 {
            signature.push(0);
        }
        
        Ok(signature)
    }

    fn supports_slot(&self, slot_id: u8) -> bool {
        slot_id == 0
    }
}

// Add base64 dependency to Cargo.toml
#[cfg(not(feature = "std"))]
mod base64 {
    pub fn encode(_data: &[u8]) -> String {
        // Minimal base64 encoding for no_std environments
        "MOCK_BASE64_DATA".to_string()
    }
    
    pub fn decode(_data: &str) -> Result<Vec<u8>, &'static str> {
        // Return mock data for no_std environments
        Ok(vec![0u8; 64])
    }
}

#[cfg(feature = "std")]
use base64;

#[cfg(not(feature = "std"))]
use self::base64;

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;

    #[test]
    fn test_generate_default_certificate() {
        let result = LinuxCertStore::generate_default_certificate();
        assert!(result.is_ok());
        let cert = result.unwrap();
        assert!(cert.contains("-----BEGIN CERTIFICATE-----"));
        assert!(cert.contains("-----END CERTIFICATE-----"));
    }

    #[test]
    fn test_generate_default_private_key() {
        let result = LinuxCertStore::generate_default_private_key();
        assert!(result.is_ok());
        let key = result.unwrap();
        assert!(key.contains("-----BEGIN PRIVATE KEY-----"));
        assert!(key.contains("-----END PRIVATE KEY-----"));
    }

    #[test]
    fn test_parse_pem_data() {
        let pem_data = "-----BEGIN CERTIFICATE-----\nVGVzdERhdGE=\n-----END CERTIFICATE-----\n";
        let result = LinuxCertStore::parse_pem_data(pem_data);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cert_store_creation() {
        let cert_file = NamedTempFile::new().unwrap();
        let key_file = NamedTempFile::new().unwrap();
        
        let cert_path = cert_file.path().to_str().unwrap();
        let key_path = key_file.path().to_str().unwrap();
        
        let result = LinuxCertStore::new(cert_path, key_path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_certificate_chain() {
        let cert_file = NamedTempFile::new().unwrap();
        let key_file = NamedTempFile::new().unwrap();
        
        let cert_path = cert_file.path().to_str().unwrap();
        let key_path = key_file.path().to_str().unwrap();
        
        let cert_store = LinuxCertStore::new(cert_path, key_path).unwrap();
        let result = cert_store.get_certificate_chain(0);
        assert!(result.is_ok());
        
        let invalid_result = cert_store.get_certificate_chain(1);
        assert!(invalid_result.is_err());
    }

    #[test]
    fn test_sign_data() {
        let cert_file = NamedTempFile::new().unwrap();
        let key_file = NamedTempFile::new().unwrap();
        
        let cert_path = cert_file.path().to_str().unwrap();
        let key_path = key_file.path().to_str().unwrap();
        
        let cert_store = LinuxCertStore::new(cert_path, key_path).unwrap();
        let test_data = b"test data for signing";
        let result = cert_store.sign_data(test_data);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 96); // ECDSA P-384 signature size
    }

    #[test]
    fn test_supports_slot() {
        let cert_file = NamedTempFile::new().unwrap();
        let key_file = NamedTempFile::new().unwrap();
        
        let cert_path = cert_file.path().to_str().unwrap();
        let key_path = key_file.path().to_str().unwrap();
        
        let cert_store = LinuxCertStore::new(cert_path, key_path).unwrap();
        assert!(cert_store.supports_slot(0));
        assert!(!cert_store.supports_slot(1));
    }
}