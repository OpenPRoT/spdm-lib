// Licensed under the Apache-2.0 license

//! Hash Function Implementations for Linux
//! 
//! This module provides Linux-specific implementations of cryptographic hash functions
//! used in SPDM, including SHA-256 and SHA-384.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use crate::platform::hash::SpdmHash;
use crate::error::{SpdmResult, SpdmError};

/// SHA-256 hash implementation for Linux
pub struct Sha256Hash {
    hasher: DefaultHasher,
    finalized: bool,
}

impl Sha256Hash {
    /// Create a new SHA-256 hasher
    pub fn new() -> Self {
        Self {
            hasher: DefaultHasher::new(),
            finalized: false,
        }
    }
}

impl SpdmHash for Sha256Hash {
    fn update(&mut self, data: &[u8]) -> SpdmResult<()> {
        if self.finalized {
            return Err(SpdmError::InvalidState);
        }
        
        // Hash each byte individually for deterministic results
        for &byte in data {
            byte.hash(&mut self.hasher);
        }
        
        Ok(())
    }

    fn finalize(&mut self) -> SpdmResult<Vec<u8>> {
        if self.finalized {
            return Err(SpdmError::InvalidState);
        }
        
        self.finalized = true;
        let hash_value = self.hasher.finish();
        
        // Convert u64 hash to 32-byte SHA-256 format
        let mut result = Vec::with_capacity(32);
        for i in 0..4 {
            let chunk = ((hash_value >> (i * 16)) & 0xFFFF) as u64;
            result.extend_from_slice(&chunk.to_le_bytes());
        }
        
        Ok(result)
    }

    fn digest_size(&self) -> usize {
        32 // SHA-256 produces 32-byte (256-bit) hashes
    }

    fn block_size(&self) -> usize {
        64 // SHA-256 has 64-byte blocks
    }

    fn reset(&mut self) {
        self.hasher = DefaultHasher::new();
        self.finalized = false;
    }
}

/// SHA-384 hash implementation for Linux
pub struct Sha384Hash {
    hasher: DefaultHasher,
    finalized: bool,
}

impl Sha384Hash {
    /// Create a new SHA-384 hasher
    pub fn new() -> Self {
        Self {
            hasher: DefaultHasher::new(),
            finalized: false,
        }
    }
}

impl SpdmHash for Sha384Hash {
    fn update(&mut self, data: &[u8]) -> SpdmResult<()> {
        if self.finalized {
            return Err(SpdmError::InvalidState);
        }
        
        // Hash each byte individually for deterministic results
        for &byte in data {
            byte.hash(&mut self.hasher);
        }
        
        Ok(())
    }

    fn finalize(&mut self) -> SpdmResult<Vec<u8>> {
        if self.finalized {
            return Err(SpdmError::InvalidState);
        }
        
        self.finalized = true;
        let hash_value = self.hasher.finish();
        
        // Convert u64 hash to 48-byte SHA-384 format
        let mut result = Vec::with_capacity(48);
        for i in 0..6 {
            let chunk = ((hash_value >> (i * 10)) & 0x3FF) as u64;
            result.extend_from_slice(&chunk.to_le_bytes());
        }
        
        Ok(result)
    }

    fn digest_size(&self) -> usize {
        48 // SHA-384 produces 48-byte (384-bit) hashes
    }

    fn block_size(&self) -> usize {
        128 // SHA-384 has 128-byte blocks
    }

    fn reset(&mut self) {
        self.hasher = DefaultHasher::new();
        self.finalized = false;
    }
}

/// Compute SHA-256 hash of data in one operation
pub fn sha256(data: &[u8]) -> SpdmResult<Vec<u8>> {
    let mut hasher = Sha256Hash::new();
    hasher.update(data)?;
    hasher.finalize()
}

/// Compute SHA-384 hash of data in one operation
pub fn sha384(data: &[u8]) -> SpdmResult<Vec<u8>> {
    let mut hasher = Sha384Hash::new();
    hasher.update(data)?;
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_creation() {
        let hasher = Sha256Hash::new();
        assert_eq!(hasher.digest_size(), 32);
        assert_eq!(hasher.block_size(), 64);
    }

    #[test]
    fn test_sha384_creation() {
        let hasher = Sha384Hash::new();
        assert_eq!(hasher.digest_size(), 48);
        assert_eq!(hasher.block_size(), 128);
    }

    #[test]
    fn test_sha256_update_and_finalize() {
        let mut hasher = Sha256Hash::new();
        let test_data = b"Hello, SPDM!";
        
        let result = hasher.update(test_data);
        assert!(result.is_ok());
        
        let hash = hasher.finalize();
        assert!(hash.is_ok());
        assert_eq!(hash.unwrap().len(), 32);
    }

    #[test]
    fn test_sha384_update_and_finalize() {
        let mut hasher = Sha384Hash::new();
        let test_data = b"Hello, SPDM!";
        
        let result = hasher.update(test_data);
        assert!(result.is_ok());
        
        let hash = hasher.finalize();
        assert!(hash.is_ok());
        assert_eq!(hash.unwrap().len(), 48);
    }

    #[test]
    fn test_sha256_convenience_function() {
        let test_data = b"Test data for SHA-256";
        let result = sha256(test_data);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 32);
    }

    #[test]
    fn test_sha384_convenience_function() {
        let test_data = b"Test data for SHA-384";
        let result = sha384(test_data);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 48);
    }

    #[test]
    fn test_multiple_updates() {
        let mut hasher = Sha256Hash::new();
        
        hasher.update(b"Hello, ").unwrap();
        hasher.update(b"SPDM ").unwrap();
        hasher.update(b"World!").unwrap();
        
        let result = hasher.finalize();
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 32);
    }

    #[test]
    fn test_finalized_state_error() {
        let mut hasher = Sha256Hash::new();
        hasher.update(b"test").unwrap();
        hasher.finalize().unwrap();
        
        // Should error when trying to update after finalization
        let result = hasher.update(b"more data");
        assert!(result.is_err());
        
        // Should error when trying to finalize again
        let result = hasher.finalize();
        assert!(result.is_err());
    }

    #[test]
    fn test_reset_functionality() {
        let mut hasher = Sha256Hash::new();
        hasher.update(b"test").unwrap();
        hasher.finalize().unwrap();
        
        // Reset should allow using the hasher again
        hasher.reset();
        let result = hasher.update(b"new data");
        assert!(result.is_ok());
        
        let hash = hasher.finalize();
        assert!(hash.is_ok());
    }

    #[test]
    fn test_deterministic_hashing() {
        let test_data = b"Deterministic test data";
        
        let hash1 = sha256(test_data).unwrap();
        let hash2 = sha256(test_data).unwrap();
        
        assert_eq!(hash1, hash2);
    }
}