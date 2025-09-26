// Licensed under the Apache-2.0 license

//! Cryptographic Platform Implementation
//! 
//! Provides SHA-384 hash and system RNG implementations

#[cfg(feature = "crypto")]
use sha2::{Sha384, Digest};

use spdm_lib::platform::hash::{SpdmHash, SpdmHashAlgoType, SpdmHashResult, SpdmHashError};
use spdm_lib::platform::rng::{SpdmRng, SpdmRngResult};

/// SHA-384 hash implementation using proper cryptography
pub struct Sha384Hash {
    current_algo: SpdmHashAlgoType,
    #[cfg(feature = "crypto")]
    hasher: Option<Sha384>,
}

impl Sha384Hash {
    pub fn new() -> Self {
        Self {
            current_algo: SpdmHashAlgoType::SHA384,
            #[cfg(feature = "crypto")]
            hasher: None,
        }
    }
}

impl SpdmHash for Sha384Hash {
    fn hash(&mut self, hash_algo: SpdmHashAlgoType, data: &[u8], hash: &mut [u8]) -> SpdmHashResult<()> {
        if hash_algo != SpdmHashAlgoType::SHA384 {
            return Err(SpdmHashError::InvalidAlgorithm);
        }
        
        if hash.len() < 48 {
            return Err(SpdmHashError::BufferTooSmall);
        }
        
        #[cfg(feature = "crypto")]
        {
            let mut hasher = Sha384::new();
            hasher.update(data);
            let result = hasher.finalize();
            hash[..48].copy_from_slice(&result[..]);
            Ok(())
        }
        
        #[cfg(not(feature = "crypto"))]
        {
            // Fallback for demo purposes when crypto feature is not enabled
            for (i, &byte) in data.iter().enumerate() {
                hash[i % 48] ^= byte;
            }
            Ok(())
        }
    }

    fn init(&mut self, hash_algo: SpdmHashAlgoType, data: Option<&[u8]>) -> SpdmHashResult<()> {
        if hash_algo != SpdmHashAlgoType::SHA384 {
            return Err(SpdmHashError::InvalidAlgorithm);
        }
        self.current_algo = hash_algo;
        
        #[cfg(feature = "crypto")]
        {
            let mut hasher = Sha384::new();
            if let Some(initial_data) = data {
                hasher.update(initial_data);
            }
            self.hasher = Some(hasher);
        }
        
        Ok(())
    }

    fn update(&mut self, data: &[u8]) -> SpdmHashResult<()> {
        #[cfg(feature = "crypto")]
        {
            if let Some(ref mut hasher) = self.hasher {
                hasher.update(data);
            } else {
                return Err(SpdmHashError::PlatformError);
            }
        }
        
        Ok(())
    }

    fn finalize(&mut self, hash: &mut [u8]) -> SpdmHashResult<()> {
        if hash.len() < 48 {
            return Err(SpdmHashError::BufferTooSmall);
        }
        
        #[cfg(feature = "crypto")]
        {
            if let Some(hasher) = self.hasher.take() {
                let result = hasher.finalize();
                hash[..48].copy_from_slice(&result[..]);
            } else {
                return Err(SpdmHashError::PlatformError);
            }
        }
        
        #[cfg(not(feature = "crypto"))]
        {
            // Fallback for demo
            hash[..48].fill(0x42);
        }
        
        Ok(())
    }

    fn reset(&mut self) {
        #[cfg(feature = "crypto")]
        {
            if self.current_algo == SpdmHashAlgoType::SHA384 {
                self.hasher = Some(Sha384::new());
            }
        }
    }

    fn algo(&self) -> SpdmHashAlgoType {
        self.current_algo
    }
}

/// System RNG implementation
pub struct SystemRng;

impl SystemRng {
    pub fn new() -> Self {
        Self
    }
}

impl SpdmRng for SystemRng {
    fn get_random_bytes(&mut self, buf: &mut [u8]) -> SpdmRngResult<()> {
        // For demo, fill with pseudo-random data
        // In real implementation, use proper RNG
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(137).wrapping_add(42);
        }
        Ok(())
    }

    fn generate_random_number(&mut self, random_number: &mut [u8]) -> SpdmRngResult<()> {
        // For demo, generate a simple pattern
        for (i, byte) in random_number.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(193).wrapping_add(67);
        }
        Ok(())
    }
}