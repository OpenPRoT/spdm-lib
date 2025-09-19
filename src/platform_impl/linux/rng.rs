// Licensed under the Apache-2.0 license

//! Linux Random Number Generator Implementation
//! 
//! This module provides a Linux-specific implementation of the SpdmRng trait
//! using /dev/urandom for cryptographically secure random number generation.

use std::fs::File;
use std::io::Read;
use crate::platform::rng::SpdmRng;
use crate::error::{SpdmResult, SpdmError};

/// Linux-specific random number generator using /dev/urandom
pub struct LinuxRng {
    urandom: File,
}

impl LinuxRng {
    /// Create a new Linux RNG instance
    pub fn new() -> SpdmResult<Self> {
        let urandom = File::open("/dev/urandom")
            .map_err(|e| SpdmError::Platform(format!("Failed to open /dev/urandom: {}", e)))?;
        
        Ok(Self { urandom })
    }
}

impl SpdmRng for LinuxRng {
    fn fill_random_bytes(&mut self, buffer: &mut [u8]) -> SpdmResult<()> {
        self.urandom.read_exact(buffer)
            .map_err(|e| SpdmError::Platform(format!("Failed to read random bytes: {}", e)))?;
        Ok(())
    }

    fn generate_u64(&mut self) -> SpdmResult<u64> {
        let mut bytes = [0u8; 8];
        self.fill_random_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn generate_u32(&mut self) -> SpdmResult<u32> {
        let mut bytes = [0u8; 4];
        self.fill_random_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linux_rng_creation() {
        let result = LinuxRng::new();
        assert!(result.is_ok());
    }

    #[test]
    fn test_fill_random_bytes() {
        let mut rng = LinuxRng::new().unwrap();
        let mut buffer = [0u8; 32];
        let result = rng.fill_random_bytes(&mut buffer);
        assert!(result.is_ok());
        
        // Verify that the buffer is not all zeros (extremely unlikely with real random data)
        assert_ne!(buffer, [0u8; 32]);
    }

    #[test]
    fn test_generate_u64() {
        let mut rng = LinuxRng::new().unwrap();
        let result = rng.generate_u64();
        assert!(result.is_ok());
        
        // Generate multiple values to ensure they're different
        let val1 = rng.generate_u64().unwrap();
        let val2 = rng.generate_u64().unwrap();
        assert_ne!(val1, val2); // Extremely unlikely to be equal
    }

    #[test]
    fn test_generate_u32() {
        let mut rng = LinuxRng::new().unwrap();
        let result = rng.generate_u32();
        assert!(result.is_ok());
        
        // Generate multiple values to ensure they're different
        let val1 = rng.generate_u32().unwrap();
        let val2 = rng.generate_u32().unwrap();
        assert_ne!(val1, val2); // Extremely unlikely to be equal
    }
}