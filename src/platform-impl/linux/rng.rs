// Licensed under the Apache-2.0 license

//! Linux RNG implementation using the `rand` crate (feature: `rand-rng`).

#![cfg(feature = "rand-rng")]

use rand::rngs::OsRng;
use rand::RngCore;

use crate::platform::rng::{SpdmRng, SpdmRngResult, SpdmRngError};

pub struct SpdmLinuxRng;

impl SpdmLinuxRng {
    pub fn new() -> Self { Self }
}

impl SpdmRng for SpdmLinuxRng {
    fn get_random_bytes(&mut self, buf: &mut [u8]) -> SpdmRngResult<()> {
        OsRng.fill_bytes(buf);
        Ok(())
    }

    fn generate_random_number(&mut self, random_number: &mut [u8]) -> SpdmRngResult<()> {
        if random_number.is_empty() { return Err(SpdmRngError::InvalidSize); }
        OsRng.fill_bytes(random_number);
        Ok(())
    }
}
