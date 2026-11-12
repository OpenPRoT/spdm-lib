// Licensed under the Apache-2.0 license

//! Host random-number backend: the OS-seeded thread RNG from `rand`.

use rand::RngCore;

use spdm_errors::PalResult;
use spdm_traits::{SpdmPalIo, SpdmPalRng};

use super::HostPal;

impl SpdmPalRng for HostPal {
    fn fill_random(&self, _io: &impl SpdmPalIo, out: &mut [u8]) -> PalResult<()> {
        rand::thread_rng().fill_bytes(out);
        Ok(())
    }
}
