// Licensed under the Apache-2.0 license

//! Host running-hash backend: SHA-384 via `sha2`.
//!
//! `State` is a live `sha2::Sha384`. `hash_clone` uses the hasher's own `Clone`
//! to fork a running transcript (the stack forks VCA/M1/L1 per DSP0274).

use sha2::{Digest, Sha384};

use spdm_error::{codes::INVARIANT, PalResult};
use spdm_traits::{SpdmPalHash, SpdmPalHashAlgo, SpdmPalIo};

use super::HostPal;

impl SpdmPalHash for HostPal {
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
        let digest = state.clone().finalize();
        out[..48].copy_from_slice(&digest);
        Ok(())
    }
}
