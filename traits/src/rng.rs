// Licensed under the Apache-2.0 license

//! Random-number abstraction used by the SPDM-Lite stack.
//!
//! Used wherever the protocol needs fresh unpredictable bytes — chiefly the
//! 32-byte nonces in CHALLENGE and GET_MEASUREMENTS. Implementations must
//! source from a cryptographically secure RNG (hardware TRNG or a seeded
//! CSPRNG); a predictable nonce defeats replay protection.

use super::*;

/// Cryptographically secure random-byte source.
pub trait SpdmPalRng {
    /// Fills all of `out` with random bytes.
    ///
    /// Must either fill the whole slice or return an error; callers never
    /// use a partially filled buffer. Like [`SpdmPalHash`], takes the in-flight
    /// `io` handle so backends needing per-exchange scratch can scope it.
    fn fill_random(&self, io: &impl SpdmPalIo, out: &mut [u8]) -> PalResult<()>;
}
