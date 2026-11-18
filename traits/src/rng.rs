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
