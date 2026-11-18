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

//! [`SpdmPalHash`] + [`ApiAlloc`] implementations on [`PlatformSpdmPal`].
//!
//! Hash state buffers are allocated from the per-task bitmap pool via
//! `alloc_bytes(SHA_CONTEXT_SIZE)`, making them deterministic and
//! independent of the global heap. Each `HashState<BitmapBytes<'static>>`
//! is 8 bytes on 32-bit targets.

use super::measurements::MeasurementProvider;
use super::*;
use spdm_traits::{SpdmPalHash, SpdmPalHashAlgo, SpdmPalIo};
use spdm_crypto::{
    sha_finish, sha_init, sha_update, ApiAlloc, HashAlgo, HashState, SHA_CONTEXT_SIZE,
};

impl<M: MeasurementProvider> ApiAlloc for PlatformSpdmPal<M> {
    type Buf<'a>
        = BitmapBytes<'a>
    where
        Self: 'a;

    #[inline]
    fn alloc(&self, len: usize) -> PalResult<Self::Buf<'_>> {
        self.allocator.alloc_bytes(len)
    }
}

impl ApiAlloc for BitmapAllocator {
    type Buf<'a>
        = BitmapBytes<'a>
    where
        Self: 'a;

    #[inline]
    fn alloc(&self, len: usize) -> PalResult<Self::Buf<'_>> {
        self.alloc_bytes(len)
    }
}

impl<M: MeasurementProvider> SpdmPalHash for PlatformSpdmPal<M> {
    type State = HashState<BitmapBytes<'static>>;

    #[inline]
    async fn hash_init(
        &self,
        _io: &impl SpdmPalIo,
        algo: SpdmPalHashAlgo,
        seed: &[u8],
    ) -> PalResult<Self::State> {
        let buf = self.allocator.alloc_bytes(SHA_CONTEXT_SIZE)?;
        sha_init(self.allocator, buf, to_api_algo(algo), seed).await
    }

    #[inline]
    async fn hash_update(
        &self,
        _io: &impl SpdmPalIo,
        state: &mut Self::State,
        data: &[u8],
    ) -> PalResult<()> {
        sha_update(self.allocator, state, data).await
    }

    #[inline]
    fn hash_clone(&self, _io: &impl SpdmPalIo, state: &Self::State) -> PalResult<Self::State> {
        let buf = self.allocator.alloc_bytes(SHA_CONTEXT_SIZE)?;
        Ok(state.clone_into(buf))
    }

    #[inline]
    async fn hash_finish(
        &self,
        _io: &impl SpdmPalIo,
        state: &mut Self::State,
        out: &mut [u8],
    ) -> PalResult<()> {
        sha_finish(self.allocator, state, out).await
    }
}

/// Map the SPDM-protocol algorithm selector onto the
/// Caliptra-mailbox algorithm code.
#[inline]
fn to_api_algo(algo: SpdmPalHashAlgo) -> HashAlgo {
    match algo {
        SpdmPalHashAlgo::Sha384 => HashAlgo::Sha384,
    }
}
