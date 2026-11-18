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

//! Shared test doubles for requester unit tests.

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use spdm_codec::SpdmVersion;
use spdm_errors::{codes::INVARIANT, PalResult};
use spdm_traits::{SpdmPalHash, SpdmPalIo, SpdmPalRng};

use super::{PeerVerifier, RequesterConfig, RequesterTransport, SpdmRequester};

/// Replays canned responses and records what the requester sent.
pub(crate) struct Script {
    pub(crate) replies: VecDeque<Vec<u8>>,
    pub(crate) sent: Vec<Vec<u8>>,
}

impl RequesterTransport for Script {
    fn send(&mut self, msg: &[u8]) -> PalResult<()> {
        self.sent.push(msg.to_vec());
        Ok(())
    }
    fn recv(&mut self, buf: &mut [u8]) -> PalResult<usize> {
        let r = self.replies.pop_front().ok_or(INVARIANT)?;
        buf.get_mut(..r.len()).ok_or(INVARIANT)?.copy_from_slice(&r);
        Ok(r.len())
    }
}

// Inert crypto stubs: these tests never inspect the transcript.
pub(crate) struct NoHash;
impl SpdmPalHash for NoHash {
    type State = ();
    fn hash_init(
        &self,
        _: &impl SpdmPalIo,
        _: spdm_traits::SpdmPalHashAlgo,
        _: &[u8],
    ) -> PalResult<()> {
        Ok(())
    }
    fn hash_update(&self, _: &impl SpdmPalIo, _: &mut (), _: &[u8]) -> PalResult<()> {
        Ok(())
    }
    fn hash_clone(&self, _: &impl SpdmPalIo, _: &()) -> PalResult<()> {
        Ok(())
    }
    fn hash_finish(&self, _: &impl SpdmPalIo, _: &mut (), _: &mut [u8]) -> PalResult<()> {
        Ok(())
    }
}
pub(crate) struct NoRng;
impl SpdmPalRng for NoRng {
    fn fill_random(&self, _: &impl SpdmPalIo, _: &mut [u8]) -> PalResult<()> {
        Ok(())
    }
}
pub(crate) struct NoVerify;
impl PeerVerifier for NoVerify {
    type PubKey = ();
    fn validate_chain(&self, _: &[u8]) -> PalResult<()> {
        Ok(())
    }
    fn verify_p384(&self, _: &(), _: &[u8; 48], _: &[u8]) -> PalResult<()> {
        Ok(())
    }
    fn verify_mldsa87(&self, _: &(), _: &[u8], _: &[u8], _: &[u8]) -> PalResult<()> {
        Ok(())
    }
}

/// A requester at `version` that replays `replies` and records what it sends.
pub(crate) fn scripted_requester(
    replies: Vec<Vec<u8>>,
    version: SpdmVersion,
) -> SpdmRequester<Script, NoHash, NoRng, NoVerify> {
    let transport = Script {
        replies: replies.into(),
        sent: Vec::new(),
    };
    let mut r = SpdmRequester::with_config(
        transport,
        NoHash,
        NoRng,
        NoVerify,
        RequesterConfig::default(),
    );
    r.version = version;
    r
}
