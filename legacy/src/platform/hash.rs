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

pub type SpdmHashResult<T> = Result<T, SpdmHashError>;

pub trait SpdmHash {
    fn hash(
        &mut self,
        hash_algo: SpdmHashAlgoType,
        data: &[u8],
        hash: &mut [u8],
    ) -> SpdmHashResult<()>;
    fn init(&mut self, hash_algo: SpdmHashAlgoType, data: Option<&[u8]>) -> SpdmHashResult<()>;
    fn update(&mut self, data: &[u8]) -> SpdmHashResult<()>;
    fn finalize(&mut self, hash: &mut [u8]) -> SpdmHashResult<()>;

    fn reset(&mut self);
    fn algo(&self) -> SpdmHashAlgoType;
}

#[derive(Debug, PartialEq)]
pub enum SpdmHashError {
    PlatformError,
    BufferTooSmall,
    InvalidAlgorithm,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SpdmHashAlgoType {
    SHA384,
    SHA512,
}

impl From<SpdmHashAlgoType> for u32 {
    fn from(algo: SpdmHashAlgoType) -> Self {
        match algo {
            SpdmHashAlgoType::SHA384 => 2u32,
            SpdmHashAlgoType::SHA512 => 4u32,
        }
    }
}

impl SpdmHashAlgoType {
    pub fn hash_size(&self) -> usize {
        match self {
            SpdmHashAlgoType::SHA384 => 48,
            SpdmHashAlgoType::SHA512 => 64,
        }
    }
}
