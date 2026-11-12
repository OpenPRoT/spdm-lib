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

pub const PCR_QUOTE_BUFFER_SIZE: usize = 0x1984;

pub type SpdmEvidenceResult<T> = Result<T, SpdmEvidenceError>;

#[derive(Debug, PartialEq)]
pub enum SpdmEvidenceError {
    InvalidEvidence,
    UnsupportedEvidenceType,
    InvalidEvidenceFormat,
    MissingEvidenceData,
    EvidenceVerificationFailed,
}

pub trait SpdmEvidence {
    fn pcr_quote(&self, buffer: &mut [u8], with_pqc_sig: bool) -> SpdmEvidenceResult<usize>;
    fn pcr_quote_size(&self, with_pqc_sig: bool) -> SpdmEvidenceResult<usize>;
}
