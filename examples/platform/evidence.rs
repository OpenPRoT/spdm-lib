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

//! Evidence Platform Implementation
//!
//! Provides device measurements and evidence functionality

use spdm_lib::platform::evidence::{SpdmEvidence, SpdmEvidenceResult};

/// Demo evidence provider with static measurements
pub struct DemoEvidence;

impl DemoEvidence {
    pub fn new() -> Self {
        Self
    }
}

impl SpdmEvidence for DemoEvidence {
    fn pcr_quote(&self, buffer: &mut [u8], _with_pqc_sig: bool) -> SpdmEvidenceResult<usize> {
        // Provide a simple demo PCR quote
        let demo_quote = b"DEMO_PCR_QUOTE_DATA_FOR_MEASUREMENTS";
        let copy_len = demo_quote.len().min(buffer.len());
        buffer[..copy_len].copy_from_slice(&demo_quote[..copy_len]);
        Ok(copy_len)
    }

    fn pcr_quote_size(&self, _with_pqc_sig: bool) -> SpdmEvidenceResult<usize> {
        Ok(b"DEMO_PCR_QUOTE_DATA_FOR_MEASUREMENTS".len())
    }
}
