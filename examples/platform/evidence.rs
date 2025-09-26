// Licensed under the Apache-2.0 license

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