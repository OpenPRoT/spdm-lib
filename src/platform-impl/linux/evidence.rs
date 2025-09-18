// Licensed under the Apache-2.0 license

//! Linux mock evidence provider (feature: `linux-evidence`).
//! Returns deterministic placeholder PCR quote data (<=48 bytes).

#![cfg(feature = "linux-evidence")]

use crate::platform::evidence::{SpdmEvidence, SpdmEvidenceResult, SpdmEvidenceError};

const MOCK_QUOTE: &[u8] = b"LINUX_PCR_QUOTE_v1"; // 17 bytes < 48

pub struct SpdmLinuxEvidence;

impl SpdmLinuxEvidence {
    pub fn new() -> Self { Self }
}

impl SpdmEvidence for SpdmLinuxEvidence {
    fn pcr_quote(&self, buffer: &mut [u8], _with_pqc_sig: bool) -> SpdmEvidenceResult<usize> {
        if buffer.is_empty() { return Err(SpdmEvidenceError::MissingEvidenceData); }
        let len = MOCK_QUOTE.len().min(buffer.len()).min(48);
        buffer[..len].copy_from_slice(&MOCK_QUOTE[..len]);
        Ok(len)
    }

    fn pcr_quote_size(&self, _with_pqc_sig: bool) -> SpdmEvidenceResult<usize> {
        Ok(MOCK_QUOTE.len().min(48))
    }
}
