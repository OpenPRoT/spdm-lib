extern crate alloc;
use alloc::boxed::Box;
use async_trait::async_trait;

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

#[async_trait]
pub trait SpdmEvidence {
    async fn pcr_quote(&self, buffer: &mut [u8], with_pqc_sig: bool) -> SpdmEvidenceResult<usize>;
    async fn pcr_quote_size(&self, with_pqc_sig: bool) -> SpdmEvidenceResult<usize>;
}
