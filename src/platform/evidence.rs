extern crate alloc;

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
