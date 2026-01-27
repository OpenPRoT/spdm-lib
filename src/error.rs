// Licensed under the Apache-2.0 license

// use crate::cert_mgr::DeviceCertsMgrError;
use crate::cert_store::CertStoreError;
use crate::chunk_ctx::ChunkError;
use crate::codec::CodecError;
use crate::commands::error_rsp::ErrorCode;
use crate::measurements::common::MeasurementsError;
use crate::platform::evidence::SpdmEvidenceError;
use crate::platform::hash::SpdmHashError;
use crate::platform::rng::SpdmRngError;
use crate::platform::transport::TransportError;
use crate::protocol::SignCtxError;
use crate::transcript::TranscriptError;

#[derive(Debug)]
pub enum SpdmError {
    UnsupportedVersion,
    InvalidParam,
    Codec(CodecError),
    Transport(TransportError),
    Command(CommandError),
    BufferTooSmall,
    UnsupportedRequest,
    CertStore(CertStoreError),
}

pub type SpdmResult<T> = Result<T, SpdmError>;

pub type CommandResult<T> = Result<T, (bool, CommandError)>;

#[non_exhaustive]
#[derive(Debug, PartialEq)]
pub enum PlatformError {
    HashError(SpdmHashError),
    RngError(SpdmRngError),
    EvidenceError(SpdmEvidenceError),
}

#[non_exhaustive]
#[derive(Debug, PartialEq)]
pub enum CommandError {
    BufferTooSmall,
    Codec(CodecError),
    ErrorCode(ErrorCode),
    UnsupportedRequest,
    UnsupportedResponse,
    SignCtx(SignCtxError),
    InvalidChunkContext,
    Chunk(ChunkError),
    CertStore(CertStoreError),
    Platform(PlatformError),
    Transcript(TranscriptError),
    Measurement(MeasurementsError),
    InvalidResponse,
}
