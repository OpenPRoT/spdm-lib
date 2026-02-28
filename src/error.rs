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
    /// An invalid state was encountered (this is likely a bug)
    InvalidState,
    /// This is a Bug
    ///
    /// Used in spots which should be infallible.
    /// This can either be a bug in this crate,
    /// in a dependency, or a uncaught platform misbehavior.
    InternalError,
}
