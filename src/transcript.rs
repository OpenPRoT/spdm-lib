// Licensed under the Apache-2.0 license

use crate::protocol::{SpdmVersion, SHA384_HASH_SIZE};
use crate::platform::hash::{SpdmHash, SpdmHashError};

#[derive(Debug, PartialEq)]
pub enum TranscriptError {
    BufferOverflow,
    InvalidState,
    Hash(SpdmHashError),
}

pub type TranscriptResult<T> = Result<T, TranscriptError>;

struct VcaBuffer {
    data: [u8; Self::SPDM_MAX_BUFFER_SIZE],
    size: usize,
}

impl Default for VcaBuffer {
    fn default() -> Self {
        Self {
            data: [0; Self::SPDM_MAX_BUFFER_SIZE],
            size: 0,
        }
    }
}

impl VcaBuffer {
    pub const SPDM_MAX_BUFFER_SIZE: usize = 256;
    fn reset(&mut self) {
        self.data.fill(0);
        self.size = 0;
    }

    fn append(&mut self, data: &[u8]) -> TranscriptResult<()> {
        if self.size + data.len() > Self::SPDM_MAX_BUFFER_SIZE {
            return Err(TranscriptError::BufferOverflow);
        }
        self.data[self.size..self.size + data.len()].copy_from_slice(data);
        self.size += data.len();
        Ok(())
    }

    fn data(&self) -> &[u8] {
        &self.data[..self.size]
    }
}

pub enum TranscriptContext {
    Vca,
    M1,
    L1,
}

/// Transcript management for the SPDM responder.
pub(crate) struct TranscriptManager<'a> {
    spdm_version: SpdmVersion,
    // Buffer for storing `VCA`
    // VCA or A = Concatenate (GET_VERSION, VERSION, GET_CAPABILITIES, CAPABILITIES, NEGOTIATE_ALGORITHMS, ALGORITHMS)
    vca_buf: VcaBuffer,
    // Hash context for `M1`
    // M1 = Concatenate(A, B, C)
    // where
    // B = Concatenate (GET_DIGESTS, DIGESTS, GET_CERTIFICATE, CERTIFICATE)
    // C = Concatenate (CHALLENGE, CHALLENGE_AUTH excluding signature)
    hash_ctx_m1: &'a mut dyn SpdmHash,
    m1_ctx_ready: bool,
    // Hash Context for `L1``
    // L1 = Concatenate(A, M) if SPDM_VERSION >= 1.2 or L1 = Concatenate(M) if SPDM_VERSION < 1.2
    // where
    // M = Concatenate (GET_MEASUREMENTS, MEASUREMENTS\signature)
    hash_ctx_l1: &'a mut dyn SpdmHash,
    l1_ctx_ready: bool,
}

impl<'a> TranscriptManager<'a> {
    pub fn new(m1: &'a mut dyn SpdmHash, l1: &'a mut dyn SpdmHash) -> Self {
        Self {
            spdm_version: SpdmVersion::V10,
            vca_buf: VcaBuffer::default(),
            hash_ctx_m1: m1,
            m1_ctx_ready: false,
            hash_ctx_l1: l1,
            l1_ctx_ready: false
        }
    }

    /// Set the SPDM version selected by the SPDM responder.
    ///
    /// # Arguments
    /// * `spdm_version` - The SPDM version to set.
    pub fn set_spdm_version(&mut self, spdm_version: SpdmVersion) {
        self.spdm_version = spdm_version;
    }

    /// Reset a transcript context or all contexts.
    ///
    /// # Arguments
    /// * `context` - The context to reset. If `None`, all contexts are reset.
    pub fn reset(&mut self) {
        self.spdm_version = SpdmVersion::V10;
        self.vca_buf.reset();
        self.hash_ctx_m1.reset();
        self.m1_ctx_ready = false;
        self.hash_ctx_l1.reset();
        self.l1_ctx_ready = false;
    }

    /// Reset a transcript context.
    ///
    /// # Arguments
    /// * `context` - The context to reset. If `None`, all contexts are reset.
    pub fn reset_context(&mut self, context: TranscriptContext) {
        match context {
            TranscriptContext::Vca => self.vca_buf.reset(),
            TranscriptContext::M1 => { self.hash_ctx_m1.reset(); self.m1_ctx_ready = false; },
            TranscriptContext::L1 => { self.hash_ctx_l1.reset(); self.l1_ctx_ready = false; },
        }
    }

    /// Append data to a transcript context.
    ///
    /// # Arguments
    /// * `context` - The context to append data to.
    /// * `data` - The data to append.
    ///
    /// # Returns
    /// * `TranscriptResult<()>` - Result indicating success or failure.
    pub async fn append(
        &mut self,
        context: TranscriptContext,
        data: &[u8],
    ) -> TranscriptResult<()> {
        match context {
            TranscriptContext::Vca => self.vca_buf.append(data),
            TranscriptContext::M1 => self.append_m1(data).await,
            TranscriptContext::L1 => self.append_l1(self.spdm_version, data).await,
        }
    }

    /// Finalize the hash for a given context.
    ///
    /// # Arguments
    /// * `context` - The context to finalize the hash for.
    /// * `hash` - The buffer to store the resulting hash.
    ///
    /// # Returns
    /// * `TranscriptResult<()>` - Result indicating success or failure.
    pub async fn hash(
        &mut self,
        context: TranscriptContext,
        hash: &mut [u8; SHA384_HASH_SIZE],
    ) -> TranscriptResult<()> {
        let hash_ctx = match context {
            TranscriptContext::Vca => return Err(TranscriptError::InvalidState),
            TranscriptContext::M1 => &mut self.hash_ctx_m1,
            TranscriptContext::L1 => &mut self.hash_ctx_l1,
        };

        hash_ctx
            .finalize(hash)
            .await
            .map_err(|e| TranscriptError::Hash(e))?;

        match context {
            TranscriptContext::M1 =>  {self.hash_ctx_m1.reset(); self.m1_ctx_ready = false; },
            TranscriptContext::L1 => {self.hash_ctx_l1.reset(); self.l1_ctx_ready = false; },
            _ => {}
        }

        Ok(())
    }

    async fn append_m1(&mut self, data: &[u8]) -> TranscriptResult<()> {
        if self.m1_ctx_ready {
            self.hash_ctx_m1
                .update(data).await.map_err(|e| TranscriptError::Hash(e))
        } else {
            let vca_data = self.vca_buf.data();
            self.hash_ctx_m1
                .init(self.hash_ctx_m1.algo(), Some(vca_data))
                .await
                .map_err(|e| TranscriptError::Hash(e))?;
            self.hash_ctx_m1
                .update(data)
                .await
                .map_err(|e| TranscriptError::Hash(e))?;
            self.m1_ctx_ready = true;
            Ok(())
        }
    }

    async fn append_l1(&mut self, spdm_version: SpdmVersion, data: &[u8]) -> TranscriptResult<()> {
        if self.l1_ctx_ready {
            self.hash_ctx_l1
                .update(data).await.map_err(|e| TranscriptError::Hash(e))
        } else {
            let vca_data = if spdm_version >= SpdmVersion::V12 {
                Some(self.vca_buf.data())
            } else {
                None
            };
            self.hash_ctx_l1
                .init(self.hash_ctx_l1.algo(), vca_data)
                .await
                .map_err(|e| TranscriptError::Hash(e))?;

            self.hash_ctx_l1
                .update(data)
                .await
                .map_err(|e| TranscriptError::Hash(e))?;

            self.l1_ctx_ready = true;
            Ok(())
        }
    }
}
