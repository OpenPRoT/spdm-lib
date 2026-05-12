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

// use crate::cert_mgr::DeviceCertsManager;
use crate::cert_store::*;
use crate::chunk_ctx::LargeResponseCtx;
use crate::codec::{Codec, MessageBuf};
use crate::commands::capabilities::handle_capabilities_response;
use crate::commands::challenge::handle_challenge_auth_response;
use crate::commands::digests::{handle_digests_response, handle_get_digests};
use crate::commands::error_rsp::{encode_error_response, ErrorCode};
use crate::commands::measurements::request::handle_measurements_response;
use crate::commands::version::handle_version_response;
use crate::commands::{
    algorithms, capabilities, certificate, challenge, chunk_get_rsp, measurements, version,
};

use crate::error::*;
use crate::measurements::common::SpdmMeasurements;
use crate::platform::evidence::SpdmEvidence;
use crate::platform::hash::SpdmHash;
use crate::platform::rng::{SpdmRng, SpdmRngResult};
use crate::platform::transport::SpdmTransport;
use crate::protocol::algorithms::*;
use crate::protocol::common::{ReqRespCode, SpdmMsgHdr};
use crate::protocol::version::*;
use crate::protocol::DeviceCapabilities;
use crate::state::{ConnectionInfo, ConnectionState, State};
use crate::transcript::{TranscriptContext, TranscriptManager};

pub struct SpdmContext<'a> {
    transport: &'a mut dyn SpdmTransport,
    pub(crate) hash: &'a mut dyn SpdmHash,
    pub(crate) supported_versions: &'a [SpdmVersion],
    pub(crate) state: State<'a>,
    pub(crate) transcript_mgr: TranscriptManager<'a>,
    pub(crate) rng: &'a mut dyn SpdmRng,
    pub(crate) local_capabilities: DeviceCapabilities,
    pub(crate) local_algorithms: LocalDeviceAlgorithms<'a>,
    pub(crate) device_certs_store: &'a mut dyn SpdmCertStore,
    pub(crate) measurements: SpdmMeasurements,
    pub(crate) large_resp_context: LargeResponseCtx,
    pub(crate) evidence: &'a dyn SpdmEvidence,
}

impl<'a> SpdmContext<'a> {
    pub fn new(
        supported_versions: &'a [SpdmVersion],
        spdm_transport: &'a mut dyn SpdmTransport,
        local_capabilities: DeviceCapabilities,
        local_algorithms: LocalDeviceAlgorithms<'a>,
        device_certs_store: &'a mut dyn SpdmCertStore,
        peer_cert_store: Option<&'a mut dyn PeerCertStore>,
        hash: &'a mut dyn SpdmHash,
        m1: &'a mut dyn SpdmHash,
        l1: &'a mut dyn SpdmHash,
        rng: &'a mut dyn SpdmRng,
        evidence: &'a dyn SpdmEvidence,
    ) -> SpdmResult<Self> {
        validate_supported_versions(supported_versions)?;
        validate_device_algorithms(&local_algorithms)?;
        validate_cert_store(device_certs_store)?;

        Ok(Self {
            supported_versions,
            transport: spdm_transport,
            state: State::new(peer_cert_store),
            transcript_mgr: TranscriptManager::new(m1, l1),
            local_capabilities,
            local_algorithms,
            device_certs_store,
            measurements: SpdmMeasurements::default(),
            large_resp_context: LargeResponseCtx::default(),
            hash,
            rng,
            evidence,
        })
    }

    pub fn connection_info(&self) -> &ConnectionInfo {
        &self.state.connection_info
    }

    pub fn transport_init_sequence(&mut self) -> SpdmResult<()> {
        self.transport.init_sequence().map_err(SpdmError::Transport)
    }

    /// The Responder receives a request message sent by the Requester and processes it accordingly.
    pub fn responder_process_message(&mut self, msg_buf: &mut MessageBuf<'a>) -> SpdmResult<()> {
        self.transport
            .receive_request(msg_buf)
            .map_err(SpdmError::Transport)?;

        match self.responder_handle_request(msg_buf) {
            Ok(()) => {
                self.send_response(msg_buf)?;
            }
            Err((rsp, command_error)) => {
                if rsp {
                    self.send_response(msg_buf).inspect_err(|_| {})?;
                }
                Err(SpdmError::Command(command_error))?;
            }
        }
        Ok(())
    }

    /// The Requester receives a response message sent by the Responder and processes it accordingly.
    ///
    /// # Arguments
    /// * `resp_buffer`: buffer the message is received into from the transport medium.
    ///
    /// # Warning
    /// This function resets all data initially stored in then resp_buffer.
    pub fn requester_process_message(
        &mut self,
        resp_buffer: &mut MessageBuf<'a>,
    ) -> SpdmResult<()> {
        resp_buffer.reset();
        self.transport
            .receive_response(resp_buffer)
            .map_err(SpdmError::Transport)?;

        match self
            .requester_handle_response(resp_buffer)
            .map_err(|(rsp, cmd_err)| {
                if rsp {
                    SpdmError::Command(cmd_err)
                } else {
                    SpdmError::InvalidParam
                }
            }) {
            Ok(()) => {}
            Err(e) => {
                return Err(e);
            }
        }
        Ok(())
    }

    // Use ReqRespCode as command issuer for now, until the correct state machine is in place
    // TODO: implement in transport
    pub fn requester_send_request(
        &mut self,
        req_buf: &mut MessageBuf<'a>,
        dst_eid: u8,
    ) -> SpdmResult<()> {
        self.transport
            .send_request(dst_eid, req_buf)
            .map_err(|_| SpdmError::InvalidParam)?;

        Ok(())
    }

    /// The responder handles incoming requests and responds to them accordingly.
    fn responder_handle_request(&mut self, buf: &mut MessageBuf<'a>) -> CommandResult<()> {
        let req = buf;

        let req_msg_header: SpdmMsgHdr =
            SpdmMsgHdr::decode(req).map_err(|e| (false, CommandError::Codec(e)))?;

        let req_code = req_msg_header
            .req_resp_code()
            .map_err(|_| (false, CommandError::UnsupportedRequest))?;

        if req_code != ReqRespCode::ChunkGet && self.large_resp_context.in_progress() {
            // Reset large response context if the request is not a CHUNK_GET
            self.large_resp_context.reset();
        }

        match req_code {
            ReqRespCode::GetVersion => version::handle_get_version(self, req_msg_header, req)?,
            ReqRespCode::GetCapabilities => {
                capabilities::handle_get_capabilities(self, req_msg_header, req)?
            }
            ReqRespCode::NegotiateAlgorithms => {
                algorithms::handle_negotiate_algorithms(self, req_msg_header, req)?
            }
            ReqRespCode::GetDigests => handle_get_digests(self, req_msg_header, req)?,
            ReqRespCode::GetCertificate => {
                certificate::handle_get_certificate(self, req_msg_header, req)?
            }
            ReqRespCode::Challenge => challenge::handle_challenge(self, req_msg_header, req)?,
            ReqRespCode::GetMeasurements => {
                measurements::response::handle_get_measurements(self, req_msg_header, req)?
            }
            ReqRespCode::ChunkGet => chunk_get_rsp::handle_chunk_get(self, req_msg_header, req)?,

            _ => Err((false, CommandError::UnsupportedRequest))?,
        }
        Ok(())
    }

    /// Requester function parsing and processing messages provided in `buf`.
    ///
    /// # Arguments
    /// * `buf`: Message buffer containing a raw response.
    fn requester_handle_response(&mut self, buf: &mut MessageBuf<'a>) -> CommandResult<()> {
        let resp = buf;
        let resp_msg_header: SpdmMsgHdr =
            SpdmMsgHdr::decode(resp).map_err(|e| (false, CommandError::Codec(e)))?;

        let resp_code = resp_msg_header
            .req_resp_code()
            .map_err(|_| (false, CommandError::UnsupportedRequest))?;

        if resp_code.is_request() {
            Err((false, CommandError::UnsupportedRequest))?
        }

        // if req_code != ReqRespCode::ChunkGet && self.large_resp_context.in_progress() {
        //     // Reset large response context if the request is not a CHUNK_GET
        //     self.large_resp_context.reset();
        // }

        match resp_code {
            ReqRespCode::Version => handle_version_response(self, resp_msg_header, resp)?,
            ReqRespCode::Capabilities => handle_capabilities_response(self, resp_msg_header, resp)?,
            ReqRespCode::Algorithms => {
                algorithms::handle_algorithms_response(self, resp_msg_header, resp)?
            }
            ReqRespCode::Digests => handle_digests_response(self, resp_msg_header, resp)?,
            ReqRespCode::Certificate => {
                certificate::request::handle_certificate_response(self, resp_msg_header, resp)?
            }
            ReqRespCode::ChallengeAuth => {
                handle_challenge_auth_response(self, resp_msg_header, resp)?
            }
            ReqRespCode::Measurements => handle_measurements_response(self, resp_msg_header, resp)?,
            _ => Err((false, CommandError::UnsupportedResponse))?,
        }

        Ok(())
    }

    fn send_response(&mut self, resp: &mut MessageBuf<'a>) -> SpdmResult<()> {
        self.transport
            .send_response(resp)
            .map_err(SpdmError::Transport)
    }

    pub(crate) fn prepare_response_buffer(&self, rsp_buf: &mut MessageBuf) -> CommandResult<()> {
        rsp_buf.reset();
        rsp_buf
            .reserve(self.transport.header_size())
            .map_err(|_| (false, CommandError::BufferTooSmall))?;
        Ok(())
    }

    /// Returns the minimum data transfer size based on local and peer capabilities.
    pub(crate) fn min_data_transfer_size(&self) -> usize {
        self.local_capabilities.data_transfer_size.min(
            self.state
                .connection_info
                .peer_capabilities()
                .data_transfer_size,
        ) as usize
    }

    pub(crate) fn verify_selected_hash_algo(&mut self) -> SpdmResult<()> {
        let peer_algorithms = self.state.connection_info.peer_algorithms();
        let local_algorithms = &self.local_algorithms.device_algorithms;
        let algorithm_priority_table = &self.local_algorithms.algorithm_priority_table;

        let base_hash_sel = local_algorithms.base_hash_algo.prioritize(
            &peer_algorithms.base_hash_algo,
            algorithm_priority_table.base_hash_algo,
        );

        // Ensure BaseHashSel has exactly one bit set
        if base_hash_sel.0.count_ones() != 1 {
            return Err(SpdmError::InvalidParam);
        }

        if base_hash_sel.tpm_alg_sha_384() != 1 {
            return Err(SpdmError::InvalidParam);
        }

        Ok(())
    }

    pub(crate) fn selected_base_asym_algo(&self) -> SpdmResult<AsymAlgo> {
        let peer_algorithms = self.state.connection_info.peer_algorithms();
        let local_algorithms = &self.local_algorithms.device_algorithms;
        let algorithm_priority_table = &self.local_algorithms.algorithm_priority_table;

        let base_asym_sel = BaseAsymAlgo(local_algorithms.base_asym_algo.0.prioritize(
            &peer_algorithms.base_asym_algo.0,
            algorithm_priority_table.base_asym_algo,
        ));

        // Ensure AsymAlgoSel has exactly one bit set
        if base_asym_sel.0.count_ones() != 1 || base_asym_sel.tpm_alg_ecdsa_ecc_nist_p384() != 1 {
            return Err(SpdmError::InvalidParam);
        }

        Ok(AsymAlgo::EccP384)
    }

    pub(crate) fn generate_error_response(
        &self,
        msg_buf: &mut MessageBuf,
        error_code: ErrorCode,
        error_data: u8,
        extended_data: Option<&[u8]>,
    ) -> (bool, CommandError) {
        let _ = self
            .prepare_response_buffer(msg_buf)
            .map_err(|_| (false, CommandError::BufferTooSmall));
        let spdm_version = self.state.connection_info.version_number();

        encode_error_response(msg_buf, spdm_version, error_code, error_data, extended_data)
    }

    pub(crate) fn reset_transcript_via_req_code(&mut self, req_code: ReqRespCode) {
        // Any request other than GET_MEASUREMENTS resets the L1 transcript context.
        if req_code != ReqRespCode::GetMeasurements {
            self.transcript_mgr.reset_context(TranscriptContext::L1);
        }

        // If requester issued GET_MEASUREMENTS request and skipped CHALLENGE completion, reset M1 context.
        match req_code {
            ReqRespCode::GetMeasurements
                if self.state.connection_info.state() < ConnectionState::Authenticated =>
            {
                self.transcript_mgr.reset_context(TranscriptContext::M1);
            }
            ReqRespCode::GetDigests => {
                self.transcript_mgr.reset_context(TranscriptContext::M1);
            }
            _ => {}
        }
    }

    pub(crate) fn append_message_to_transcript(
        &mut self,
        msg_buf: &mut MessageBuf<'_>,
        transcript_context: TranscriptContext,
    ) -> CommandResult<()> {
        let msg = msg_buf
            .message_data()
            .map_err(|e| (false, CommandError::Codec(e)))?;

        self.transcript_mgr
            .append(transcript_context, msg)
            .map_err(|e| (false, CommandError::Transcript(e)))
    }

    pub fn peer_cert_store(&self) -> Option<&dyn PeerCertStore> {
        self.state.peer_cert_store.as_deref()
    }

    /// To safeguard the user-facing API, we prohibit the retrieval of hashes unless the context is in a valid state.
    /// These states are:
    /// - [`ConnectionState::AfterCertificate`] for the M1 transcript context
    /// - [`ConnectionState::Authenticated`] for the L2 transcript context
    ///
    /// # Arguments
    /// - `transcript_context`: The transcript context for which the hash is being requested.
    pub fn transcript_hash(
        &mut self,
        transcript_context: TranscriptContext,
        hash: &mut [u8],
    ) -> CommandResult<()> {
        match transcript_context {
            TranscriptContext::M1 => {
                if self.state.connection_info.state() < ConnectionState::AfterCertificate {
                    return Err((false, CommandError::InvalidState));
                }
            }
            TranscriptContext::L1 => {
                if self.state.connection_info.state() < ConnectionState::Authenticated {
                    return Err((false, CommandError::InvalidState));
                }
            }
            TranscriptContext::Vca => {
                return Err((false, CommandError::InvalidState));
            }
        }

        let mut hash_out_max = [0u8; 48];
        self.transcript_mgr
            .hash(transcript_context, &mut hash_out_max)
            .map_err(|e| (false, CommandError::Transcript(e)))?;

        if hash.len() > hash_out_max.len() {
            return Err((false, CommandError::BufferTooSmall));
        }

        hash.copy_from_slice(&hash_out_max[..hash.len()]);
        Ok(())
    }

    /// Expose the `SystemRng` function `get_random_bytes` to context.
    ///
    /// # Arguments
    /// - `dest`: Destination buffer that holds the random bytes.
    pub fn get_random_bytes(&mut self, dest: &mut [u8]) -> SpdmRngResult<()> {
        self.rng.get_random_bytes(dest)
    }

    /// Set the connection state to authenticated
    ///
    /// Should be called after after the signature of a CHALLENGE response has been verified.
    pub fn set_authenticated(&mut self) {
        self.state
            .connection_info
            .set_state(ConnectionState::Authenticated);
    }
}
