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

use crate::{
    cert_store::{CertStoreResult, SpdmCertStore},
    context::SpdmContext,
    platform::{
        evidence::{SpdmEvidence, SpdmEvidenceResult},
        hash::SpdmHash,
        rng::SpdmRng,
        transport::SpdmTransport,
    },
    protocol::{
        AsymAlgo, CertificateInfo, DeviceCapabilities, KeyUsageMask, LocalDeviceAlgorithms,
        SpdmVersion,
    },
};

pub struct MockResources {
    transport: MockTransport,
    hasher: StdHash,
    m1: StdHash,
    l1: StdHash,
    rng: StdRng,
    cert_store: MockCertStore,
    evidence: MockEvidence,
}
impl MockResources {
    pub fn new() -> MockResources {
        MockResources {
            transport: MockTransport,
            hasher: StdHash,
            m1: StdHash,
            l1: StdHash,
            rng: StdRng,
            cert_store: MockCertStore,
            evidence: MockEvidence,
        }
    }
}

pub fn create_context<'a>(
    stack: &'a mut MockResources,
    versions: &'a [SpdmVersion],
    algorithms: LocalDeviceAlgorithms<'a>,
) -> SpdmContext<'a> {
    SpdmContext::new(
        versions,
        &mut stack.transport,
        DeviceCapabilities::default(),
        algorithms,
        &mut stack.cert_store,
        None,
        &mut stack.hasher,
        &mut stack.m1,
        &mut stack.l1,
        &mut stack.rng,
        &stack.evidence,
    )
    .unwrap()
}

/// Create a array with all available versions
pub fn versions_default() -> [SpdmVersion; 4] {
    [
        SpdmVersion::V10,
        SpdmVersion::V11,
        SpdmVersion::V12,
        SpdmVersion::V13,
    ]
}

struct StdHash;

impl SpdmHash for StdHash {
    fn hash(
        &mut self,
        _hash_algo: crate::platform::hash::SpdmHashAlgoType,
        _data: &[u8],
        _hash: &mut [u8],
    ) -> crate::platform::hash::SpdmHashResult<()> {
        todo!()
    }

    fn init(
        &mut self,
        _hash_algo: crate::platform::hash::SpdmHashAlgoType,
        _data: Option<&[u8]>,
    ) -> crate::platform::hash::SpdmHashResult<()> {
        todo!()
    }

    fn update(&mut self, _data: &[u8]) -> crate::platform::hash::SpdmHashResult<()> {
        todo!()
    }

    fn finalize(&mut self, _hash: &mut [u8]) -> crate::platform::hash::SpdmHashResult<()> {
        todo!()
    }

    fn reset(&mut self) {
        todo!()
    }

    fn algo(&self) -> crate::platform::hash::SpdmHashAlgoType {
        todo!()
    }
}

struct StdRng;

impl SpdmRng for StdRng {
    fn get_random_bytes(&mut self, _buf: &mut [u8]) -> crate::platform::rng::SpdmRngResult<()> {
        todo!()
    }

    fn generate_random_number(
        &mut self,
        _random_number: &mut [u8],
    ) -> crate::platform::rng::SpdmRngResult<()> {
        todo!()
    }
}

struct MockTransport;
impl SpdmTransport for MockTransport {
    fn send_request<'a>(
        &mut self,
        _dest_eid: u8,
        _req: &mut crate::codec::MessageBuf<'a>,
    ) -> crate::platform::transport::TransportResult<()> {
        todo!()
    }

    fn receive_response<'a>(
        &mut self,
        _rsp: &mut crate::codec::MessageBuf<'a>,
    ) -> crate::platform::transport::TransportResult<()> {
        todo!()
    }

    fn receive_request<'a>(
        &mut self,
        _req: &mut crate::codec::MessageBuf<'a>,
    ) -> crate::platform::transport::TransportResult<()> {
        todo!()
    }

    fn send_response<'a>(
        &mut self,
        _resp: &mut crate::codec::MessageBuf<'a>,
    ) -> crate::platform::transport::TransportResult<()> {
        todo!()
    }

    fn max_message_size(&self) -> crate::platform::transport::TransportResult<usize> {
        todo!()
    }

    fn header_size(&self) -> usize {
        0
    }

    fn init_sequence(&mut self) -> crate::platform::transport::TransportResult<()> {
        todo!()
    }
}

struct MockCertStore;
impl SpdmCertStore for MockCertStore {
    fn slot_count(&self) -> u8 {
        1
    }
    fn is_provisioned(&self, slot_id: u8) -> bool {
        slot_id == 0
    }
    fn cert_chain_len(&mut self, _asym: AsymAlgo, _slot_id: u8) -> CertStoreResult<usize> {
        Ok(128)
    }
    fn get_cert_chain(
        &mut self,
        _slot_id: u8,
        _asym: AsymAlgo,
        _offset: usize,
        out: &mut [u8],
    ) -> CertStoreResult<usize> {
        let fill = out.len().min(16);
        for b in &mut out[..fill] {
            *b = 0x55;
        }
        Ok(fill)
    }
    fn root_cert_hash(
        &mut self,
        _slot_id: u8,
        _asym: AsymAlgo,
        out: &mut [u8; crate::protocol::SHA384_HASH_SIZE],
    ) -> CertStoreResult<()> {
        for b in out.iter_mut() {
            *b = 0x11;
        }
        Ok(())
    }
    fn sign_hash<'a>(
        &self,
        _slot_id: u8,
        _hash: &'a [u8; crate::protocol::SHA384_HASH_SIZE],
        sig: &'a mut [u8; crate::protocol::ECC_P384_SIGNATURE_SIZE],
    ) -> CertStoreResult<()> {
        for b in sig.iter_mut() {
            *b = 0x22;
        }
        Ok(())
    }
    fn key_pair_id(&self, _slot_id: u8) -> Option<u8> {
        Some(0)
    }
    fn cert_info(&self, _slot_id: u8) -> Option<CertificateInfo> {
        None
    }
    fn key_usage_mask(&self, _slot_id: u8) -> Option<KeyUsageMask> {
        None
    }
}

struct MockEvidence;
impl SpdmEvidence for MockEvidence {
    fn pcr_quote(&self, buffer: &mut [u8], _with_pqc_sig: bool) -> SpdmEvidenceResult<usize> {
        let data = b"EVID";
        let len = data.len().min(buffer.len());
        buffer[..len].copy_from_slice(&data[..len]);
        Ok(len)
    }
    fn pcr_quote_size(&self, _with_pqc_sig: bool) -> SpdmEvidenceResult<usize> {
        Ok(4)
    }
}
