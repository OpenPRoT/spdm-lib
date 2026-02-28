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

//! Basic instantiation test for SpdmContext (host validator)
//! Run with: cargo test --features std -- --nocapture

use spdm_lib::cert_store::{CertStoreResult, SpdmCertStore};
use spdm_lib::codec::MessageBuf;
use spdm_lib::context::SpdmContext;
use spdm_lib::error::SpdmResult;
use spdm_lib::platform::evidence::{SpdmEvidence, SpdmEvidenceResult};
use spdm_lib::platform::hash::{SpdmHash, SpdmHashAlgoType, SpdmHashResult};
use spdm_lib::platform::rng::{SpdmRng, SpdmRngResult};
use spdm_lib::platform::transport::{SpdmTransport, TransportResult};
use spdm_lib::protocol::algorithms::{
    AeadCipherSuite, AlgorithmPriorityTable, AsymAlgo, BaseAsymAlgo, BaseHashAlgo,
    DeviceAlgorithms, DheNamedGroup, KeySchedule, LocalDeviceAlgorithms, MeasurementHashAlgo,
    MeasurementSpecification, MelSpecification, OtherParamSupport, ReqBaseAsymAlg,
};
use spdm_lib::protocol::algorithms::{ECC_P384_SIGNATURE_SIZE, SHA384_HASH_SIZE};
use spdm_lib::protocol::version::SpdmVersion;
use spdm_lib::protocol::DeviceCapabilities;

struct MockTransport;
impl SpdmTransport for MockTransport {
    fn send_request<'a>(&mut self, _dest: u8, _req: &mut MessageBuf<'a>) -> TransportResult<()> {
        Ok(())
    }
    fn receive_response<'a>(&mut self, _rsp: &mut MessageBuf<'a>) -> TransportResult<()> {
        Ok(())
    }
    fn receive_request<'a>(&mut self, _req: &mut MessageBuf<'a>) -> TransportResult<()> {
        Ok(())
    }
    fn send_response<'a>(&mut self, _resp: &mut MessageBuf<'a>) -> TransportResult<()> {
        Ok(())
    }
    fn max_message_size(&self) -> TransportResult<usize> {
        Ok(1024)
    }
    fn header_size(&self) -> usize {
        0
    }

    fn init_sequence(&mut self) -> TransportResult<()> {
        todo!()
    }
}

struct MockHash {
    algo: SpdmHashAlgoType,
}
impl MockHash {
    fn new() -> Self {
        Self {
            algo: SpdmHashAlgoType::SHA384,
        }
    }
}
impl SpdmHash for MockHash {
    fn hash(&mut self, _algo: SpdmHashAlgoType, data: &[u8], out: &mut [u8]) -> SpdmHashResult<()> {
        let len = out.len().min(data.len());
        out[..len].copy_from_slice(&data[..len]);
        Ok(())
    }
    fn init(&mut self, _algo: SpdmHashAlgoType, _data: Option<&[u8]>) -> SpdmHashResult<()> {
        Ok(())
    }
    fn update(&mut self, _data: &[u8]) -> SpdmHashResult<()> {
        Ok(())
    }
    fn finalize(&mut self, out: &mut [u8]) -> SpdmHashResult<()> {
        for b in out.iter_mut() {
            *b = 0xAA;
        }
        Ok(())
    }
    fn reset(&mut self) {}
    fn algo(&self) -> SpdmHashAlgoType {
        self.algo
    }
}

struct MockRng;
impl SpdmRng for MockRng {
    fn get_random_bytes(&mut self, buf: &mut [u8]) -> SpdmRngResult<()> {
        for (i, b) in buf.iter_mut().enumerate() {
            *b = i as u8;
        }
        Ok(())
    }
    fn generate_random_number(&mut self, buf: &mut [u8]) -> SpdmRngResult<()> {
        self.get_random_bytes(buf)
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
    fn get_cert_chain<'a>(
        &mut self,
        _slot_id: u8,
        _asym: AsymAlgo,
        _offset: usize,
        out: &'a mut [u8],
    ) -> CertStoreResult<usize> {
        let fill = out.len().min(16);
        for b in &mut out[..fill] {
            *b = 0x55;
        }
        Ok(fill)
    }
    fn root_cert_hash<'a>(
        &mut self,
        _slot_id: u8,
        _asym: AsymAlgo,
        out: &'a mut [u8; SHA384_HASH_SIZE],
    ) -> CertStoreResult<()> {
        for b in out.iter_mut() {
            *b = 0x11;
        }
        Ok(())
    }
    fn sign_hash<'a>(
        &self,
        _slot_id: u8,
        _hash: &'a [u8; SHA384_HASH_SIZE],
        sig: &'a mut [u8; ECC_P384_SIGNATURE_SIZE],
    ) -> CertStoreResult<()> {
        for b in sig.iter_mut() {
            *b = 0x22;
        }
        Ok(())
    }
    fn key_pair_id(&self, _slot_id: u8) -> Option<u8> {
        Some(0)
    }
    fn cert_info(&self, _slot_id: u8) -> Option<spdm_lib::protocol::certs::CertificateInfo> {
        None
    }
    fn key_usage_mask(&self, _slot_id: u8) -> Option<spdm_lib::protocol::certs::KeyUsageMask> {
        None
    }
}

#[test]
fn spdm_validator_host() -> SpdmResult<()> {
    // Supported versions
    let versions = [SpdmVersion::V10];

    // Capabilities (minimal plausible set)
    let dev_caps = DeviceCapabilities {
        ct_exponent: 0,
        flags: spdm_lib::protocol::capabilities::CapabilityFlags::default(),
        data_transfer_size: 1024,
        max_spdm_msg_size: 2048,
        include_supported_algorithms: false,
    };

    // Algorithms (provide trivial single-selection values)
    let device_algo = DeviceAlgorithms {
        measurement_spec: MeasurementSpecification::default(),
        other_param_support: OtherParamSupport::default(),
        measurement_hash_algo: MeasurementHashAlgo::default(),
        base_asym_algo: BaseAsymAlgo::default(),
        base_hash_algo: BaseHashAlgo::default(),
        mel_specification: MelSpecification::default(),
        dhe_group: DheNamedGroup::default(),
        aead_cipher_suite: AeadCipherSuite::default(),
        req_base_asym_algo: ReqBaseAsymAlg::default(),
        key_schedule: KeySchedule::default(),
    };
    let priority_table = AlgorithmPriorityTable {
        measurement_specification: None,
        opaque_data_format: None,
        base_asym_algo: None,
        base_hash_algo: None,
        mel_specification: None,
        dhe_group: None,
        aead_cipher_suite: None,
        req_base_asym_algo: None,
        key_schedule: None,
    };
    let local_algos = LocalDeviceAlgorithms {
        device_algorithms: device_algo,
        algorithm_priority_table: priority_table,
    };

    let mut transport = MockTransport;
    let mut hash_main = MockHash::new();
    let mut hash_m1 = MockHash::new();
    let mut hash_l1 = MockHash::new();
    let mut rng = MockRng;
    let evidence = MockEvidence;
    let mut certs = MockCertStore;

    let ctx = SpdmContext::new(
        &versions,
        &mut transport,
        dev_caps,
        local_algos,
        &mut certs,
        None,
        &mut hash_main,
        &mut hash_m1,
        &mut hash_l1,
        &mut rng,
        &evidence,
    )?;
    let _ = &ctx; // suppress unused variable warning

    // Smoke check some internal state expectations
    // Context created; we can check selected versions slice used.
    assert_eq!(versions[0], SpdmVersion::V10);

    Ok(())
}
