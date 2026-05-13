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

//! DMTF libspdm ECP384 test certificate chain for SPDM platform implementations.
//!
//! Certificates sourced from: spdm-emu/libspdm/unit_test/sample_key/ecp384/
//! - ca.cert.der: root CA (matches examples/cert/ecp384_ca.cert.der used by the requester)
//! - inter.cert.der: intermediate CA signed by the root
//! - end_responder.cert.der: end-entity cert signed by the intermediate CA
//! - end_responder.key.der: SEC1 DER-encoded P-384 private key for the end-entity cert

/// DMTF libspdm ECP384 root CA certificate (DER-encoded).
/// This is the same cert as examples/cert/ecp384_ca.cert.der used by the requester.
pub const STATIC_ROOT_CA_CERT: &[u8] = include_bytes!("../certs/ca.cert.der");

/// DMTF libspdm ECP384 intermediate CA certificate (DER-encoded).
pub const STATIC_INTER_CERT: &[u8] = include_bytes!("../certs/inter.cert.der");

/// DMTF libspdm ECP384 end-entity (responder) certificate (DER-encoded).
pub const STATIC_END_CERT: &[u8] = include_bytes!("../certs/end_responder.cert.der");

/// SEC1 DER-encoded P-384 private key for the end-entity responder certificate.
pub const STATIC_END_RESPONDER_KEY_DER: &[u8] = include_bytes!("../certs/end_responder.key.der");
