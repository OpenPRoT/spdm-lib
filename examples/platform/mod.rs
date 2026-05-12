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

//! Platform implementations for SPDM examples
//!
//! This module provides working platform implementations that can be easily
//! swapped out for production implementations.

#![allow(unused_imports)]
#![allow(dead_code)]

pub mod cert_store;
pub mod certs;
pub mod crypto;
pub mod evidence;
pub mod socket_transport;

pub use cert_store::DemoCertStore;
pub use crypto::{Sha384Hash, SystemRng};
pub use evidence::DemoEvidence;
pub use socket_transport::SpdmSocketTransport;
// Certificate constants available for examples that need them
#[allow(unused_imports)]
pub use certs::{
    STATIC_END_CERT, STATIC_END_RESPONDER_KEY_DER, STATIC_INTER_CERT, STATIC_ROOT_CA_CERT,
};
