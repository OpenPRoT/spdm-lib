// Licensed under the Apache-2.0 license

//! Platform implementations for SPDM examples
//!
//! This module provides working platform implementations that can be easily
//! swapped out for production implementations.

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
pub use certs::{ATTESTATION_PRIVATE_KEY, STATIC_ATTESTATION_CERT, STATIC_ROOT_CA_CERT};
