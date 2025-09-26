// Licensed under the Apache-2.0 license

//! Platform implementations for SPDM examples
//! 
//! This module provides working platform implementations that can be easily
//! swapped out for production implementations.

pub mod socket_transport;
pub mod crypto;
pub mod cert_store;
pub mod evidence;
pub mod certs;

pub use socket_transport::SpdmSocketTransport;
pub use crypto::{Sha384Hash, SystemRng};
pub use cert_store::DemoCertStore;
pub use evidence::DemoEvidence;
// Certificate constants available for examples that need them
#[allow(unused_imports)]
pub use certs::{STATIC_ROOT_CA_CERT, STATIC_ATTESTATION_CERT, STATIC_CERTIFICATE_CHAIN};