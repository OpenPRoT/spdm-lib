// Licensed under the Apache-2.0 license

//! Platform implementations including static certificates

// Static certificate data
pub mod certs;

// Re-export certificate constants
pub use certs::{STATIC_ROOT_CA_CERT, STATIC_ATTESTATION_CERT, STATIC_CERTIFICATE_CHAIN};