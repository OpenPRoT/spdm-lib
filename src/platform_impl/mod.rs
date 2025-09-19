// Licensed under the Apache-2.0 license

//! Linux-specific platform implementations for the SPDM library
//! 
//! This module provides concrete implementations of the platform traits
//! for Linux systems, including TCP transport, RNG, evidence collection,
//! certificate management, and cryptographic hash functions.

pub mod linux;

// Re-export commonly used types
pub use linux::*;