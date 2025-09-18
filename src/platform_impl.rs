// Licensed under the Apache-2.0 license

//! Platform specific concrete implementations (host/OS bound). Currently Linux only.

#[cfg(feature = "tcp-transport")]
pub mod linux {
    pub mod tcp;
    pub use tcp::SpdmTcp;
}
