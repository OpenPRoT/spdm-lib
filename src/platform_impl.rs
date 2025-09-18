// Licensed under the Apache-2.0 license

//! Platform specific concrete implementations (host/OS bound). Currently Linux only.

#[cfg(any(feature = "tcp-transport", feature = "rand-rng", feature = "linux-evidence", feature = "linux-certs"))]
pub mod linux {
    #[cfg(feature = "tcp-transport")]
    pub mod tcp;
    #[cfg(feature = "tcp-transport")]
    pub use tcp::SpdmTcp;

    #[cfg(feature = "rand-rng")]
    pub mod rng;
    #[cfg(feature = "rand-rng")]
    pub use rng::SpdmLinuxRng;

    #[cfg(feature = "linux-evidence")]
    pub mod evidence;
    #[cfg(feature = "linux-evidence")]
    pub use evidence::SpdmLinuxEvidence;

    #[cfg(feature = "linux-certs")]
    pub mod certs;
    #[cfg(feature = "linux-certs")]
    pub use certs::SpdmLinuxCertStore;
}
