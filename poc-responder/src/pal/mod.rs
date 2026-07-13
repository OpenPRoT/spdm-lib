// Licensed under the Apache-2.0 license

//! `HostPal` — the single platform binding the SPDM stack runs on.
//!
//! One type implements the whole `SpdmPal` super-trait family across the
//! submodules here: transport (spdm-emu TCP), allocation (heap), hashing
//! (sha2), cert store + signing (p384), measurements, and a session-crypto
//! stub. `SpdmStack::new(HostPal)` then drives the responder.

mod alloc;
mod certs;
mod hash;
mod meas;
mod session;
mod transport;

use std::cell::RefCell;
use std::net::TcpStream;

use spdm_traits::{MeasurementInfo, SpdmPal};

use alloc::AllocStats;
use certs::CertState;

/// Host platform abstraction layer.
pub struct HostPal {
    /// spdm-emu socket, behind a `RefCell` because `recv_request`/`send_response`
    /// take `&self` (the stack keeps an `Io` borrow alive across the call pair).
    pub(crate) stream: RefCell<TcpStream>,
    /// Static DER cert chain + P-384 signing key.
    pub(crate) certs: CertState,
    /// Fixed measurement table.
    pub(crate) measurements: Vec<MeasurementInfo>,
    /// Allocation counters, printed on drop.
    pub(crate) stats: AllocStats,
}

impl HostPal {
    /// Builds a PAL bound to an accepted spdm-emu connection.
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream: RefCell::new(stream),
            certs: CertState::new(),
            measurements: meas::measurement_table(),
            stats: AllocStats::default(),
        }
    }

    /// Returns the slot-0 cert state, or an error for any other slot.
    fn slot0(&self, slot: u8) -> spdm_error::PalResult<&CertState> {
        if slot == 0 {
            Ok(&self.certs)
        } else {
            Err(spdm_error::codes::INVARIANT)
        }
    }
}

// All six sub-traits are implemented across the submodules, so the marker
// super-trait is satisfied automatically.
impl SpdmPal for HostPal {}

impl Drop for HostPal {
    fn drop(&mut self) {
        self.stats.report();
    }
}
