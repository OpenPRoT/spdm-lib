// Licensed under the Apache-2.0 license

//! Minimal measurement provider: one immutable-ROM digest measurement.

use sha2::{Digest, Sha384};

use spdm_error::{codes::INVARIANT, PalResult};
use spdm_traits::{MeasurementInfo, SpdmPalMeasurements, SPDM_NONCE_LEN};

use super::HostPal;

/// The single measurement block this responder exposes (index 1).
const MEAS_INDEX: u8 = 1;
const DIGEST_LEN: u16 = 48;

impl SpdmPalMeasurements for HostPal {
    fn measurement_info(&self) -> &[MeasurementInfo] {
        &self.measurements
    }

    fn get_measurement_value(
        &self,
        _io: &Self::Io<'_>,
        index: u8,
        _nonce: Option<&[u8; SPDM_NONCE_LEN]>,
        out: &mut [u8],
    ) -> PalResult<usize> {
        if index != MEAS_INDEX {
            return Err(INVARIANT);
        }
        if out.len() < DIGEST_LEN as usize {
            return Err(INVARIANT);
        }
        // Deterministic placeholder digest: SHA-384 of a fixed firmware label.
        let mut h = Sha384::new();
        h.update(b"poc-responder:firmware:v0");
        out[..48].copy_from_slice(&h.finalize());
        Ok(48)
    }
}

/// Builds the fixed measurement table used by [`HostPal`].
pub fn measurement_table() -> Vec<MeasurementInfo> {
    vec![MeasurementInfo {
        index: MEAS_INDEX,
        value_size: DIGEST_LEN,
        value_type: 0, // ImmutableROM
        is_raw: false, // already a digest
        is_tcb: true,
    }]
}
