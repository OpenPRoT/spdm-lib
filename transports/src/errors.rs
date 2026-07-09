// Licensed under the Apache-2.0 license

//! Error code constants produced by spdm-lib transports.
//!
//! Subdomain bytes live in [`spdm_errors`]; this module owns
//! the per-transport [`PalErrorCode`] constants. Each transport gets its
//! own submodule so callers can `use spdm_transports::errors::mctp::*;`.

use spdm_error::{domain, PalErrorCode};

/// Error codes returned by [`crate::mctp::SpdmMctpTransport`].
///
/// All codes live in [`spdm_error::domain::SPDM`] subdomain
/// [`spdm_errors::SUBDOMAIN_MCTP`].
pub mod mctp {
    use super::{domain, PalErrorCode};
    use spdm_errors::SUBDOMAIN_MCTP;

    /// The received message did not match the configured MCTP message type.
    pub const UNEXPECTED_MESSAGE_TYPE: PalErrorCode =
        PalErrorCode::new(domain::SPDM, SUBDOMAIN_MCTP, 0x0001);

    /// `send_response` was called without a prior successful
    /// `recv_request` (no captured `MessageInfo`).
    pub const NO_REQUEST_IN_FLIGHT: PalErrorCode =
        PalErrorCode::new(domain::SPDM, SUBDOMAIN_MCTP, 0x0002);

    /// The received message is malformed (shorter than the MCTP
    /// header, or longer than the receive buffer).
    pub const INVALID_MESSAGE: PalErrorCode =
        PalErrorCode::new(domain::SPDM, SUBDOMAIN_MCTP, 0x0003);

    /// A secured-message operation was requested but this transport
    /// does not support SPDM Secured Messages.
    pub const OPERATION_NOT_SUPPORTED: PalErrorCode =
        PalErrorCode::new(domain::SPDM, SUBDOMAIN_MCTP, 0x0004);

    /// The caller-provided receive buffer is too small to hold even
    /// the MCTP transport header.
    pub const BUFFER_TOO_SMALL: PalErrorCode =
        PalErrorCode::new(domain::SPDM, SUBDOMAIN_MCTP, 0x0005);
}

/// Error codes returned by [`crate::doe::SpdmDoeTransport`].
pub mod doe {
    use super::{domain, PalErrorCode};
    use spdm_errors::SUBDOMAIN_DOE;

    /// The received DOE data object type is not SPDM or Secure SPDM.
    pub const UNEXPECTED_OBJECT_TYPE: PalErrorCode =
        PalErrorCode::new(domain::SPDM, SUBDOMAIN_DOE, 0x0001);

    /// The received message is malformed (shorter than the DOE header,
    /// or longer than the receive buffer).
    pub const INVALID_MESSAGE: PalErrorCode =
        PalErrorCode::new(domain::SPDM, SUBDOMAIN_DOE, 0x0002);

    /// The caller-provided receive buffer is too small.
    pub const BUFFER_TOO_SMALL: PalErrorCode =
        PalErrorCode::new(domain::SPDM, SUBDOMAIN_DOE, 0x0003);
}
