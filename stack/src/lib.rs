// Licensed under the Apache-2.0 license

//! `spdm-stack` — SPDM responder state machine and dispatcher.
//!
//! This crate implements the responder side of the SPDM protocol on
//! top of the SPDM-Lite Platform Abstraction Layer
//! ([`spdm_traits`]). It owns:
//!
//! * A [`SpdmStack`] — the main `run()` loop that receives an SPDM
//!   request, dispatches it to a handler, and sends back either the
//!   handler's response or a SPDM `ERROR` PDU. A matched VDM backend may
//!   request that a vendor-protocol failure be dropped without a response
//!   when that is the source stack's wire behavior.
//! * A [`ConnectionState`] — the per-connection negotiation state
//!   (current phase, negotiated version, peer capabilities, …) plus
//!   the responder's fixed local-policy advertisement.
//! * Per-command handler modules ([`version`], [`capabilities`],
//!   [`algorithms`]).
//!
//! Handlers are pure async functions over `&mut ConnectionState` and
//! `&Pal`; they return [`SpdmResult<PalBytes<'_, Pal>>`](SpdmResult)
//! where `Ok` is the fully-encoded response buffer (transport header
//! + SPDM header + body) and `Err` is an SPDM wire byte that the
//!   dispatcher turns into an `ERROR` PDU.
//!
//! Below the handler/dispatcher boundary this crate uses the
//! workspace-wide [`PalErrorCode`](spdm_errors::PalErrorCode) /
//! [`PalResult`](spdm_errors::PalResult) types; `?` lifts those into
//! [`SpdmError`] automatically (see [`error`]).

#![no_std]

extern crate alloc;

mod algorithms;
mod build;
mod capabilities;
mod certificate;
mod challenge;
mod chunk;
mod digests;
mod end_session;
mod error;
mod finish;
mod heartbeat;
mod key_exchange;
pub mod key_schedule;
mod measurements;
pub mod requester;
pub mod session;
#[cfg(feature = "set-certificate")]
mod set_certificate;
pub(crate) mod signing;
mod stack;
mod transcript;
mod vendor_defined;
mod version;

pub use error::*;
pub use stack::*;
pub use transcript::*;
