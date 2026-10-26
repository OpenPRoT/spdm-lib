// Licensed under the Apache-2.0 license

//! Host proof-of-concept SPDM programs, run as Cargo examples:
//!
//! * `poc-responder` — the `spdm-stack` Responder over the DMTF spdm-emu
//!   socket framing, with host crypto (`sha2` / `p384`).
//! * `poc-requester` — the `spdm-stack` Requester over the same framing.
//!
//! This library is intentionally empty; Cargo requires a target for the
//! package that owns the examples.
