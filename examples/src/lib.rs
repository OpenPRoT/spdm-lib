// Copyright 2025
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Host proof-of-concept SPDM programs, run as Cargo examples:
//!
//! * `poc-responder` — the `spdm-stack` Responder over the DMTF spdm-emu
//!   socket framing, with host crypto (`sha2` / `p384`).
//! * `poc-requester` — the `spdm-stack` Requester over the same framing.
//!
//! This library is intentionally empty; Cargo requires a target for the
//! package that owns the examples.
