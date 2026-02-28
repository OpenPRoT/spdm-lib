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

#![cfg_attr(not(test), no_std)]

/// Common errors
pub mod error;

/// Codec and protocol buffer
pub mod codec;

/// Spdm common message protocol handling
pub mod protocol;

/// Context and request handling
pub mod commands;
pub mod context;

/// Spdm responder state
pub mod state;

/// Device certificate management
pub mod cert_store;

/// Transcript management
pub mod transcript;

/// Spdm measurements management
pub mod measurements;

/// Chunking context for large messages
pub mod chunk_ctx;

/// Platform-specific traits
pub mod platform;

/// Mock implementations for unit tests
#[cfg(test)]
pub(crate) mod test;
