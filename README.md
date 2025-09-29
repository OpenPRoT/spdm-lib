# spdm-lib
This is a fork of spdm-lib from [Caliptra MCU](https://github.com/chipsalliance/caliptra-mcu-sw/tree/main/runtime/userspace/api/spdm-lib)

Long term the goal is to mold this into a platform independent implementation of an SPDM Requester and Responder. Short term is to get it working in a way that can be used outside of Caliptra MCU, and refactor to relocate things that may hamper embedded operation.

# Merge Policy

There are several branches within this repository, 2 of which are relevant at all times:

_upstream_ - This is a copy of the unmodified sources from the caliptra-mcu-sw repository. When updates come into the tree, they will be copied here and committed.

_openprot_ - This branch contains all openprot created commits. This branch will be rebased on top of upstream regularly.

The use of _main_ is TBD.

## Feature Flags & Platform Helpers

The library is `#![no_std]` by default. Platform conveniences live behind feature flags that pull in `std` only when needed.

Feature summary:

* `std` – Enables use of the Rust standard library.
* `crypto` – Enables cryptographic features using real implementations.

For platform implementations (transport, RNG, evidence), see the `examples/platform/` directory which provides working reference implementations.

### Platform Implementation Examples

The `examples/platform/` directory provides reference implementations:

```rust
// Socket transport for DMTF SPDM protocol
use examples::platform::SpdmSocketTransport;

// SHA-384 hash implementation  
use examples::platform::Sha384Hash;

// System RNG
use examples::platform::SystemRng;

// Certificate store with ECDSA signing
use examples::platform::DemoCertStore;

// Demo evidence implementation
use examples::platform::DemoEvidence;
```

See `examples/spdm_responder.rs` for a complete working example that uses all platform implementations.
	todo!("fill in actual constructor usage");
}
```

Replace these platform helpers with your embedded / production implementations by providing your own types that implement the same traits.

### No-Std Note

If you are targeting a `no_std` environment, avoid enabling the above platform features and supply custom implementations that do not depend on `std`.
