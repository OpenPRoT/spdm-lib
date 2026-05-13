This is a fork of spdm-lib from [Caliptra MCU](https://github.com/chipsalliance/caliptra-mcu-sw/tree/main/runtime/userspace/api/spdm-lib)

Long term the goal is to mold this into a platform independent implementation of an SPDM Requester and Responder. Short term is to get it working in a way that can be used outside of Caliptra MCU, and refactor to relocate things that may hamper embedded operation.

`## Feature Flags & Platform Helpers

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
