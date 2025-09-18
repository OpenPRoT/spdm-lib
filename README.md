This is a fork of spdm-lib from [Caliptra MCU](https://github.com/chipsalliance/caliptra-mcu-sw/tree/main/runtime/userspace/api/spdm-lib)

Long term the goal is to mold this into a platform independent implementation of an SPDM Requester and Responder. Short term is to get it working in a way that can be used outside of Caliptra MCU, and refactor to relocate things that may hamper embedded operation.

`## Feature Flags & Platform Helpers

The library is `#![no_std]` by default. Platform conveniences live behind feature flags that pull in `std` only when needed.

Feature summary:

* `std` – Enables use of the Rust standard library. (Most other platform features imply this.)
* `tcp-transport` – Provides a blocking TCP length‑prefixed SPDM transport: `platform_impl::linux::SpdmTcp`.
* `rand-rng` – Provides `SpdmLinuxRng` based on `rand::rngs::OsRng` implementing the `SpdmRng` trait.
* `linux-evidence` – Provides `SpdmLinuxEvidence`, a minimal mock implementing `SpdmEvidence` returning a <=48 byte static quote.

These helpers live under the `platform_impl` module so they are clearly optional and replaceable for embedded targets.

### Enabling Features

Example enabling all three helpers:

```
cargo add spdm-lib --features "tcp-transport rand-rng linux-evidence"
```

Or in your `Cargo.toml`:

```toml
[dependencies]
spdm-lib = { path = "../spdm-lib", features = ["tcp-transport", "rand-rng", "linux-evidence"] }
```

### TCP Transport Usage (length‑prefixed)

```rust
use spdm_lib::platform_impl::linux::SpdmTcp; // behind `tcp-transport`

fn connect() -> std::io::Result<SpdmTcp> {
	// Establish connection to responder (example address)
	let tcp = SpdmTcp::connect("127.0.0.1:2323")?;
	Ok(tcp)
}
```

`SpdmTcp` implements the `SpdmTransport` trait expected by `SpdmContext`.

### RNG Helper

```rust
use spdm_lib::platform_impl::linux::SpdmLinuxRng; // behind `rand-rng`
use spdm_lib::platform::rng::SpdmRng; // trait

fn random_bytes() -> [u8; 16] {
	let rng = SpdmLinuxRng::default();
	let mut buf = [0u8; 16];
	rng.get_random_bytes(&mut buf).expect("rng failure");
	buf
}
```

### Evidence Helper

```rust
use spdm_lib::platform_impl::linux::SpdmLinuxEvidence; // behind `linux-evidence`
use spdm_lib::platform::evidence::SpdmEvidence; // trait (path illustrative)

fn fetch_quote() -> Vec<u8> {
	let ev = SpdmLinuxEvidence::default();
	let mut buf = [0u8; 64]; // bigger than max; implementation limits to <=48
	let size = ev.evidence_size().unwrap();
	let written = ev.get_evidence(&mut buf[..size]).expect("evidence failure");
	buf[..written].to_vec()
}
```

### Integrating With `SpdmContext`

Construction (simplified – actual context may require additional capability / algorithm configuration):

```rust
use spdm_lib::SpdmContext; // assuming context exposes a constructor in this crate
use spdm_lib::platform_impl::linux::{SpdmTcp, SpdmLinuxRng, SpdmLinuxEvidence};

fn build_context() -> anyhow::Result<SpdmContext<SpdmTcp>> {
	let transport = SpdmTcp::connect("127.0.0.1:2323")?;
	let rng = SpdmLinuxRng::default();
	let evidence = SpdmLinuxEvidence::default();
	// Pseudocode; adjust to actual constructor signature.
	// SpdmContext::new(transport, rng, evidence, /* other deps */)
	todo!("fill in actual constructor usage");
}
```

Replace these platform helpers with your embedded / production implementations by providing your own types that implement the same traits.

### No-Std Note

If you are targeting a `no_std` environment, avoid enabling the above platform features and supply custom implementations that do not depend on `std`.
