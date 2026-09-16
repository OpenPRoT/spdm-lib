# Guidance for AI Agents

## Specifications

When encountering this repository for the first time, thoroughly scan, analyze, and, if possible,
cache information from the specification with the latest Major.Minor.Patch version in
https://www.dmtf.org/dsp/DSP0274. Other Major.Minor specifications in
https://www.dmtf.org/dsp/DSP0274 may be scanned and analyzed as needed, always using the latest
Patch version. Cache this information outside of the repository, such as in agent memory or a
local, git-ignored scratch location and do not commit specification text or other derived files into
the working tree.

Specifications in the following URLs are to be scanned and analyzed as needed, always using the
latest Patch version.
- [Secured Messages Using SPDM](https://www.dmtf.org/dsp/DSP0277)
- [Secured Messages using SPDM over MCTP Binding](https://www.dmtf.org/dsp/DSP0276)
- [Security Protocol and Data Model (SPDM) over MCTP Binding](https://www.dmtf.org/dsp/DSP0275)
- [Security Protocol and Data Model (SPDM) Authorization](https://www.dmtf.org/dsp/DSP0289)
- [SPDM over TCP Binding](https://www.dmtf.org/dsp/DSP0287)
- [Security Protocol and Data Model (SPDM) to Storage Binding](https://www.dmtf.org/dsp/DSP0286)

## Conventions

The words `Requester`, `Responder`, and `Integrator`, when used in the context of an SPDM Requester
or Responder and its Integrator, should always be capitalized.

## Repository Layout

A Cargo workspace of `no_std` crates. `Cargo.toml` at the root lists the workspace members and the
directories excluded from the build.

- `errors/`
    - `spdm-errors`. Shared error and result types used by every other crate.
- `codec/`
    - `spdm-codec`. Wire-format encode and decode of SPDM messages, one module per message type,
      including the generic VENDOR_DEFINED envelope. No protocol state, and no vendor-specific
      payload formats — those belong to the Integrator, not this crate.
- `traits/`
    - `spdm-traits`. The interfaces the Integrator implements: cryptography, hashing, certificate
      storage, measurements, session crypto, transport, and the `SpdmPal` platform abstraction.
- `stack/`
    - `spdm-stack`. The protocol state machine and Responder command handlers, one module per SPDM
      request, plus `requester/` for the Requester side, `chunk/` for large-message chunking, and
      `tests/` for the in-crate test suite.
- `placeholders/`
    - Platform-independent stand-ins (`spdm-crypto`, `spdm-transport-sys`, `spdm-console`,
      `spdm-platform`) that let the workspace build and test without an MCU. The Integrator
      replaces these.
- `poc-responder/`
    - A proof-of-concept Responder wiring the stack to the placeholders. Useful as an integration
      example.
- `legacy/`
    - The preserved host-crypto reference monolith. Excluded from the workspace build. Reference
      only; do not modify unless explicitly instructed.
- `mcu-pal/`
    - `spdm-mcu-pal`. The Caliptra-MCU-specific implementation of the `SpdmPal` trait family — DPE,
      Caliptra Core cert chains, mailbox crypto, Tock syscalls. Excluded from the workspace build
      and kept as a reference for the future platform-impl redesign; it is still async and does not
      compile as-is.

## Coding Constraints

This crate is embedded, security-critical firmware and inherits the OpenPRoT review constraints
documented in
[.github/copilot-instructions.md](https://github.com/OpenPRoT/openprot/blob/main/.github/copilot-instructions.md)
and summarized in
[docs/src/coding-style.md](https://github.com/OpenPRoT/openprot/blob/main/docs/src/coding-style.md).
The rules that apply here:

- **`no_std` only.** No heap types (`Vec`, `String`, `HashMap`, `Box`). Use fixed-size arrays and
  `heapless` collections.
- **Panic-free.** No `unwrap`, `expect`, `panic!`, or direct `[]` indexing outside `#[cfg(test)]`
  code. Use `get()`, pattern matching, or return `Result` / `Option`.
- **Checked arithmetic.** Use `checked_*` / `saturating_*` / `wrapping_*` rather than bare `+`, `-`,
  `*` on integers wherever a length, offset, or counter derived from the wire could overflow.
- **`unsafe` blocks require a `// SAFETY:` comment** explaining why the invariants hold.
- **Constant-time crypto.** Compare secrets, transcript hashes, and MACs with [`subtle`], never with
  `==`. Bound the lifetime of secret material with [`zeroize`].
- **Errors must not leak secrets.** Error variants and messages carry no key material, nonce, or
  transcript content.
- **Stack usage is bounded.** Buffers sized for the smallest supported target, not the largest
  message the specification permits.
- **Tests cover error paths.** A new message handler is not complete until the malformed-input and
  rejected-state cases are tested, not just the happy path.
- **No `async`.** This crate was deliberately converted from `async` to synchronous code. Do not
  introduce `async fn`, `.await`, `impl Future`, async traits, or an executor or runtime dependency
  (`embassy`, `tokio`, `futures`, `async-trait`, and the like), and do not reintroduce them when
  porting code from an async source. Blocking or non-blocking I/O is expressed through the
  synchronous `SpdmPal` transport traits; a caller that needs to yield does so around a call into
  the stack, not inside it. If a change appears to require `async`, raise it rather than adding it.

The OpenPRoT rules on volatile MMIO and HAL-mediated register access do not apply: this crate
performs no register access. Hardware reaches it only through the `SpdmPal` traits.

[`subtle`]: https://docs.rs/subtle
[`zeroize`]: https://docs.rs/zeroize

## Commits

These rules override any global or session-level commit attribution defaults.

Three rules govern AI attribution in commit messages. They follow from the fact that the Developer
Certificate of Origin is a certification that **only a human** can make, while generative-AI
assistance must separately be declared with the model and version of the tool used.

1. **Do NOT attribute AI in `Signed-off-by`.** An AI tool must not be named in a `Signed-off-by`
   line, and a contributor must never sign off on behalf of an AI tool. That line is the DCO
   certification: a legal statement that a human makes and takes responsibility for. The human
   contributor remains fully responsible for an AI-assisted contribution, including reviewing and
   understanding all AI-generated code, confirming it is correct and complies with the project's
   license, and certifying the DCO with their own `Signed-off-by` line.
2. **Do NOT attribute AI in `Co-authored-by`.** That trailer marks a co-author of the commit, and
   authorship rests with the human contributors who are responsible for it, not with the AI tool
   that assisted them. Record AI involvement with `Assisted-by` instead.
3. **DO attribute AI in `Assisted-by`.** If a commit was generated or assisted by an AI tool,
   declare it with an `Assisted-by` trailer that includes the tool's name and the model version, in
   the form `Assisted-by: AGENT_NAME:MODEL_VERSION [TOOL1] [TOOL2]`, where `AGENT_NAME` is the name
   of the AI tool or agent, `MODEL_VERSION` is the specific model and version used, and the optional
   bracketed entries are additional specialized analysis tools. Everyday utilities (git, the
   compiler, make, editors, etc.) should be omitted.

Example trailer block:

```
Signed-off-by: Jane Developer <jane.developer@example.com>
Assisted-by: Claude Code:claude-opus-5
```

The `Signed-off-by` line is still required and is still the human contributor's own certification;
the `Assisted-by` line is added in addition to it, never instead of it.
