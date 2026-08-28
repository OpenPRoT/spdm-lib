// Licensed under the Apache-2.0 license

//! SPDM secure session management.
//!
//! Owns the fixed-size session table ([`SessionManager`]) and
//! per-session state ([`SessionInfo`]). Session lifecycle:
//!
//! 1. KEY_EXCHANGE → [`SessionManager::create_session`] →
//!    `HandshakeInProgress`
//! 2. FINISH → state = `Established`, handshake keys destroyed
//! 3. Session used for secured message framing
//! 4. GET_VERSION or error → [`SessionManager::remove_all_and_destroy`]

use core::ops::{Deref, DerefMut};
use spdm_codec::{errors::SPDM_SESSION_LIMIT_EXCEEDED, HeartBeatPeriod, SpdmVersion};
use spdm_traits::{PalResult, SpdmPalHash, SpdmPalIo};

use crate::heartbeat::HEARTBEAT_TIMEOUT_MULTIPLIER;
use crate::key_schedule::{spdm_version_str, KeySchedule};

// ── Session state ───────────────────────────────────────────────────

/// Session lifecycle state.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SessionState {
    /// KEY_EXCHANGE_RSP sent, waiting for FINISH.
    HandshakeInProgress,
    /// FINISH done, data keys active.
    Established,
}

// ── Per-session TH transcript ───────────────────────────────────────

/// Per-session TH transcript hash state.
///
/// Wraps the PAL's running-hash state (`S`) with methods that enforce
/// the correct TH feeding order.
///
/// The TH is started by **forking** (cloning) the connection's
/// running VCA hash state via [`init_from_running`](Self::init_from_running).
/// This ensures the raw VCA message bytes are already consumed in
/// the hash, producing `TH = hash(raw_VCA ‖ …)` as SPDM
/// requires. Handlers then append cert_chain_hash,
/// KEY_EXCHANGE_REQ, KEY_EXCHANGE_RSP, signature, FINISH_REQ, and
/// FINISH_RSP.
///
/// # Heap allocation
///
/// When `S = HashState` (the caliptra-api-lite backend), each
/// `Option<S>` allocates 200 bytes on the global heap via `Box`.
/// One instance exists per session, so N concurrent sessions add
/// `N × 200` bytes of heap for TH. The owning [`SessionInfo`] is also
/// heap-allocated by [`SessionManager::create_session`], so secure
/// session state does not inflate the responder task future while no
/// session is active.
pub struct SessionTranscript<S> {
    th: Option<S>,
}

impl<S> Default for SessionTranscript<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> SessionTranscript<S> {
    pub const fn new() -> Self {
        Self { th: None }
    }

    /// Fork the running VCA hash state into this session's TH.
    ///
    /// The cloned state already contains the raw VCA message bytes
    /// (GET_VERSION ‖ VERSION ‖ … ‖ ALGORITHMS). Subsequent
    /// [`Self::append`] calls add cert_chain_hash, KEY_EXCHANGE_REQ,
    /// KEY_EXCHANGE_RSP, etc., producing the correct TH input:
    ///
    /// ```text
    /// TH = hash(raw_VCA ‖ cert_chain_hash ‖ req ‖ rsp_partial)
    /// ```
    ///
    /// **Do not** feed `hash(VCA)` into a fresh hash — that would
    /// produce `hash(hash(VCA) ‖ …)`, which is incorrect per
    /// SPDM
    pub fn init_from_running<H: SpdmPalHash<State = S>>(
        &mut self,
        hash: &H,
        io: &impl SpdmPalIo,
        running: &S,
    ) -> PalResult<()> {
        self.th = Some(hash.hash_clone(io, running)?);
        Ok(())
    }

    /// Append data to the running TH.
    pub fn append<H: SpdmPalHash<State = S>>(
        &mut self,
        hash: &H,
        io: &impl SpdmPalIo,
        data: &[u8],
    ) -> PalResult<()> {
        let state = self.th.as_mut().ok_or(spdm_errors::codes::INVARIANT)?;
        hash.hash_update(io, state, data)
    }

    /// Clone the running state and finalize the clone to produce a
    /// digest, leaving the original state intact for further appending.
    ///
    /// Used for TH1 (signing) and TH1' (HMAC) snapshots.
    pub fn clone_and_finalize<H: SpdmPalHash<State = S>>(
        &self,
        hash: &H,
        io: &impl SpdmPalIo,
        out: &mut [u8],
    ) -> PalResult<()> {
        let state = self.th.as_ref().ok_or(spdm_errors::codes::INVARIANT)?;
        let mut clone = hash.hash_clone(io, state)?;
        hash.hash_finish(io, &mut clone, out)
    }

    /// Finalize destructively (last use — e.g. TH2).
    pub fn finalize<H: SpdmPalHash<State = S>>(
        &mut self,
        hash: &H,
        io: &impl SpdmPalIo,
        out: &mut [u8],
    ) -> PalResult<()> {
        let state = self.th.as_mut().ok_or(spdm_errors::codes::INVARIANT)?;
        hash.hash_finish(io, state, out)?;
        self.th = None;
        Ok(())
    }
}

// ── SessionInfo ─────────────────────────────────────────────────────

/// Per-session state.
///
/// `K` = [`SpdmPalSessionCrypto::Key`], `S` = [`SpdmPalHash::State`].
pub struct SessionInfo<K: Clone, S> {
    /// Combined session ID: `(rsp_session_id << 16) | req_session_id`.
    pub session_id: u32,
    /// Lifecycle state.
    pub state: SessionState,
    /// Key schedule (owns all CMK handles for this session).
    pub key_schedule: KeySchedule<K>,
    /// Per-session TH transcript hash state.
    pub transcript: SessionTranscript<S>,
    /// HeartbeatPeriod negotiated in KEY_EXCHANGE_RSP. `DISABLED` (zero) means
    /// no liveness watchdog runs for this session.
    pub heartbeat_period: HeartBeatPeriod,
    /// Monotonic ms after which a silent session is torn down. `None` when the
    /// watchdog is not armed.
    pub deadline_ms: Option<u64>,
}

impl<K: Clone, S> Drop for SessionInfo<K, S> {
    fn drop(&mut self) {
        self.key_schedule.destroy_all();
        // NOTE: The physical backing memory slot of this SessionInfo structure in the coordinator pool
        // is guaranteed to be securely zeroized/wiped inside `SpdmBox::drop()` upon slot reclamation.
    }
}

impl<K: Clone, S> SessionInfo<K, S> {
    /// Construct a new `SessionInfo` value. Caller is responsible for
    /// wrapping it in the appropriate box type via the PAL allocator.
    pub fn new(session_id: u32, version: SpdmVersion) -> Self {
        Self {
            session_id,
            state: SessionState::HandshakeInProgress,
            key_schedule: KeySchedule::new(spdm_version_str(version)),
            transcript: SessionTranscript::new(),
            heartbeat_period: HeartBeatPeriod::DISABLED,
            deadline_ms: None,
        }
    }

    /// Timeout window in ms: `HEARTBEAT_TIMEOUT_MULTIPLIER` missed periods.
    fn heartbeat_window_ms(&self) -> Option<u64> {
        if !self.heartbeat_period.is_enabled() {
            return None;
        }
        (self.heartbeat_period.secs() as u64)
            .checked_mul(1000)
            .and_then(|ms| ms.checked_mul(HEARTBEAT_TIMEOUT_MULTIPLIER))
    }

    /// Start the watchdog for a session that has just negotiated a period.
    pub fn arm_heartbeat(&mut self, now_ms: u64) {
        self.deadline_ms = self
            .heartbeat_window_ms()
            .and_then(|window| now_ms.checked_add(window));
    }

    /// Refresh the watchdog after any traffic on this session.
    pub fn touch_heartbeat(&mut self, now_ms: u64) {
        if self.deadline_ms.is_some() {
            self.arm_heartbeat(now_ms);
        }
    }

    /// True when the watchdog is armed and `now_ms` is past the deadline.
    pub fn heartbeat_expired(&self, now_ms: u64) -> bool {
        self.deadline_ms.is_some_and(|deadline| now_ms >= deadline)
    }
}

// ── SessionManager ──────────────────────────────────────────────────

/// Fixed-size session table.
///
/// `K` = key handle, `S` = hash state, `B` = box type wrapping
/// `SessionInfo<K, S>`, `N` = max concurrent sessions.
pub struct SessionManager<K: Clone, S, B, const N: usize> {
    sessions: [Option<B>; N],
    next_rsp_session_id: u16,
    _phantom: core::marker::PhantomData<(K, S)>,
}

impl<K: Clone, S, B, const N: usize> Default for SessionManager<K, S, B, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: Clone, S, B, const N: usize> SessionManager<K, S, B, N> {
    pub fn new() -> Self {
        Self {
            sessions: core::array::from_fn(|_| None),
            next_rsp_session_id: 1,
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<K: Clone, S, B: Deref<Target = SessionInfo<K, S>> + DerefMut, const N: usize>
    SessionManager<K, S, B, N>
{
    /// Allocate a new session slot.
    ///
    /// `alloc_fn` is called to wrap the constructed `SessionInfo` in the
    /// platform box type (e.g., `SpdmBox` from bitmap, or `Box` in tests).
    ///
    /// Returns the combined session ID on success. The session starts
    /// in [`SessionState::HandshakeInProgress`].
    pub fn create_session(
        &mut self,
        req_session_id: u16,
        version: SpdmVersion,
        alloc_fn: impl FnOnce(SessionInfo<K, S>) -> PalResult<B>,
    ) -> PalResult<u32> {
        let slot = self
            .sessions
            .iter()
            .position(|s| s.is_none())
            .ok_or(SPDM_SESSION_LIMIT_EXCEEDED)?;

        // Pick a responder session ID that avoids collision.
        let rsp_id = self.alloc_rsp_session_id(req_session_id)?;
        let session_id = ((rsp_id as u32) << 16) | (req_session_id as u32);

        let info = SessionInfo::new(session_id, version);
        self.sessions[slot] = Some(alloc_fn(info)?);

        Ok(session_id)
    }

    /// Look up a session by combined ID.
    pub fn find(&self, session_id: u32) -> Option<&SessionInfo<K, S>> {
        self.sessions
            .iter()
            .flatten()
            .find(|s| s.session_id == session_id)
            .map(|b| &**b)
    }

    /// Look up a session by combined ID (mutable).
    pub fn find_mut(&mut self, session_id: u32) -> Option<&mut SessionInfo<K, S>> {
        self.sessions
            .iter_mut()
            .flatten()
            .find(|s| s.session_id == session_id)
            .map(|b| &mut **b)
    }

    /// Remove a session and clear all local key blobs.
    pub fn remove_and_destroy(&mut self, session_id: u32) {
        for slot in self.sessions.iter_mut() {
            if slot.as_ref().is_some_and(|s| s.session_id == session_id) {
                if let Some(info) = slot.as_mut() {
                    info.key_schedule.destroy_all();
                }
                *slot = None;
                return;
            }
        }
    }

    /// Remove all sessions and clear all local key blobs.
    pub fn remove_all_and_destroy(&mut self) {
        for slot in self.sessions.iter_mut() {
            if let Some(info) = slot.as_mut() {
                info.key_schedule.destroy_all();
            }
            *slot = None;
        }
    }

    /// Check if any session is in the handshake phase.
    /// Tear down every session whose heartbeat watchdog has expired.
    ///
    /// This stack's transport receive is blocking, so expiry is evaluated
    /// lazily whenever the responder next wakes for a message rather than from
    /// a timer. A session that has gone silent is therefore reclaimed on the
    /// next inbound message, not at the instant its deadline passes.
    pub fn expire_due(&mut self, now_ms: u64) -> usize {
        let mut expired_count = 0;
        for slot in self.sessions.iter_mut() {
            let expired = slot
                .as_ref()
                .is_some_and(|session| session.heartbeat_expired(now_ms));
            if expired {
                if let Some(mut session) = slot.take() {
                    session.key_schedule.destroy_all();
                }
                expired_count += 1;
            }
        }
        expired_count
    }

    /// Earliest armed watchdog deadline across all sessions, if any.
    ///
    /// A transport that can wait with a timeout would sleep until this instant;
    /// with the blocking receive used here it is informational.
    pub fn nearest_deadline_ms(&self) -> Option<u64> {
        self.sessions
            .iter()
            .flatten()
            .filter_map(|session| session.deadline_ms)
            .min()
    }

    pub fn has_handshake_in_progress(&self) -> bool {
        self.sessions
            .iter()
            .flatten()
            .any(|s| s.state == SessionState::HandshakeInProgress)
    }

    /// Allocate a responder session ID that doesn't collide with
    /// existing sessions. Skips ID 0.
    fn alloc_rsp_session_id(&mut self, req_id: u16) -> PalResult<u16> {
        // Try up to N+1 IDs (to handle wrap-around)
        for _ in 0..=N {
            let rsp_id = self.next_rsp_session_id;
            self.next_rsp_session_id = self.next_rsp_session_id.wrapping_add(1);
            if self.next_rsp_session_id == 0 {
                self.next_rsp_session_id = 1;
            }

            let combined = ((rsp_id as u32) << 16) | (req_id as u32);
            let collision = self
                .sessions
                .iter()
                .flatten()
                .any(|s| s.session_id == combined);
            if !collision {
                return Ok(rsp_id);
            }
        }
        Err(SPDM_SESSION_LIMIT_EXCEEDED)
    }
}
