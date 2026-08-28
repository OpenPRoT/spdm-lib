// Licensed under the Apache-2.0 license

//! Host allocator: `SpdmPalAlloc` + `spdm_crypto::ApiAlloc` over the global heap.
//!
//! The embedded PAL uses a bitmap pool over a fixed scratch region; on the host
//! we simply hand out `Box`/`Vec`, which already satisfy the `DerefMut` RAII
//! guard associated types the stack requires.

use core::cell::Cell;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};

use spdm_crypto::ApiAlloc;
use spdm_errors::PalResult;
use spdm_traits::{SpdmPalAlloc, SpdmPalIo};

use super::HostPal;

/// Upper bound on a single in-flight large SPDM message (chunking).
pub const LARGE_CAPACITY: usize = 64 * 1024;

/// Per-connection allocation counters. All allocator entry points bump these;
/// `HostPal`'s `Drop` prints a summary when the session ends.
///
/// Uses `Cell` because every allocator method takes `&self`.
#[derive(Default)]
pub struct AllocStats {
    /// `SpdmPalAlloc::alloc` (typed scratch box) calls.
    pub typed: Cell<u64>,
    /// `SpdmPalAlloc::alloc_bytes` (per-IO byte scratch) calls.
    pub bytes: Cell<u64>,
    /// `SpdmPalAlloc::alloc_large_buf` (chunked large message) calls.
    pub large: Cell<u64>,
    /// `SpdmPalAlloc::alloc_persistent` (session-lifetime object) calls.
    pub persistent: Cell<u64>,
    /// `spdm_crypto::ApiAlloc::alloc` (mailbox scratch) calls.
    pub api: Cell<u64>,
    /// Total bytes requested across `alloc_bytes` / `alloc_large_buf` /
    /// `ApiAlloc::alloc` (the byte-sized allocators).
    pub total_bytes: Cell<u64>,
}

impl AllocStats {
    fn bump(counter: &Cell<u64>) {
        counter.set(counter.get() + 1);
    }

    fn add_bytes(&self, len: usize) {
        self.total_bytes.set(self.total_bytes.get() + len as u64);
    }

    /// Total number of allocation calls across every entry point.
    pub fn total_calls(&self) -> u64 {
        self.typed.get()
            + self.bytes.get()
            + self.large.get()
            + self.persistent.get()
            + self.api.get()
    }

    /// Prints a one-block summary of the allocation activity.
    pub fn report(&self) {
        println!("[poc] ---- allocation summary ----");
        println!("[poc]   alloc (typed box)   : {}", self.typed.get());
        println!("[poc]   alloc_bytes         : {}", self.bytes.get());
        println!("[poc]   alloc_large_buf     : {}", self.large.get());
        println!("[poc]   alloc_persistent    : {}", self.persistent.get());
        println!("[poc]   ApiAlloc::alloc     : {}", self.api.get());
        println!("[poc]   total calls         : {}", self.total_calls());
        println!("[poc]   total bytes (sized) : {}", self.total_bytes.get());
    }
}

/// Heap box that carries the PAL borrow lifetime `'a` so the `SpdmPalAlloc::Box`
/// GAT (`where T: 'a`) is satisfied. On host there is no pool to free into; the
/// inner `Box<T>` owns the value outright.
pub struct HostBox<'a, T> {
    inner: Box<T>,
    _pal: PhantomData<&'a T>,
}

impl<T> Deref for HostBox<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.inner
    }
}

impl<T> DerefMut for HostBox<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl ApiAlloc for HostPal {
    type Buf<'a> = Vec<u8>;

    fn alloc(&self, len: usize) -> PalResult<Self::Buf<'_>> {
        AllocStats::bump(&self.stats.api);
        self.stats.add_bytes(len);
        Ok(vec![0u8; len])
    }
}

impl SpdmPalAlloc for HostPal {
    type Box<'a, T>
        = HostBox<'a, T>
    where
        Self: 'a,
        T: 'a;

    type Bytes<'a>
        = Vec<u8>
    where
        Self: 'a;

    type LargeBuf = Vec<u8>;

    type PersistentBox<T: Sized + 'static> = Box<T>;

    fn alloc<T: Sized>(&self, _io: &impl SpdmPalIo, value: T) -> PalResult<Self::Box<'_, T>> {
        AllocStats::bump(&self.stats.typed);
        Ok(HostBox {
            inner: Box::new(value),
            _pal: PhantomData,
        })
    }

    fn alloc_bytes(&self, _io: &impl SpdmPalIo, len: usize) -> PalResult<Self::Bytes<'_>> {
        AllocStats::bump(&self.stats.bytes);
        self.stats.add_bytes(len);
        Ok(vec![0u8; len])
    }

    fn large_capacity(&self) -> usize {
        LARGE_CAPACITY
    }

    fn alloc_large_buf(&self, len: usize) -> PalResult<Self::LargeBuf> {
        AllocStats::bump(&self.stats.large);
        self.stats.add_bytes(len);
        Ok(vec![0u8; len])
    }

    fn large_buf_into_bytes(
        &self,
        mut buf: Self::LargeBuf,
        len: usize,
    ) -> PalResult<Self::Bytes<'_>> {
        buf.truncate(len);
        Ok(buf)
    }

    fn alloc_persistent<T: Sized + 'static>(&self, value: T) -> PalResult<Self::PersistentBox<T>> {
        AllocStats::bump(&self.stats.persistent);
        Ok(Box::new(value))
    }
}
