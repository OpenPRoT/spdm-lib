// Licensed under the Apache-2.0 license

//! Host allocator: `SpdmPalAlloc` + `spdm_crypto::ApiAlloc` over the global heap.
//!
//! The embedded PAL uses a bitmap pool over a fixed scratch region; on the host
//! we simply hand out `Box`/`Vec`, which already satisfy the `DerefMut` RAII
//! guard associated types the stack requires.

use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};

use spdm_crypto::ApiAlloc;
use spdm_error::PalResult;
use spdm_traits::{SpdmPalAlloc, SpdmPalIo};

use super::HostPal;

/// Upper bound on a single in-flight large SPDM message (chunking).
pub const LARGE_CAPACITY: usize = 64 * 1024;

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
        Ok(HostBox {
            inner: Box::new(value),
            _pal: PhantomData,
        })
    }

    fn alloc_bytes(&self, _io: &impl SpdmPalIo, len: usize) -> PalResult<Self::Bytes<'_>> {
        Ok(vec![0u8; len])
    }

    fn large_capacity(&self) -> usize {
        LARGE_CAPACITY
    }

    fn alloc_large_buf(&self, len: usize) -> PalResult<Self::LargeBuf> {
        Ok(vec![0u8; len])
    }

    fn alloc_persistent<T: Sized + 'static>(&self, value: T) -> PalResult<Self::PersistentBox<T>> {
        Ok(Box::new(value))
    }
}
