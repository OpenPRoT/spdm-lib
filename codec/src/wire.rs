// Licensed under the Apache-2.0 license

//! Cursor-style sync wire I/O over zerocopy types.
//!
//! Every wire field in spdm-lib is modelled as a `#[repr(C)]`
//! [`zerocopy::Unaligned`] struct, so the only cursor operations a
//! handler needs are:
//!
//! - "write this whole struct at the current position"
//! - "read a reference to a struct of this type at the current
//!   position"
//! - "advance / retrieve raw bytes" for opaque blobs (cert chain,
//!   nonce, …).
//!
//! Errors are a single ZST so `Result<T, WireError>` shares the same
//! niche as `PalResult<T>` after enum-niche optimisation.

use core::mem::size_of;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct WireError;

/// Borrow-only writer over a caller-owned `&mut [u8]`.
pub struct WireWriter<'b> {
    buf: &'b mut [u8],
    pos: usize,
}

impl<'b> WireWriter<'b> {
    #[inline]
    pub fn new(buf: &'b mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    #[inline]
    pub fn position(&self) -> usize {
        self.pos
    }

    #[inline]
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Reserve `n` bytes for in-place population (length-prefixed
    /// payloads or crypto output buffers).
    #[inline]
    pub fn reserve(&mut self, n: usize) -> Result<&mut [u8], WireError> {
        let start = self.pos;
        let end = start.checked_add(n).ok_or(WireError)?;
        let slice = self.buf.get_mut(start..end).ok_or(WireError)?;
        self.pos = end;
        Ok(slice)
    }

    /// Write a whole zerocopy value at the current position.
    #[inline]
    pub fn write<T: IntoBytes + Immutable + ?Sized>(&mut self, v: &T) -> Result<(), WireError> {
        let bytes = v.as_bytes();
        let dst = self.reserve(bytes.len())?;
        for (d, s) in dst.iter_mut().zip(bytes) {
            *d = *s;
        }
        Ok(())
    }

    /// Write raw bytes (transcript material, opaque blobs, etc.).
    pub fn write_bytes(&mut self, b: &[u8]) -> Result<(), WireError> {
        self.write(b)
    }

    /// Pad with `n` zero bytes (spec Reserved fields).
    pub fn pad_zero(&mut self, n: usize) -> Result<(), WireError> {
        let dst = self.reserve(n)?;
        dst.fill(0);
        Ok(())
    }

    /// Truncate the cursor back to a known length.
    #[inline]
    pub fn truncate(&mut self, len: usize) {
        debug_assert!(len <= self.pos);
        self.pos = len;
    }

    /// Consume the writer and return the populated prefix.
    #[inline]
    pub fn into_bytes(self) -> &'b [u8] {
        &self.buf[..self.pos]
    }

    /// Consume the writer and return the populated prefix mutably.
    #[inline]
    pub fn into_bytes_mut(self) -> &'b mut [u8] {
        &mut self.buf[..self.pos]
    }
}

/// Borrow-only reader over a caller-owned `&[u8]`.
pub struct WireReader<'b> {
    buf: &'b [u8],
    pos: usize,
}

impl<'b> WireReader<'b> {
    #[inline]
    pub fn new(buf: &'b [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    #[inline]
    pub fn position(&self) -> usize {
        self.pos
    }

    #[inline]
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Borrow a `T` at the current position and advance the cursor by
    /// `size_of::<T>()`.
    pub fn read<T>(&mut self) -> Result<&'b T, WireError>
    where
        T: FromBytes + KnownLayout + Unaligned + Immutable,
    {
        let n = size_of::<T>();
        let bytes = self.take(n)?;
        T::ref_from_bytes(bytes).map_err(|_| WireError)
    }

    /// Take `n` raw bytes (opaque blobs, signatures, transcript
    /// material).
    pub fn take(&mut self, n: usize) -> Result<&'b [u8], WireError> {
        if self.remaining() < n {
            return Err(WireError);
        }
        let start = self.pos;
        self.pos += n;
        Ok(&self.buf[start..self.pos])
    }

    /// Skip `n` bytes; bounds-checked.
    pub fn skip(&mut self, n: usize) -> Result<(), WireError> {
        let _ = self.take(n)?;
        Ok(())
    }

    /// Returns the unread tail of the buffer without consuming it.
    #[inline]
    pub fn rest(&self) -> &'b [u8] {
        &self.buf[self.pos..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ReqRespCode, SpdmMsgHdrPdu, SpdmVersion};

    // ---- WireWriter ----------------------------------------------------------

    #[test]
    fn test_writer_write_advances_position_and_tracks_remaining() {
        let mut buf = [0xFFu8; 8];
        let mut w = WireWriter::new(&mut buf);
        assert_eq!(w.position(), 0);
        assert_eq!(w.remaining(), 8);

        // Common header is 2 bytes: 8 - 2 = 6 remaining.
        w.write(&SpdmMsgHdrPdu::new(SpdmVersion::V12, ReqRespCode::VERSION))
            .unwrap();
        assert_eq!(w.position(), 2);
        assert_eq!(w.remaining(), 6);

        // 3 more raw bytes: position 2 + 3 = 5, remaining 8 - 5 = 3.
        w.write_bytes(&[1, 2, 3]).unwrap();
        assert_eq!(w.position(), 5);
        assert_eq!(w.remaining(), 3);

        assert_eq!(w.into_bytes(), &[0x12, 0x04, 1, 2, 3]);
    }

    #[test]
    fn test_writer_exact_fit_then_full() {
        let mut buf = [0u8; 2];
        let mut w = WireWriter::new(&mut buf);
        w.write_bytes(&[0xAA, 0xBB]).unwrap();
        assert_eq!(w.remaining(), 0);
        // A zero-length write at a full buffer is fine; one more byte is not.
        assert!(w.write_bytes(&[]).is_ok());
        assert_eq!(w.write_bytes(&[0xCC]), Err(WireError));
    }

    #[test]
    fn test_writer_empty_buffer_rejects_any_write() {
        let mut buf: [u8; 0] = [];
        let mut w = WireWriter::new(&mut buf);
        assert_eq!(w.remaining(), 0);
        assert_eq!(w.write_bytes(&[1]), Err(WireError));
        assert!(w.into_bytes().is_empty());
    }

    #[test]
    fn test_writer_failed_write_changes_nothing() {
        let mut buf = [0xFFu8; 3];
        let mut w = WireWriter::new(&mut buf);
        w.write_bytes(&[1, 2]).unwrap();

        // 2 bytes requested, only 1 left: must fail without a partial write.
        assert_eq!(w.write_bytes(&[9, 9]), Err(WireError));
        assert_eq!(w.position(), 2);
        assert_eq!(w.remaining(), 1);
        assert_eq!(buf, [1, 2, 0xFF]);
    }

    #[test]
    fn test_writer_reserve_is_overflow_safe() {
        let mut buf = [0u8; 4];
        let mut w = WireWriter::new(&mut buf);
        // start (0) + usize::MAX does not overflow but is far past the buffer.
        assert!(w.reserve(usize::MAX).is_err());
        assert_eq!(w.position(), 0);

        // start (1) + usize::MAX overflows usize; checked_add must catch it.
        w.write_bytes(&[1]).unwrap();
        assert!(w.reserve(usize::MAX).is_err());
        assert_eq!(w.position(), 1);
    }

    #[test]
    fn test_writer_reserve_allows_in_place_population() {
        let mut buf = [0xFFu8; 4];
        let mut w = WireWriter::new(&mut buf);
        w.reserve(3).unwrap().copy_from_slice(&[1, 2, 3]);
        assert_eq!(w.position(), 3);
        assert_eq!(w.into_bytes(), &[1, 2, 3]);
    }

    #[test]
    fn test_writer_pad_zero_overwrites_and_is_bounded() {
        let mut buf = [0xFFu8; 4];
        let mut w = WireWriter::new(&mut buf);
        w.write_bytes(&[0xAA]).unwrap();
        w.pad_zero(2).unwrap();
        assert_eq!(w.position(), 3);

        // 2 requested, 1 left: rejected, position unchanged.
        assert_eq!(w.pad_zero(2), Err(WireError));
        assert_eq!(w.position(), 3);
        // Padding replaced the 0xFF fill; the untouched tail is still 0xFF.
        assert_eq!(buf, [0xAA, 0x00, 0x00, 0xFF]);
    }

    #[test]
    fn test_writer_truncate_rewinds_and_allows_rewrite() {
        let mut buf = [0u8; 4];
        let mut w = WireWriter::new(&mut buf);
        w.write_bytes(&[1, 2, 3, 4]).unwrap();
        w.truncate(2);
        assert_eq!(w.position(), 2);
        assert_eq!(w.remaining(), 2);
        w.write_bytes(&[9]).unwrap();
        assert_eq!(w.into_bytes(), &[1, 2, 9]);

        let mut buf = [0u8; 2];
        let mut w = WireWriter::new(&mut buf);
        w.write_bytes(&[1, 2]).unwrap();
        w.truncate(0);
        assert!(w.into_bytes().is_empty());
    }

    // Pins current behavior: the "len <= pos" check is a debug_assert, so only
    // debug builds catch a forward truncate. A release build would silently move
    // the cursor forward over unwritten bytes (and a len past the buffer would
    // later panic in `into_bytes`/underflow in `remaining`).
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic]
    fn test_writer_truncate_past_position_panics_in_debug() {
        let mut buf = [0u8; 4];
        let mut w = WireWriter::new(&mut buf);
        w.write_bytes(&[1]).unwrap();
        w.truncate(3);
    }

    #[test]
    fn test_writer_into_bytes_mut_exposes_only_written_prefix() {
        let mut buf = [0u8; 4];
        let mut w = WireWriter::new(&mut buf);
        w.write_bytes(&[1, 2]).unwrap();
        let prefix = w.into_bytes_mut();
        assert_eq!(prefix.len(), 2);
        prefix[0] = 0x7F;
        assert_eq!(buf, [0x7F, 2, 0, 0]);
    }

    // ---- WireReader ----------------------------------------------------------

    #[test]
    fn test_reader_read_struct_advances_and_failed_read_does_not() {
        let buf = [0x12, 0x04, 0xAA];
        let mut r = WireReader::new(&buf);
        assert_eq!(r.position(), 0);
        assert_eq!(r.remaining(), 3);
        assert!(!r.is_empty());

        let hdr: &SpdmMsgHdrPdu = r.read().unwrap();
        assert_eq!(hdr.version, 0x12);
        assert_eq!(hdr.code, ReqRespCode::VERSION);
        // Header is 2 bytes: position 2, remaining 3 - 2 = 1.
        assert_eq!(r.position(), 2);
        assert_eq!(r.remaining(), 1);

        // A second 2-byte read needs 2 but only 1 is left: error, cursor stays.
        assert!(r.read::<SpdmMsgHdrPdu>().is_err());
        assert_eq!(r.position(), 2);
        assert_eq!(r.rest(), &[0xAA]);

        assert_eq!(r.take(1).unwrap(), &[0xAA]);
        assert!(r.is_empty());
    }

    #[test]
    fn test_reader_empty_buffer() {
        let mut r = WireReader::new(&[]);
        assert!(r.is_empty());
        assert!(r.read::<SpdmMsgHdrPdu>().is_err());
        assert!(r.take(0).unwrap().is_empty());
        assert!(r.rest().is_empty());
    }

    #[test]
    fn test_reader_take_and_skip_are_bounded_and_overflow_safe() {
        let buf = [1u8, 2, 3, 4];
        let mut r = WireReader::new(&buf);

        assert_eq!(r.take(2).unwrap(), &[1, 2]);
        // 3 requested, 2 left: error, cursor unchanged.
        assert_eq!(r.take(3), Err(WireError));
        assert_eq!(r.position(), 2);

        // usize::MAX must not overflow `pos + n`.
        assert_eq!(r.take(usize::MAX), Err(WireError));
        assert_eq!(r.skip(usize::MAX), Err(WireError));
        assert_eq!(r.position(), 2);

        r.skip(1).unwrap();
        assert_eq!(r.rest(), &[4]);
        assert!(r.skip(2).is_err());
        r.skip(1).unwrap();
        assert!(r.is_empty());
    }

    #[test]
    fn test_reader_rest_does_not_consume() {
        let buf = [1u8, 2, 3];
        let mut r = WireReader::new(&buf);
        r.skip(1).unwrap();
        assert_eq!(r.rest(), &[2, 3]);
        assert_eq!(r.rest(), &[2, 3]);
        assert_eq!(r.position(), 1);
    }

    #[test]
    fn test_writer_reader_roundtrip() {
        let mut buf = [0u8; 6];
        let mut w = WireWriter::new(&mut buf);
        w.write(&SpdmMsgHdrPdu::new(SpdmVersion::V13, ReqRespCode::DIGESTS))
            .unwrap();
        w.write_bytes(&[0xDE, 0xAD, 0xBE, 0xEF]).unwrap();
        let written = w.into_bytes();
        // 2-byte header + 4 payload bytes = 6.
        assert_eq!(written.len(), 6);

        let mut r = WireReader::new(written);
        let hdr: &SpdmMsgHdrPdu = r.read().unwrap();
        assert_eq!(hdr.version, 0x13);
        assert_eq!(hdr.code, ReqRespCode::DIGESTS);
        assert_eq!(r.rest(), &[0xDE, 0xAD, 0xBE, 0xEF]);
    }
}
