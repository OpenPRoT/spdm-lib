// Licensed under the Apache-2.0 license

//! Requester side of large-response chunking (DSP0274 §10.12): a Responder
//! that cannot fit a response in `DataTransferSize` answers `ERROR(LargeResponse)`
//! with a handle, and the Requester pulls the response with `CHUNK_GET` /
//! `CHUNK_RESPONSE`. An ML-DSA-87 signature alone is 4627 bytes, so any PQC
//! CHALLENGE_AUTH or signed MEASUREMENTS needs this on a small-MTU Responder.
//!
//! The reassembled bytes are the response exactly as if it had arrived whole;
//! the `ERROR` and chunk messages never enter a transcript.

use crate::error::SPDM_LARGE_RESPONSE;
use spdm_codec::{
    ChunkGetReqBodyV13, ChunkGetReqBodyV14, ChunkResponseBody, ReqRespCode, SpdmMsgHdrPdu,
    SpdmVersion, CHUNK_ATTR_LAST_CHUNK, LARGE_RESPONSE_SIZE_FIELD_SIZE,
};
use spdm_errors::{codes::INVARIANT, PalResult};
use spdm_traits::{SpdmPalHash, SpdmPalRng};
use zerocopy::little_endian::{U16, U32};
use zerocopy::{FromBytes, IntoBytes};

use super::{PeerVerifier, RequesterTransport, SpdmRequester};

/// Returns the chunk handle if `msg` is `ERROR(LargeResponse)`.
pub(crate) fn large_response_handle(msg: &[u8]) -> Option<u8> {
    let (hdr, body) = SpdmMsgHdrPdu::ref_from_prefix(msg).ok()?;
    // Body: ErrorCode, ErrorData, then one extended-data byte: the handle.
    (hdr.code == ReqRespCode::ERROR && *body.first()? == SPDM_LARGE_RESPONSE.spec_byte())
        .then(|| body.get(2).copied())
        .flatten()
}

impl<T: RequesterTransport, H: SpdmPalHash, R: SpdmPalRng, V: PeerVerifier>
    SpdmRequester<T, H, R, V>
{
    /// Pulls the large response identified by `handle` into `out`, returning
    /// its length. Fails if the Responder misbehaves (wrong handle or sequence,
    /// short or empty chunk, size mismatch) or the response exceeds `out`.
    pub(crate) fn fetch_large_response(&mut self, handle: u8, out: &mut [u8]) -> PalResult<usize> {
        let version = self.version;
        let mut seq: u32 = 0;
        let mut total: Option<usize> = None;
        let mut got = 0usize;

        loop {
            let mut req = [0u8; SpdmMsgHdrPdu::SIZE + ChunkGetReqBodyV14::SIZE];
            let hdr = SpdmMsgHdrPdu::new(version, ReqRespCode::CHUNK_GET);
            req[..SpdmMsgHdrPdu::SIZE].copy_from_slice(hdr.as_bytes());
            // CHUNK_GET carries a 16-bit sequence number through 1.3, 32-bit from 1.4.
            let len = if version >= SpdmVersion::V14 {
                let body = ChunkGetReqBodyV14 {
                    param1: 0,
                    handle,
                    chunk_seq_num: U32::new(seq),
                };
                req[SpdmMsgHdrPdu::SIZE..].copy_from_slice(body.as_bytes());
                req.len()
            } else {
                let body = ChunkGetReqBodyV13 {
                    param1: 0,
                    handle,
                    chunk_seq_num: U16::new(u16::try_from(seq).map_err(|_| INVARIANT)?),
                };
                let end = SpdmMsgHdrPdu::SIZE + ChunkGetReqBodyV13::SIZE;
                req[SpdmMsgHdrPdu::SIZE..end].copy_from_slice(body.as_bytes());
                end
            };
            self.transport.send(&req[..len])?;

            let n = self.transport.recv(&mut self.buf)?;
            let msg = self.buf.get(..n).ok_or(INVARIANT)?;
            let (hdr, body) = SpdmMsgHdrPdu::ref_from_prefix(msg).map_err(|_| INVARIANT)?;
            if hdr.code != ReqRespCode::CHUNK_RESPONSE || hdr.version != version.to_u8() {
                return Err(INVARIANT);
            }
            let (fixed, mut data) =
                ChunkResponseBody::ref_from_prefix(body).map_err(|_| INVARIANT)?;
            if fixed.handle != handle
                || u32::from(fixed.chunk_seq_num.get()) != seq
                || fixed.reserved.get() != 0
            {
                return Err(INVARIANT);
            }
            if seq == 0 {
                // The first chunk announces the whole response size.
                let (size, rest) = U32::ref_from_prefix(data).map_err(|_| INVARIANT)?;
                let size = usize::try_from(size.get()).map_err(|_| INVARIANT)?;
                if size == 0 || size > out.len() {
                    return Err(INVARIANT);
                }
                total = Some(size);
                data = rest;
                debug_assert_eq!(LARGE_RESPONSE_SIZE_FIELD_SIZE, 4);
            }
            let total = total.ok_or(INVARIANT)?;

            let chunk_size = usize::try_from(fixed.chunk_size.get()).map_err(|_| INVARIANT)?;
            // A chunk must carry data and exactly what it declares.
            if chunk_size == 0 || data.len() != chunk_size {
                return Err(INVARIANT);
            }
            let end = got.checked_add(chunk_size).ok_or(INVARIANT)?;
            out.get_mut(got..end)
                .ok_or(INVARIANT)?
                .copy_from_slice(data);
            got = end;

            let last = fixed.chunk_sender_attr & CHUNK_ATTR_LAST_CHUNK != 0;
            if last || got >= total {
                // LastChunk and the announced size must agree.
                return if last && got == total {
                    Ok(got)
                } else {
                    Err(INVARIANT)
                };
            }
            seq = seq.checked_add(1).ok_or(INVARIANT)?;
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::collections::VecDeque;
    use alloc::vec::Vec;

    use spdm_traits::SpdmPalIo;

    use super::*;
    use crate::requester::RequesterConfig;

    /// Replays canned responses and records what the requester sent.
    struct Script {
        replies: VecDeque<Vec<u8>>,
        sent: Vec<Vec<u8>>,
    }

    impl RequesterTransport for Script {
        fn send(&mut self, msg: &[u8]) -> PalResult<()> {
            self.sent.push(msg.to_vec());
            Ok(())
        }
        fn recv(&mut self, buf: &mut [u8]) -> PalResult<usize> {
            let r = self.replies.pop_front().ok_or(INVARIANT)?;
            buf.get_mut(..r.len()).ok_or(INVARIANT)?.copy_from_slice(&r);
            Ok(r.len())
        }
    }

    // Chunking never touches the transcript, so these are inert.
    struct NoHash;
    impl SpdmPalHash for NoHash {
        type State = ();
        fn hash_init(
            &self,
            _: &impl SpdmPalIo,
            _: spdm_traits::SpdmPalHashAlgo,
            _: &[u8],
        ) -> PalResult<()> {
            Ok(())
        }
        fn hash_update(&self, _: &impl SpdmPalIo, _: &mut (), _: &[u8]) -> PalResult<()> {
            Ok(())
        }
        fn hash_clone(&self, _: &impl SpdmPalIo, _: &()) -> PalResult<()> {
            Ok(())
        }
        fn hash_finish(&self, _: &impl SpdmPalIo, _: &mut (), _: &mut [u8]) -> PalResult<()> {
            Ok(())
        }
    }
    struct NoRng;
    impl SpdmPalRng for NoRng {
        fn fill_random(&self, _: &impl SpdmPalIo, _: &mut [u8]) -> PalResult<()> {
            Ok(())
        }
    }
    struct NoVerify;
    impl PeerVerifier for NoVerify {
        type PubKey = ();
        fn validate_chain(&self, _: &[u8]) -> PalResult<()> {
            Ok(())
        }
        fn verify_p384(&self, _: &(), _: &[u8; 48], _: &[u8]) -> PalResult<()> {
            Ok(())
        }
        fn verify_mldsa87(&self, _: &(), _: &[u8], _: &[u8], _: &[u8]) -> PalResult<()> {
            Ok(())
        }
    }

    const VERSION: SpdmVersion = SpdmVersion::V14;

    /// CHUNK_RESPONSE; `total` is the LargeResponseSize carried by chunk 0 only.
    fn chunk(handle: u8, seq: u16, last: bool, total: Option<u32>, data: &[u8]) -> Vec<u8> {
        let mut m = alloc::vec![VERSION.to_u8(), ReqRespCode::CHUNK_RESPONSE.0];
        m.push(u8::from(last));
        m.push(handle);
        m.extend_from_slice(&seq.to_le_bytes());
        m.extend_from_slice(&[0, 0]);
        m.extend_from_slice(&(data.len() as u32).to_le_bytes());
        if let Some(t) = total {
            m.extend_from_slice(&t.to_le_bytes());
        }
        m.extend_from_slice(data);
        m
    }

    fn requester(replies: Vec<Vec<u8>>) -> SpdmRequester<Script, NoHash, NoRng, NoVerify> {
        let t = Script {
            replies: replies.into(),
            sent: Vec::new(),
        };
        let mut r =
            SpdmRequester::with_config(t, NoHash, NoRng, NoVerify, RequesterConfig::default());
        r.version = VERSION;
        r
    }

    fn fetch(replies: Vec<Vec<u8>>, cap: usize) -> (PalResult<usize>, Vec<u8>, Vec<Vec<u8>>) {
        let mut r = requester(replies);
        let mut out = alloc::vec![0u8; cap];
        let res = r.fetch_large_response(7, &mut out);
        (res, out, r.into_transport().sent)
    }

    #[test]
    fn reassembles_two_chunks_and_asks_in_sequence() {
        let (res, out, sent) = fetch(
            alloc::vec![
                chunk(7, 0, false, Some(6), &[1, 2, 3]),
                chunk(7, 1, true, None, &[4, 5, 6]),
            ],
            16,
        );
        assert_eq!(res, Ok(6));
        assert_eq!(&out[..6], &[1, 2, 3, 4, 5, 6]);
        // v1.4 CHUNK_GET: header, param1 0, handle, 32-bit sequence number.
        assert_eq!(sent[0], [0x14, 0x86, 0, 7, 0, 0, 0, 0]);
        assert_eq!(sent[1], [0x14, 0x86, 0, 7, 1, 0, 0, 0]);
    }

    #[test]
    fn rejects_wrong_handle_and_wrong_sequence() {
        let (res, ..) = fetch(alloc::vec![chunk(8, 0, true, Some(1), &[1])], 16);
        assert!(res.is_err());
        let (res, ..) = fetch(alloc::vec![chunk(7, 1, true, Some(1), &[1])], 16);
        assert!(res.is_err());
        // Second chunk repeats sequence 0.
        let (res, ..) = fetch(
            alloc::vec![
                chunk(7, 0, false, Some(2), &[1]),
                chunk(7, 0, true, None, &[2])
            ],
            16,
        );
        assert!(res.is_err());
    }

    #[test]
    fn rejects_size_problems() {
        // Larger than the output buffer, and a zero announced size.
        let (res, ..) = fetch(alloc::vec![chunk(7, 0, true, Some(32), &[1])], 16);
        assert!(res.is_err());
        let (res, ..) = fetch(alloc::vec![chunk(7, 0, true, Some(0), &[])], 16);
        assert!(res.is_err());
        // An empty non-final chunk would otherwise loop forever.
        let (res, ..) = fetch(alloc::vec![chunk(7, 0, false, Some(4), &[])], 16);
        assert!(res.is_err());
        // LastChunk before the announced size, and data past it.
        let (res, ..) = fetch(alloc::vec![chunk(7, 0, true, Some(4), &[1, 2])], 16);
        assert!(res.is_err());
        let (res, ..) = fetch(alloc::vec![chunk(7, 0, false, Some(2), &[1, 2, 3])], 16);
        assert!(res.is_err());
        // Declared chunk size disagrees with the bytes present.
        let mut bad = chunk(7, 0, true, Some(2), &[1, 2]);
        bad.pop();
        let (res, ..) = fetch(alloc::vec![bad], 16);
        assert!(res.is_err());
    }

    #[test]
    fn rejects_error_and_unrelated_replies() {
        let (res, ..) = fetch(alloc::vec![alloc::vec![0x14, 0x7F, 0x05, 0x00]], 16);
        assert!(res.is_err());
        let (res, ..) = fetch(alloc::vec![alloc::vec![0x14, 0x03, 0, 0, 0, 0]], 16);
        assert!(res.is_err());
        // Version differs from the negotiated one.
        let mut m = chunk(7, 0, true, Some(1), &[1]);
        m[0] = 0x13;
        let (res, ..) = fetch(alloc::vec![m], 16);
        assert!(res.is_err());
    }

    #[test]
    fn pre_1_4_uses_the_16_bit_chunk_get() {
        let t = Script {
            replies: alloc::vec![{
                let mut m = chunk(7, 0, true, Some(1), &[9]);
                m[0] = 0x13;
                m
            }]
            .into(),
            sent: Vec::new(),
        };
        let mut r =
            SpdmRequester::with_config(t, NoHash, NoRng, NoVerify, RequesterConfig::default());
        r.version = SpdmVersion::V13;
        let mut out = [0u8; 4];
        assert_eq!(r.fetch_large_response(7, &mut out), Ok(1));
        assert_eq!(r.into_transport().sent[0], [0x13, 0x86, 0, 7, 0, 0]);
    }

    #[test]
    fn large_response_handle_extracts_the_handle() {
        // v1.4 ERROR, code 0x0F, data 0, extended data = handle 7.
        assert_eq!(
            large_response_handle(&[0x14, 0x7F, 0x0F, 0x00, 0x07]),
            Some(7)
        );
    }

    #[test]
    fn large_response_handle_rejects_other_messages() {
        // Other error code, missing handle, and a non-ERROR message.
        assert_eq!(large_response_handle(&[0x14, 0x7F, 0x05, 0x00, 0x07]), None);
        assert_eq!(large_response_handle(&[0x14, 0x7F, 0x0F, 0x00]), None);
        assert_eq!(large_response_handle(&[0x14, 0x03, 0x0F, 0x00, 0x07]), None);
        assert_eq!(large_response_handle(&[]), None);
    }
}
