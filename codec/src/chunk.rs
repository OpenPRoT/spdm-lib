// Licensed under the Apache-2.0 license

//! SPDM chunking wire types.

use zerocopy::{
    little_endian::U16, little_endian::U32, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned,
};

/// CHUNK_SEND sender attribute bit: this is the final chunk.
pub const CHUNK_ATTR_LAST_CHUNK: u8 = 0x01;
/// CHUNK_SEND_ACK receiver attribute bit: an early error was detected.
pub const CHUNK_ACK_ATTR_EARLY_ERROR: u8 = 0x01;

/// CHUNK_RESPONSE body bytes before optional LargeResponseSize and chunk data.
pub const CHUNK_RESPONSE_FIXED_BODY_SIZE: usize = ChunkResponseBody::SIZE;

/// Size of the LargeResponseSize field in the first CHUNK_RESPONSE.
pub const LARGE_RESPONSE_SIZE_FIELD_SIZE: usize = 4;

/// 10-byte CHUNK_SEND request body after the SPDM common header.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct ChunkSendReqBody {
    pub chunk_sender_attr: u8,
    pub handle: u8,
    // TODO
    // SPDM 1.4 extends the sequence number to 32-bit.
    // We leave it at 16-bit for now and error if a larger sequence number is encountered.
    // See: https://github.com/chipsalliance/caliptra-mcu-sw/issues/2165
    pub chunk_seq_num: U16,
    pub reserved: U16,
    pub chunk_size: U32,
}

impl ChunkSendReqBody {
    pub const SIZE: usize = 10;
}

const _: () = assert!(core::mem::size_of::<ChunkSendReqBody>() == ChunkSendReqBody::SIZE);

/// 4-byte CHUNK_SEND_ACK response body after the SPDM common header.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct ChunkSendAckBodyV13 {
    pub chunk_receiver_attr: u8,
    pub handle: u8,
    pub chunk_seq_num: U16,
}

impl ChunkSendAckBodyV13 {
    pub const SIZE: usize = 4;
}

const _: () = assert!(core::mem::size_of::<ChunkSendAckBodyV13>() == ChunkSendAckBodyV13::SIZE);

/// 6-byte CHUNK_SEND_ACK response body after the SPDM common header.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct ChunkSendAckBodyV14 {
    pub chunk_receiver_attr: u8,
    pub handle: u8,
    pub chunk_seq_num: U32,
}

impl ChunkSendAckBodyV14 {
    pub const SIZE: usize = 6;
}

const _: () = assert!(core::mem::size_of::<ChunkSendAckBodyV14>() == ChunkSendAckBodyV14::SIZE);

pub trait ChunkGetReqBody {
    /// Size of the request
    fn size(&self) -> usize;

    /// Get Param1 of the request.
    fn get_param1(&self) -> u8;

    /// Get the chunk handle of the request.
    fn get_handle(&self) -> u8;

    /// Get the chunk sequence number for this request.
    ///
    /// <= SPDM 1.3 sequence numbers are limited to 16-bit.
    fn get_chunk_seq_num(&self) -> u32;
}

/// 4-byte CHUNK_GET request body after the SPDM common header.
///
/// Applicable to SPDM 1.3 and lower.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct ChunkGetReqBodyV13 {
    pub param1: u8,
    pub handle: u8,
    pub chunk_seq_num: U16,
}

impl ChunkGetReqBodyV13 {
    pub const SIZE: usize = 4;
}

impl ChunkGetReqBody for ChunkGetReqBodyV13 {
    fn size(&self) -> usize {
        ChunkGetReqBodyV13::SIZE
    }

    fn get_param1(&self) -> u8 {
        self.param1
    }

    fn get_handle(&self) -> u8 {
        self.handle
    }

    fn get_chunk_seq_num(&self) -> u32 {
        self.chunk_seq_num.get() as u32
    }
}

const _: () = assert!(core::mem::size_of::<ChunkGetReqBodyV13>() == ChunkGetReqBodyV13::SIZE);

/// 6-byte CHUNK_GET v1.4 request body after the SPDM common header.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct ChunkGetReqBodyV14 {
    pub param1: u8,
    pub handle: u8,
    pub chunk_seq_num: U32,
}

impl ChunkGetReqBodyV14 {
    pub const SIZE: usize = 6;
}

impl ChunkGetReqBody for ChunkGetReqBodyV14 {
    fn size(&self) -> usize {
        ChunkGetReqBodyV14::SIZE
    }

    fn get_param1(&self) -> u8 {
        self.param1
    }

    fn get_handle(&self) -> u8 {
        self.handle
    }

    fn get_chunk_seq_num(&self) -> u32 {
        self.chunk_seq_num.get()
    }
}

const _: () = assert!(core::mem::size_of::<ChunkGetReqBodyV14>() == ChunkGetReqBodyV14::SIZE);

/// 10-byte CHUNK_RESPONSE body after the SPDM common header.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct ChunkResponseBody {
    pub chunk_sender_attr: u8,
    pub handle: u8,
    // TODO
    // SPDM 1.4 extends the sequence number to 32-bit.
    // We leave it at 16-bit for now and error if a larger sequence number is encountered.
    // See: https://github.com/chipsalliance/caliptra-mcu-sw/issues/2165
    pub chunk_seq_num: U16,
    pub reserved: U16,
    pub chunk_size: U32,
}

impl ChunkResponseBody {
    pub const SIZE: usize = 10;
}

const _: () = assert!(core::mem::size_of::<ChunkResponseBody>() == ChunkResponseBody::SIZE);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WireReader;

    #[test]
    fn test_chunk_sizes_and_constants() {
        // CHUNK_SEND / CHUNK_RESPONSE: attr(1) + handle(1) + seq(2) + reserved(2) + size(4) = 10.
        assert_eq!(ChunkSendReqBody::SIZE, 10);
        assert_eq!(ChunkResponseBody::SIZE, 10);
        assert_eq!(CHUNK_RESPONSE_FIXED_BODY_SIZE, 10);
        // CHUNK_SEND_ACK: attr(1) + handle(1) + seq(2 in V1.3, 4 in V1.4) = 4 / 6.
        assert_eq!(ChunkSendAckBodyV13::SIZE, 4);
        assert_eq!(ChunkSendAckBodyV14::SIZE, 6);
        // CHUNK_GET: param1(1) + handle(1) + seq(2 in V1.3, 4 in V1.4) = 4 / 6.
        assert_eq!(ChunkGetReqBodyV13::SIZE, 4);
        assert_eq!(ChunkGetReqBodyV14::SIZE, 6);
        assert_eq!(LARGE_RESPONSE_SIZE_FIELD_SIZE, 4);
        assert_eq!(CHUNK_ATTR_LAST_CHUNK, 0x01);
        assert_eq!(CHUNK_ACK_ATTR_EARLY_ERROR, 0x01);
    }

    #[test]
    fn test_chunk_send_req_layout_roundtrip() {
        let body = ChunkSendReqBody {
            chunk_sender_attr: CHUNK_ATTR_LAST_CHUNK,
            handle: 0x07,
            chunk_seq_num: U16::new(0x0102),
            reserved: U16::new(0),
            chunk_size: U32::new(0x1200),
        };
        let bytes = [
            0x01, // attr: LastChunk
            0x07, // handle
            0x02, 0x01, // seq = 0x0102 (little-endian)
            0x00, 0x00, // reserved
            0x00, 0x12, 0x00, 0x00, // chunk_size = 0x1200 (little-endian)
        ];
        assert_eq!(body.as_bytes(), &bytes);

        let parsed = ChunkSendReqBody::ref_from_bytes(&bytes).unwrap();
        assert_eq!(parsed.chunk_sender_attr & CHUNK_ATTR_LAST_CHUNK, 1);
        assert_eq!(parsed.handle, 0x07);
        assert_eq!(parsed.chunk_seq_num.get(), 0x0102);
        assert_eq!(parsed.reserved.get(), 0);
        assert_eq!(parsed.chunk_size.get(), 0x1200);
    }

    #[test]
    fn test_chunk_send_req_max_values() {
        let bytes = [0xFF; 10];
        let parsed = ChunkSendReqBody::ref_from_bytes(&bytes).unwrap();
        assert_eq!(parsed.chunk_seq_num.get(), u16::MAX);
        assert_eq!(parsed.chunk_size.get(), u32::MAX);
    }

    #[test]
    fn test_chunk_send_req_rejects_truncated() {
        // One byte short of the 10-byte body.
        assert!(WireReader::new(&[0u8; 9]).read::<ChunkSendReqBody>().is_err());
        assert!(WireReader::new(&[]).read::<ChunkSendReqBody>().is_err());
    }

    #[test]
    fn test_chunk_send_req_chunk_data_tail() {
        // Body (10) + 4 bytes of chunk data. The reader consumes only the body;
        // the data stays in `rest()`.
        let buf = [
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, // chunk_size = 4
            0xDE, 0xAD, 0xBE, 0xEF,
        ];
        let mut r = WireReader::new(&buf);
        let body: &ChunkSendReqBody = r.read().unwrap();
        assert_eq!(body.chunk_size.get(), 4);
        assert_eq!(r.rest(), &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_chunk_send_req_chunk_size_not_checked_against_buffer() {
        // Pins current leniency: chunk_size (0x1000) says far more data than the
        // 2 bytes present; the struct parse does not cross-check. Callers must.
        let buf = [
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, // chunk_size = 0x1000
            0xAA, 0xBB,
        ];
        let mut r = WireReader::new(&buf);
        let body: &ChunkSendReqBody = r.read().unwrap();
        assert_eq!(body.chunk_size.get(), 0x1000);
        assert_eq!(r.remaining(), 2);
    }

    #[test]
    fn test_chunk_send_req_v14_32bit_seq_is_misparsed_today() {
        // Pins the known TODO above `chunk_seq_num`: a V1.4 sender uses a 4-byte
        // sequence number occupying bytes 2..6. This struct reads only bytes 2..4
        // as the sequence number and bytes 4..6 as `reserved`, so seq 0x0001_0000
        // parses as seq = 0 with reserved = 1.
        let bytes = [
            0x00, 0x01, // attr, handle
            0x00, 0x00, 0x01, 0x00, // 32-bit seq = 0x0001_0000
            0x04, 0x00, 0x00, 0x00, // chunk_size = 4
        ];
        let parsed = ChunkSendReqBody::ref_from_bytes(&bytes).unwrap();
        assert_eq!(parsed.chunk_seq_num.get(), 0);
        assert_eq!(parsed.reserved.get(), 1);
    }

    #[test]
    fn test_chunk_send_ack_v13_layout() {
        let ack = ChunkSendAckBodyV13 {
            chunk_receiver_attr: CHUNK_ACK_ATTR_EARLY_ERROR,
            handle: 0x09,
            chunk_seq_num: U16::new(0xABCD),
        };
        // attr, handle, seq (little-endian, 2 bytes).
        assert_eq!(ack.as_bytes(), &[0x01, 0x09, 0xCD, 0xAB]);
        let parsed = ChunkSendAckBodyV13::ref_from_bytes(ack.as_bytes()).unwrap();
        assert_eq!(parsed.chunk_receiver_attr & CHUNK_ACK_ATTR_EARLY_ERROR, 1);
        assert_eq!(parsed.chunk_seq_num.get(), 0xABCD);

        assert!(WireReader::new(&[0u8; 3]).read::<ChunkSendAckBodyV13>().is_err());
    }

    #[test]
    fn test_chunk_send_ack_v14_layout() {
        let ack = ChunkSendAckBodyV14 {
            chunk_receiver_attr: 0,
            handle: 0x09,
            chunk_seq_num: U32::new(0x0001_0002),
        };
        // attr, handle, seq (little-endian, 4 bytes) — exceeds the V1.3 16-bit range.
        assert_eq!(ack.as_bytes(), &[0x00, 0x09, 0x02, 0x00, 0x01, 0x00]);
        let parsed = ChunkSendAckBodyV14::ref_from_bytes(ack.as_bytes()).unwrap();
        assert_eq!(parsed.chunk_seq_num.get(), 0x0001_0002);

        assert!(WireReader::new(&[0u8; 5]).read::<ChunkSendAckBodyV14>().is_err());
    }

    #[test]
    fn test_chunk_get_v13_via_trait() {
        let bytes = [0x00, 0x05, 0xFF, 0xFF]; // param1, handle, seq = 0xFFFF
        let req = ChunkGetReqBodyV13::ref_from_bytes(&bytes).unwrap();
        let dyn_req: &dyn ChunkGetReqBody = req;
        assert_eq!(dyn_req.size(), 4);
        assert_eq!(dyn_req.get_param1(), 0);
        assert_eq!(dyn_req.get_handle(), 5);
        // 16-bit seq widens to u32 without sign extension or overflow.
        assert_eq!(dyn_req.get_chunk_seq_num(), 0xFFFF);
    }

    #[test]
    fn test_chunk_get_v14_via_trait() {
        let bytes = [0x00, 0x05, 0xFF, 0xFF, 0xFF, 0xFF]; // seq = 0xFFFF_FFFF
        let req = ChunkGetReqBodyV14::ref_from_bytes(&bytes).unwrap();
        let dyn_req: &dyn ChunkGetReqBody = req;
        assert_eq!(dyn_req.size(), 6);
        assert_eq!(dyn_req.get_handle(), 5);
        assert_eq!(dyn_req.get_chunk_seq_num(), u32::MAX);
    }

    #[test]
    fn test_chunk_get_param1_passthrough_and_defaults() {
        // param1 is not validated here; a non-zero value is returned as-is.
        let req = ChunkGetReqBodyV14 {
            param1: 0x80,
            handle: 1,
            chunk_seq_num: U32::new(1),
        };
        assert_eq!(req.get_param1(), 0x80);

        let d13 = ChunkGetReqBodyV13::default();
        let d14 = ChunkGetReqBodyV14::default();
        assert_eq!(d13.as_bytes(), &[0u8; 4]);
        assert_eq!(d14.as_bytes(), &[0u8; 6]);
    }

    #[test]
    fn test_chunk_get_rejects_truncated() {
        assert!(WireReader::new(&[0u8; 3]).read::<ChunkGetReqBodyV13>().is_err());
        assert!(WireReader::new(&[0u8; 5]).read::<ChunkGetReqBodyV14>().is_err());
    }

    #[test]
    fn test_chunk_response_first_chunk_with_large_response_size() {
        // First CHUNK_RESPONSE (seq 0) = fixed body (10) + LargeResponseSize (4) + data (8).
        // Body total = 10 + 4 + 8 = 22 bytes.
        let buf = [
            0x00, 0x03, // attr, handle
            0x00, 0x00, // seq = 0
            0x00, 0x00, // reserved
            0x08, 0x00, 0x00, 0x00, // chunk_size = 8
            0x00, 0x20, 0x00, 0x00, // LargeResponseSize = 0x2000
            1, 2, 3, 4, 5, 6, 7, 8, // chunk data
        ];
        assert_eq!(
            buf.len(),
            CHUNK_RESPONSE_FIXED_BODY_SIZE + LARGE_RESPONSE_SIZE_FIELD_SIZE + 8
        );

        let mut r = WireReader::new(&buf);
        let body: &ChunkResponseBody = r.read().unwrap();
        assert_eq!(body.handle, 3);
        assert_eq!(body.chunk_seq_num.get(), 0);
        assert_eq!(body.chunk_size.get(), 8);
        let large: &U32 = r.read().unwrap();
        assert_eq!(large.get(), 0x2000);
        assert_eq!(r.rest(), &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn test_chunk_response_last_chunk_and_truncation() {
        let body = ChunkResponseBody {
            chunk_sender_attr: CHUNK_ATTR_LAST_CHUNK,
            handle: 2,
            chunk_seq_num: U16::new(3),
            reserved: U16::new(0),
            chunk_size: U32::new(16),
        };
        assert_eq!(
            body.as_bytes(),
            &[0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00]
        );
        assert!(WireReader::new(&body.as_bytes()[..9])
            .read::<ChunkResponseBody>()
            .is_err());
    }
}
