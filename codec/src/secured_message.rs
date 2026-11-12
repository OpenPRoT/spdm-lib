// Licensed under the Apache-2.0 license

//! Secured SPDM message framing.
//!
//! Wire layout:
//! ```text
//! [ session_id(4) | length(2) | encrypted_data(N) | tag(16) ]
//! ```
//!
//! Plaintext inside `encrypted_data`:
//! ```text
//! [ app_data_length(2) | app_data(M) ]
//! ```
//!
//! AAD = `session_id(4) || length(2)` (no sequence number on wire).

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::WireError;

/// AES-256-GCM authentication tag size.
pub const AES_256_GCM_TAG_SIZE: usize = 16;

/// Secured message header size (session_id + length).
pub const SECURED_MSG_HDR_SIZE: usize = 6;

/// Secured message header (session_id + length), parsed from
/// incoming secured messages.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug)]
#[repr(C)]
pub struct SecuredMessageHeader {
    pub session_id: [u8; 4],
    pub length: [u8; 2],
}

const _: () = assert!(core::mem::size_of::<SecuredMessageHeader>() == SECURED_MSG_HDR_SIZE);

impl SecuredMessageHeader {
    /// Session ID as u32 (little-endian).
    #[inline]
    pub fn session_id_u32(&self) -> u32 {
        u32::from_le_bytes(self.session_id)
    }

    /// Length field as u16 (little-endian).
    /// This is `encrypted_data_len + tag_len`.
    #[inline]
    pub fn length_u16(&self) -> u16 {
        u16::from_le_bytes(self.length)
    }
}

/// Encode the AAD (Associated Authenticated Data) for AEAD.
///
/// AAD = session_id(4, LE) || length(2, LE).
pub fn encode_aad(session_id: u32, length: u16, out: &mut [u8]) -> Result<(), WireError> {
    let (header, _) = SecuredMessageHeader::mut_from_prefix(out).map_err(|_| WireError)?;
    *header = SecuredMessageHeader {
        session_id: session_id.to_le_bytes(),
        length: length.to_le_bytes(),
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secured_message_constants() {
        // session_id(4) + length(2) = 6; AES-256-GCM tag = 16.
        assert_eq!(SECURED_MSG_HDR_SIZE, 6);
        assert_eq!(AES_256_GCM_TAG_SIZE, 16);
    }

    #[test]
    fn test_secured_header_parse() {
        // A record carrying 10 bytes of app data:
        //   plaintext      = app_data_length(2) + app_data(10) = 12
        //   header length  = encrypted_data(12) + tag(16)      = 28 = 0x1C
        let bytes = [
            0x78, 0x56, 0x34, 0x12, // session_id = 0x12345678 (little-endian)
            0x1C, 0x00, // length = 28 (little-endian)
        ];
        let (hdr, rest) = SecuredMessageHeader::ref_from_prefix(&bytes).unwrap();
        assert_eq!(hdr.session_id_u32(), 0x1234_5678);
        assert_eq!(hdr.length_u16(), 28);
        assert_eq!(hdr.length_u16() as usize, 2 + 10 + AES_256_GCM_TAG_SIZE);
        assert!(rest.is_empty());
    }

    #[test]
    fn test_secured_header_parse_leaves_payload_in_rest() {
        let mut buf = [0xEEu8; SECURED_MSG_HDR_SIZE + 4];
        buf[..6].copy_from_slice(&[0x01, 0x00, 0x00, 0x00, 0x04, 0x00]);
        let (hdr, rest) = SecuredMessageHeader::ref_from_prefix(&buf).unwrap();
        assert_eq!(hdr.session_id_u32(), 1);
        assert_eq!(hdr.length_u16(), 4);
        assert_eq!(rest, &[0xEE; 4]);
    }

    #[test]
    fn test_secured_header_parse_rejects_short() {
        // Header is 6 bytes; 5 is one short.
        assert!(SecuredMessageHeader::ref_from_prefix(&[0u8; 5]).is_err());
        assert!(SecuredMessageHeader::ref_from_prefix(&[]).is_err());
    }

    #[test]
    fn test_secured_header_length_not_validated() {
        // Pins current leniency: the header decodes `length` (0) even though a
        // valid record needs at least the 16-byte tag, and it does not compare
        // `length` against the bytes actually present. Callers must do both.
        let bytes = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00];
        let (hdr, _) = SecuredMessageHeader::ref_from_prefix(&bytes).unwrap();
        assert_eq!(hdr.length_u16(), 0);

        let big = [0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xAA];
        let (hdr, rest) = SecuredMessageHeader::ref_from_prefix(&big).unwrap();
        assert_eq!(hdr.length_u16(), u16::MAX);
        assert_eq!(rest.len(), 1);
    }

    #[test]
    fn test_encode_aad_exact_buffer() {
        let mut out = [0u8; SECURED_MSG_HDR_SIZE];
        encode_aad(0x1234_5678, 28, &mut out).unwrap();
        // session_id LE, then length LE (28 = 0x1C).
        assert_eq!(out, [0x78, 0x56, 0x34, 0x12, 0x1C, 0x00]);
    }

    #[test]
    fn test_encode_aad_larger_buffer_only_touches_header() {
        let mut out = [0xAAu8; 8];
        encode_aad(0x0000_0001, 0x0100, &mut out).unwrap();
        // First 6 bytes written (id = 1, length = 0x0100 -> 00 01); last 2 untouched.
        assert_eq!(out, [0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0xAA, 0xAA]);
    }

    #[test]
    fn test_encode_aad_too_small_leaves_buffer_untouched() {
        for len in 0..SECURED_MSG_HDR_SIZE {
            let mut out = [0xAAu8; SECURED_MSG_HDR_SIZE];
            assert!(encode_aad(1, 2, &mut out[..len]).is_err(), "len {len}");
            assert_eq!(out, [0xAA; SECURED_MSG_HDR_SIZE], "len {len}");
        }
    }

    #[test]
    fn test_encode_aad_extremes_and_roundtrip() {
        for (id, len) in [
            (0u32, 0u16),
            (1, 1),
            (0x0100_0000, 0x0001), // byte-order check: only the top id byte set
            (u32::MAX, u16::MAX),
        ] {
            let mut out = [0u8; SECURED_MSG_HDR_SIZE];
            encode_aad(id, len, &mut out).unwrap();
            let (hdr, _) = SecuredMessageHeader::ref_from_prefix(&out).unwrap();
            assert_eq!(hdr.session_id_u32(), id);
            assert_eq!(hdr.length_u16(), len);
        }

        let mut out = [0u8; SECURED_MSG_HDR_SIZE];
        encode_aad(u32::MAX, u16::MAX, &mut out).unwrap();
        assert_eq!(out, [0xFF; 6]);
    }
}
