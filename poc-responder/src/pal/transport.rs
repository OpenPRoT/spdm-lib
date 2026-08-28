// Licensed under the Apache-2.0 license

//! spdm-emu TCP socket transport (SOCKET_TRANSPORT_TYPE_NONE).
//!
//! Ported from the legacy `socket_transport.rs` example, adapted to the new
//! `SpdmPalIoTransport` / `SpdmPalIo` traits.
//!
//! Wire framing (DMTF spdm-emu common protocol): every message is a 12-byte
//! big-endian header `{ command:u32, transport_type:u32, payload_size:u32 }`
//! followed by `payload_size` bytes. In NONE mode the payload is the raw SPDM
//! message with no additional transport header, so `header_size()` is 0.

use std::io::{Read, Write};

use spdm_errors::{codes::INVARIANT, PalErrorCode, PalResult};
use spdm_traits::{SpdmPalIo, SpdmPalIoKind, SpdmPalIoTransport};

use super::HostPal;

// spdm-emu socket command codes (spdm_emu_common/command.h).
const CMD_NORMAL: u32 = 0x0000_0001;
const CMD_CLIENT_HELLO: u32 = 0x0000_0003;
const CMD_STOP: u32 = 0x0000_0004;
const CMD_TEST: u32 = 0x0000_DEAD;

// spdm-emu transport type: NONE (raw SPDM payload, no MCTP/DOE header).
const TRANSPORT_TYPE_NONE: u32 = 0x0000_0000;

const SOCKET_HDR_LEN: usize = 12;

/// Human-readable name for an SPDM request/response code (DSP0274 Table 4).
/// The code is byte 1 of the SPDM message (byte 0 is the version).
fn spdm_code_name(code: u8) -> &'static str {
    match code {
        // Requests
        0x84 => "GET_VERSION",
        0xE1 => "GET_CAPABILITIES",
        0xE3 => "NEGOTIATE_ALGORITHMS",
        0x81 => "GET_DIGESTS",
        0x82 => "GET_CERTIFICATE",
        0x83 => "CHALLENGE",
        0xE0 => "GET_MEASUREMENTS",
        0x85 => "CHUNK_SEND",
        0x86 => "CHUNK_GET",
        0xE4 => "KEY_EXCHANGE",
        0xE5 => "FINISH",
        0xE6 => "PSK_EXCHANGE",
        0xE7 => "PSK_FINISH",
        0xEC => "END_SESSION",
        0xEE => "SET_CERTIFICATE",
        0xFE => "VENDOR_DEFINED_REQUEST",
        // Responses
        0x04 => "VERSION",
        0x61 => "CAPABILITIES",
        0x63 => "ALGORITHMS",
        0x01 => "DIGESTS",
        0x02 => "CERTIFICATE",
        0x03 => "CHALLENGE_AUTH",
        0x60 => "MEASUREMENTS",
        0x05 => "CHUNK_SEND_ACK",
        0x06 => "CHUNK_RESPONSE",
        0x64 => "KEY_EXCHANGE_RSP",
        0x65 => "FINISH_RSP",
        0x6C => "END_SESSION_ACK",
        0x6E => "SET_CERTIFICATE_RSP",
        0x7E => "VENDOR_DEFINED_RESPONSE",
        0x7F => "ERROR",
        _ => "UNKNOWN",
    }
}

/// Preview the first `n` bytes of a buffer as hex, for compact logging.
fn hex_preview(buf: &[u8], n: usize) -> String {
    let take = buf.len().min(n);
    let mut s = String::new();
    for (i, b) in buf[..take].iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        s.push_str(&format!("{b:02x}"));
    }
    if buf.len() > take {
        s.push_str(" ...");
    }
    s
}

/// Logs one decoded SPDM message (`dir` is "req"/"rsp"). Byte 0 is the SPDM
/// version, byte 1 the request/response code.
fn log_spdm(dir: &str, msg: &[u8]) {
    if msg.len() < 2 {
        println!("[poc] {dir}: <{} bytes, too short to decode>", msg.len());
        return;
    }
    let version = msg[0];
    let code = msg[1];
    let name = spdm_code_name(code);
    let error = if code == 0x7F {
        "  *** ERROR PDU ***"
    } else {
        ""
    };
    println!(
        "[poc] {dir}  {name} (v1.{}, code 0x{code:02x}, {} bytes){error}",
        version & 0x0f,
        msg.len(),
    );
    println!("[poc]      {}", hex_preview(msg, 16));
}

/// A received SPDM request frame (NONE mode: payload is pure SPDM).
pub struct HostIo {
    data: Vec<u8>,
}

impl SpdmPalIo for HostIo {
    fn kind(&self) -> SpdmPalIoKind {
        // NONE mode carries only plain SPDM messages.
        SpdmPalIoKind::Message
    }

    fn request(&self) -> &[u8] {
        &self.data
    }
}

impl HostPal {
    /// Reads one spdm-emu framed message: `(command, payload)`.
    fn recv_frame(&self) -> PalResult<(u32, Vec<u8>)> {
        let mut stream = self.stream.borrow_mut();

        let mut hdr = [0u8; SOCKET_HDR_LEN];
        stream.read_exact(&mut hdr).map_err(|_| INVARIANT)?;

        let command = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
        let payload_size = u32::from_be_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]) as usize;

        let mut payload = vec![0u8; payload_size];
        if payload_size > 0 {
            stream.read_exact(&mut payload).map_err(|_| INVARIANT)?;
        }
        Ok((command, payload))
    }

    /// Writes one spdm-emu framed message.
    fn send_frame(&self, command: u32, payload: &[u8]) -> PalResult<()> {
        let mut stream = self.stream.borrow_mut();

        let mut hdr = [0u8; SOCKET_HDR_LEN];
        hdr[0..4].copy_from_slice(&command.to_be_bytes());
        hdr[4..8].copy_from_slice(&TRANSPORT_TYPE_NONE.to_be_bytes());
        hdr[8..12].copy_from_slice(&(payload.len() as u32).to_be_bytes());

        stream.write_all(&hdr).map_err(|_| INVARIANT)?;
        if !payload.is_empty() {
            stream.write_all(payload).map_err(|_| INVARIANT)?;
        }
        stream.flush().map_err(|_| INVARIANT)?;
        Ok(())
    }
}

impl SpdmPalIoTransport for HostPal {
    type Io<'a> = HostIo;

    fn secure_message_supported(&self) -> bool {
        false
    }

    fn header_size(&self) -> usize {
        0
    }

    fn mtu(&self) -> usize {
        // spdm-emu default max buffer; the stack caps DataTransferSize by this.
        //
        // NOTE: a smaller mtu forces oversized responses (cert chain,
        // measurements) down the chunking path — the responder correctly emits
        // a LARGE_RESPONSE error + chunk handle, but the large staging buffer
        // (`alloc_large_buf`) is only allocated once the requester follows up
        // with CHUNK_GET/CHUNK_SEND. The legacy requester example does not
        // implement that follow-up, so chunking can't be exercised end-to-end
        // yet. This is a requester-side gap to fix as the responder is ported
        // forward, not a responder bug.
        4096
    }

    fn recv_request(&self) -> PalResult<Self::Io<'_>> {
        // Drive the spdm-emu socket protocol until a real SPDM message arrives.
        loop {
            let (command, payload) = self.recv_frame()?;
            match command {
                CMD_NORMAL => {
                    if payload.is_empty() {
                        // Empty normal frame — nothing to dispatch; ask again.
                        self.send_frame(CMD_NORMAL, &[])?;
                        continue;
                    }
                    log_spdm("<- req", &payload);
                    return Ok(HostIo { data: payload });
                }
                CMD_TEST => {
                    // spdm-emu handshake ("Client Hello!" -> "Server Hello!").
                    println!("[poc] socket: TEST (client hello) -> replying Server Hello");
                    self.send_frame(CMD_TEST, b"Server Hello!\0")?;
                }
                CMD_CLIENT_HELLO => {
                    println!("[poc] socket: CLIENT_HELLO -> replying Server Hello");
                    self.send_frame(CMD_CLIENT_HELLO, b"Server Hello!")?;
                }
                CMD_STOP => {
                    println!("[poc] socket: STOP -> closing connection");
                    let _ = self.send_frame(CMD_STOP, &[]);
                    // Signal a fatal transport error so the run loop exits.
                    return Err(PalErrorCode::kernel(0));
                }
                other => {
                    // Unknown command: echo an empty stop and keep going.
                    println!("[poc] socket: unknown command 0x{other:08x} -> sending STOP");
                    self.send_frame(CMD_STOP, &[])?;
                }
            }
        }
    }

    fn send_response(
        &self,
        _io: &Self::Io<'_>,
        _kind: SpdmPalIoKind,
        msg: &mut [u8],
    ) -> PalResult<()> {
        // header_size() == 0, so `msg` is the raw SPDM payload.
        log_spdm("-> rsp", msg);
        self.send_frame(CMD_NORMAL, msg)
    }
}
