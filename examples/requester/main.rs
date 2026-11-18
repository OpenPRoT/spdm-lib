// Licensed under the Apache-2.0 license

//! Host SPDM requester proof-of-concept (VCA milestone).
//!
//! Connects to an SPDM responder over TCP using the DMTF spdm-emu socket
//! framing (SOCKET_TRANSPORT_TYPE_NONE), performs the spdm-emu client-hello
//! handshake, then drives the VCA flow (GET_VERSION / GET_CAPABILITIES /
//! NEGOTIATE_ALGORITHMS) via `spdm_stack::requester::SpdmRequester` and prints
//! the negotiated parameters.

use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;

mod pal;

use spdm_codec::SpdmVersion;
use spdm_errors::{codes::INVARIANT, PalResult};
use spdm_stack::requester::{RequesterConfig, RequesterTransport, SpdmRequester};

use pal::{demo_trust_anchors, HostHash, HostRng, HostVerifier};

const DEFAULT_PORT: u16 = 2323;

/// SPDM versions this Requester negotiates, highest first.
const SPDM_VERSIONS: &[SpdmVersion] = &[SpdmVersion::V14, SpdmVersion::V13, SpdmVersion::V12];

// spdm-emu socket command codes.
const CMD_NORMAL: u32 = 0x0000_0001;
const CMD_TEST: u32 = 0x0000_DEAD;
const TRANSPORT_TYPE_NONE: u32 = 0x0000_0000;
const SOCKET_HDR_LEN: usize = 12;

/// spdm-emu socket transport (client side).
struct SocketTransport {
    stream: TcpStream,
}

impl SocketTransport {
    fn send_frame(&mut self, command: u32, payload: &[u8]) -> std::io::Result<()> {
        let mut hdr = [0u8; SOCKET_HDR_LEN];
        hdr[0..4].copy_from_slice(&command.to_be_bytes());
        hdr[4..8].copy_from_slice(&TRANSPORT_TYPE_NONE.to_be_bytes());
        hdr[8..12].copy_from_slice(&(payload.len() as u32).to_be_bytes());
        self.stream.write_all(&hdr)?;
        if !payload.is_empty() {
            self.stream.write_all(payload)?;
        }
        self.stream.flush()
    }

    fn recv_frame(&mut self) -> std::io::Result<(u32, Vec<u8>)> {
        let mut hdr = [0u8; SOCKET_HDR_LEN];
        self.stream.read_exact(&mut hdr)?;
        let command = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
        let size = u32::from_be_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]) as usize;
        let mut payload = vec![0u8; size];
        if size > 0 {
            self.stream.read_exact(&mut payload)?;
        }
        Ok((command, payload))
    }

    /// Performs the spdm-emu client-hello handshake.
    fn client_hello(&mut self) -> std::io::Result<()> {
        self.send_frame(CMD_TEST, b"Client Hello!\0")?;
        let (_cmd, data) = self.recv_frame()?;
        println!(
            "[req] socket handshake: got {:?}",
            String::from_utf8_lossy(&data)
        );
        Ok(())
    }
}

impl RequesterTransport for SocketTransport {
    fn send(&mut self, msg: &[u8]) -> PalResult<()> {
        println!("[req] -> {}", spdm_name(msg));
        self.send_frame(CMD_NORMAL, msg).map_err(|_| INVARIANT)
    }

    fn recv(&mut self, buf: &mut [u8]) -> PalResult<usize> {
        let (_cmd, data) = self.recv_frame().map_err(|_| INVARIANT)?;
        println!("[req] <- {}", spdm_name(&data));
        if data.len() > buf.len() {
            return Err(INVARIANT);
        }
        buf[..data.len()].copy_from_slice(&data);
        Ok(data.len())
    }
}

/// Decode an SPDM message code byte to a name for logging.
fn spdm_name(msg: &[u8]) -> String {
    if msg.len() < 2 {
        return format!("<{} bytes>", msg.len());
    }
    let name = match msg[1] {
        0x84 => "GET_VERSION",
        0x04 => "VERSION",
        0xE1 => "GET_CAPABILITIES",
        0x61 => "CAPABILITIES",
        0xE3 => "NEGOTIATE_ALGORITHMS",
        0x63 => "ALGORITHMS",
        0x81 => "GET_DIGESTS",
        0x01 => "DIGESTS",
        0x82 => "GET_CERTIFICATE",
        0x02 => "CERTIFICATE",
        0x83 => "CHALLENGE",
        0x03 => "CHALLENGE_AUTH",
        0xE0 => "GET_MEASUREMENTS",
        0x60 => "MEASUREMENTS",
        0x7F => "ERROR",
        0x86 => "CHUNK_GET",
        0x06 => "CHUNK_RESPONSE",
        _ => "UNKNOWN",
    };
    format!("{name} (v1.{}, {} bytes)", msg[0] & 0x0f, msg.len())
}

fn main() {
    let Args {
        port,
        trust_anchors,
    } = parse_args();
    let addr = ("127.0.0.1", port);

    let stream = match TcpStream::connect(addr) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[req] connect to 127.0.0.1:{port} failed: {e}");
            std::process::exit(1);
        }
    };
    println!("[req] connected to 127.0.0.1:{port}");

    let mut transport = SocketTransport { stream };
    if let Err(e) = transport.client_hello() {
        eprintln!("[req] client-hello handshake failed: {e}");
        std::process::exit(1);
    }

    let config = RequesterConfig {
        versions: SPDM_VERSIONS,
        ..RequesterConfig::default()
    };
    let mut requester = SpdmRequester::with_config(
        transport,
        HostHash,
        HostRng,
        HostVerifier::new(trust_anchors),
        config,
    );
    let n = match requester.negotiate() {
        Ok(n) => {
            println!("[req] VCA complete:");
            println!("[req]   version          : {}", n.version.spec_str());
            println!(
                "[req]   peer flags       : 0x{:08x}",
                n.peer_flags.into_bits()
            );
            println!(
                "[req]   peer DTS / maxmsg: {} / {}",
                n.peer_data_transfer_size, n.peer_max_spdm_msg_size
            );
            println!(
                "[req]   base_asym_sel    : 0x{:08x}",
                n.base_asym_sel.into_bits()
            );
            println!(
                "[req]   pqc_asym_sel     : 0x{:08x}",
                n.pqc_asym_sel.into_bits()
            );
            println!(
                "[req]   base_hash_sel    : 0x{:08x}",
                n.base_hash_sel.into_bits()
            );
            n
        }
        Err(e) => {
            eprintln!("[req] VCA failed: {e:08x}");
            std::process::exit(1);
        }
    };
    let _ = n;

    // Attestation: DIGESTS → CERTIFICATE → CHALLENGE → MEASUREMENTS, with cert
    // chain validation and signature verification.
    match requester.attest(0) {
        Ok(att) => {
            println!("[req] attestation complete:");
            println!("[req]   measurement blocks : {}", att.measurement_blocks);
            println!("[req]   signatures verified: {}", att.verified);
            println!("[req] SPDM full flow completed successfully");
        }
        Err(e) => {
            eprintln!("[req] attestation failed: {e:08x}");
            std::process::exit(1);
        }
    }
}

struct Args {
    port: u16,
    /// DER root certificates to trust; the demo roots when none are given.
    trust_anchors: Vec<Vec<u8>>,
}

fn parse_args() -> Args {
    let mut port = DEFAULT_PORT;
    let mut trust_anchors = Vec::new();
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-p" | "--port" => {
                let v = args.next().unwrap_or_default();
                port = v.parse().unwrap_or_else(|_| {
                    eprintln!("[req] invalid port: {v}");
                    std::process::exit(1);
                });
            }
            "--root" => {
                let path = args.next().unwrap_or_default();
                trust_anchors.push(std::fs::read(&path).unwrap_or_else(|e| {
                    eprintln!("[req] cannot read root certificate {path}: {e}");
                    std::process::exit(1);
                }));
            }
            "-h" | "--help" => {
                println!(
                    "usage: poc-requester [--port <PORT>] [--root <ROOT.der>]...\n  \
                     --port  default {DEFAULT_PORT}\n  \
                     --root  trust this DER root certificate (repeatable); replaces the\n          \
                     built-in demo roots, which only the poc-responder uses"
                );
                std::process::exit(0);
            }
            other => {
                eprintln!("[req] unknown argument: {other}");
                std::process::exit(1);
            }
        }
    }
    if trust_anchors.is_empty() {
        trust_anchors = demo_trust_anchors();
    }
    Args {
        port,
        trust_anchors,
    }
}
