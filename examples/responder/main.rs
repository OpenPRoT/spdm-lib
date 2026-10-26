// Licensed under the Apache-2.0 license

//! Host SPDM responder proof-of-concept.
//!
//! Runs the `spdm-stack` responder against the DMTF `spdm-emu` over TCP
//! (SOCKET_TRANSPORT_TYPE_NONE). All platform behaviour is supplied by a single
//! [`HostPal`] that carries the socket transport internally and uses host crypto
//! (sha2 / p384 / rand). VDM is disabled (`NoVdmBackend`, the stack default).

mod pal;

use std::env;
use std::net::TcpListener;

use spdm_stack::SpdmStack;

use pal::HostPal;

const DEFAULT_PORT: u16 = 2323;

fn main() {
    let port = parse_port();

    let listener = match TcpListener::bind(("0.0.0.0", port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[poc] failed to bind port {port}: {e}");
            std::process::exit(1);
        }
    };
    println!("[poc] SPDM responder listening on 0.0.0.0:{port}");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let peer = stream
                    .peer_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|_| "<unknown>".into());
                println!("[poc] client connected: {peer}");

                let pal = HostPal::new(stream);
                let mut stack: SpdmStack<HostPal> = SpdmStack::new(pal);
                match stack.run() {
                    Ok(()) => println!("[poc] session with {peer} ended"),
                    Err(e) => println!("[poc] session with {peer} closed: {e:08x}"),
                }
            }
            Err(e) => eprintln!("[poc] accept error: {e}"),
        }
    }
}

fn parse_port() -> u16 {
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-p" | "--port" => {
                if let Some(v) = args.next() {
                    if let Ok(p) = v.parse() {
                        return p;
                    }
                    eprintln!("[poc] invalid port: {v}");
                    std::process::exit(1);
                }
            }
            "-h" | "--help" => {
                println!("usage: poc-responder [--port <PORT>]  (default {DEFAULT_PORT})");
                std::process::exit(0);
            }
            other => {
                eprintln!("[poc] unknown argument: {other}");
                std::process::exit(1);
            }
        }
    }
    DEFAULT_PORT
}
