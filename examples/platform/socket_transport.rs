// Licensed under the Apache-2.0 license

//! Socket Transport Platform Implementation
//! 
//! Provides TCP socket transport compatible with DMTF SPDM validator/emulator

use std::net::TcpStream;
use std::io::{Read, Write, Result as IoResult};

use spdm_lib::platform::transport::{SpdmTransport, TransportResult, TransportError};
use spdm_lib::codec::MessageBuf;

/// Socket platform command types (from DMTF emulator)
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u32)]
pub enum SocketSpdmCommand {
    Normal = 0x00000001,
    ClientHello = 0x00000003,
    Shutdown = 0x00000004,
    Unknown = 0x00000000,
}

impl From<u32> for SocketSpdmCommand {
    fn from(value: u32) -> Self {
        match value {
            0x00000001 => SocketSpdmCommand::Normal,
            0x00000003 => SocketSpdmCommand::ClientHello,
            0x00000004 => SocketSpdmCommand::Shutdown,
            _ => SocketSpdmCommand::Unknown,
        }
    }
}

/// Socket transport implementation for SPDM over TCP
pub struct SpdmSocketTransport {
    stream: TcpStream,
    raw: bool,
    verbose: bool,
}

impl SpdmSocketTransport {
    const TCP_BINDING_VERSION: u8 = 0x01;
    const TCP_MESSAGE_TYPE_OUT_OF_SESSION: u8 = 0x05;
    const TCP_MESSAGE_TYPE_IN_SESSION: u8 = 0x06;

    /// Create a new socket transport
    pub fn new(stream: TcpStream, raw: bool, verbose: bool) -> Self {
        Self { stream, raw, verbose }
    }

    fn log_bytes(&self, prefix: &str, data: &[u8]) {
        if !self.verbose {
             return;
         }
         print!("{prefix}");
         for b in data {
             print!("{:02x} ", b);
         }
         println!();
     }

    fn log_frame(&self, prefix: &str, header: &[u8], data: &[u8]) {
        if !self.verbose {
            return;
        }
        let mut buf = Vec::with_capacity(header.len() + data.len());
        buf.extend_from_slice(header);
        buf.extend_from_slice(data);
        self.log_bytes(prefix, &buf);
    }

    /// Receive platform data with socket message header
    fn receive_platform_data(&mut self) -> IoResult<(SocketSpdmCommand, Vec<u8>)> {
        // Read socket message header
        let mut header_bytes = [0u8; 12]; // sizeof(SocketMessageHeader)
        self.stream.read_exact(&mut header_bytes)?;
        
        let command = u32::from_be_bytes([header_bytes[0], header_bytes[1], header_bytes[2], header_bytes[3]]);
        let _transport_type = u32::from_be_bytes([header_bytes[4], header_bytes[5], header_bytes[6], header_bytes[7]]);
        let data_size = u32::from_be_bytes([header_bytes[8], header_bytes[9], header_bytes[10], header_bytes[11]]);
        
        let socket_command = SocketSpdmCommand::from(command);
        
        if data_size > 0 {
            let mut data = vec![0u8; data_size as usize];
            self.stream.read_exact(&mut data)?;
            self.log_frame("RX frame: ", &header_bytes, &data);
            Ok((socket_command, data))
         } else {
            self.log_frame("RX frame: ", &header_bytes, &[]);
             Ok((socket_command, Vec::new()))
         }
     }

    /// Send platform data with socket message header
    fn send_platform_data(&mut self, command: SocketSpdmCommand, data: &[u8]) -> IoResult<()> {
        // Send header in big-endian format to match validator expectations
        let command_bytes = (command as u32).to_be_bytes();
        let transport_bytes = if self.raw { 0u32 } else { 3u32 }.to_be_bytes(); // NONE when raw, TCP=3 otherwise
        let size_bytes = (data.len() as u32).to_be_bytes();
        
        self.stream.write_all(&command_bytes)?;
        self.stream.write_all(&transport_bytes)?;
        self.stream.write_all(&size_bytes)?;
        
        // Send data if any
        if !data.is_empty() {
            self.stream.write_all(data)?;
        }

        // Log full frame (header + payload)
        let mut header = Vec::with_capacity(12);
        header.extend_from_slice(&command_bytes);
        header.extend_from_slice(&transport_bytes);
        header.extend_from_slice(&size_bytes);
        self.log_frame("TX frame: ", &header, data);

         self.stream.flush()?;
         Ok(())
     }
}

impl SpdmTransport for SpdmSocketTransport {
    fn send_request<'a>(&mut self, _dest_eid: u8, _req: &mut MessageBuf<'a>) -> TransportResult<()> {
        // Not used in responder mode
        Err(TransportError::DriverError)
    }

    fn receive_response<'a>(&mut self, _rsp: &mut MessageBuf<'a>) -> TransportResult<()> {
        // Not used in responder mode
        Err(TransportError::DriverError)
    }

    fn receive_request<'a>(&mut self, req: &mut MessageBuf<'a>) -> TransportResult<()> {
        // Handle socket protocol and extract SPDM data
        loop {
            match self.receive_platform_data() {
                Ok((command, data)) => {
                    match command {
                        SocketSpdmCommand::Normal => {
                            if self.raw {
                                if data.is_empty() {
                                    self.send_platform_data(SocketSpdmCommand::Unknown, &[]).map_err(|_| TransportError::SendError)?;
                                    continue;
                                }
                                req.reset();
                                req.put_data(data.len()).map_err(|_| TransportError::BufferTooSmall)?;
                                let buf = req.data_mut(data.len()).map_err(|_| TransportError::BufferTooSmall)?;
                                buf.copy_from_slice(&data);
                                return Ok(());
                            }
                            // Expect SPDM-over-TCP binding header: payload_length (LE, includes version+type+payload), version, type
                            if data.len() < 4 {
                                self.send_platform_data(SocketSpdmCommand::Unknown, &[]).map_err(|_| TransportError::SendError)?;
                                continue;
                            }
                            let payload_len = u16::from_le_bytes([data[0], data[1]]) as usize;
                            let binding_version = data[2];
                            let message_type = data[3];

                            // payload_length = 2 (version+type) + SPDM_payload
                            let expected_total = payload_len + 2;
                            if binding_version != Self::TCP_BINDING_VERSION
                                || payload_len < 2
                                || data.len() != expected_total
                            {
                                self.send_platform_data(SocketSpdmCommand::Unknown, &[]).map_err(|_| TransportError::SendError)?;
                                continue;
                            }

                            // Allow both in-session and out-of-session; in-session must carry at least session_id (4 bytes)
                            let spdm_payload = &data[4..];
                            let spdm_payload_len = spdm_payload.len();
                            let valid_type = match message_type {
                                Self::TCP_MESSAGE_TYPE_OUT_OF_SESSION => true,
                                Self::TCP_MESSAGE_TYPE_IN_SESSION => spdm_payload_len >= 4,
                                _ => false,
                            };
                            if !valid_type || spdm_payload_len + 2 != payload_len {
                                self.send_platform_data(SocketSpdmCommand::Unknown, &[]).map_err(|_| TransportError::SendError)?;
                                continue;
                            }

                            req.reset();
                            req.put_data(spdm_payload_len).map_err(|_| TransportError::BufferTooSmall)?;
                            let buf = req.data_mut(spdm_payload_len).map_err(|_| TransportError::BufferTooSmall)?;
                            buf.copy_from_slice(spdm_payload);
                            return Ok(());
                        },
                        SocketSpdmCommand::ClientHello => {
                            // Handle client hello
                            let response = b"Server Hello!";
                            self.send_platform_data(SocketSpdmCommand::ClientHello, response).map_err(|_| TransportError::SendError)?;
                            continue;
                        },
                        SocketSpdmCommand::Shutdown => {
                             // Send shutdown response first
                             let _ = self.send_platform_data(SocketSpdmCommand::Shutdown, &[]);
                             return Err(TransportError::ReceiveError);
                        },
                        SocketSpdmCommand::Unknown => {
                            self.send_platform_data(SocketSpdmCommand::Unknown, &[]).map_err(|_| TransportError::SendError)?;
                            continue; 
                        }
                    }
                },
                Err(_) => {
                    return Err(TransportError::ReceiveError);
                }
            }
        }
    }

    fn send_response<'a>(&mut self, resp: &mut MessageBuf<'a>) -> TransportResult<()> {
        // Extract response data and send with socket protocol
        let message_data = resp.message_data().map_err(|_| TransportError::BufferTooSmall)?;

        if self.raw {
            self.send_platform_data(SocketSpdmCommand::Normal, message_data).map_err(|_| TransportError::SendError)?;
            return Ok(());
        }

        // Heuristic: SPDM header has version in high nibble == 0x1; otherwise assume in-session (session_id-prefixed)
        let msg_type = if message_data.first().map(|b| (b >> 4) == 0x1).unwrap_or(false) {
            Self::TCP_MESSAGE_TYPE_OUT_OF_SESSION
        } else if message_data.len() >= 4 {
            Self::TCP_MESSAGE_TYPE_IN_SESSION
        } else {
            return Err(TransportError::SendError);
        };

        let payload_len = (message_data.len() + 2) as u16; // version + type + payload
        let mut framed = Vec::with_capacity(4 + message_data.len());
        framed.extend_from_slice(&payload_len.to_le_bytes());
        framed.push(Self::TCP_BINDING_VERSION);
        framed.push(msg_type);
        framed.extend_from_slice(message_data);

        self.send_platform_data(SocketSpdmCommand::Normal, &framed).map_err(|_| TransportError::SendError)?;
        Ok(())
    }

    fn max_message_size(&self) -> TransportResult<usize> {
        Ok(4096)
    }

    fn header_size(&self) -> usize {
        0 // No additional header for SPDM messages
    }
}