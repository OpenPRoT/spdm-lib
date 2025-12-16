// Licensed under the Apache-2.0 license

//! Socket Transport Platform Implementation
//!
//! Provides TCP socket transport compatible with DMTF SPDM validator/emulator

use std::io::{Read, Result as IoResult, Write};
use std::net::TcpStream;

use spdm_lib::codec::MessageBuf;
use spdm_lib::platform::transport::{SpdmTransport, TransportError, TransportResult};

/// Socket platform command types (from DMTF emulator)
// TODO: Doe we have to add elements for ServerHello etc as well?
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
}

impl SpdmSocketTransport {
    /// Create a new socket transport
    pub fn new(stream: TcpStream) -> Self {
        Self { stream }
    }

    /// Receive platform data with socket message header
    fn receive_platform_data(&mut self) -> IoResult<(SocketSpdmCommand, Vec<u8>)> {
        // Read socket message header
        let mut header_bytes = [0u8; 12]; // sizeof(SocketMessageHeader)
        self.stream.read_exact(&mut header_bytes)?;

        let command = u32::from_be_bytes([
            header_bytes[0],
            header_bytes[1],
            header_bytes[2],
            header_bytes[3],
        ]);
        let _transport_type = u32::from_be_bytes([
            header_bytes[4],
            header_bytes[5],
            header_bytes[6],
            header_bytes[7],
        ]);
        let data_size = u32::from_be_bytes([
            header_bytes[8],
            header_bytes[9],
            header_bytes[10],
            header_bytes[11],
        ]);

        let socket_command = SocketSpdmCommand::from(command);

        if data_size > 0 {
            let mut data = vec![0u8; data_size as usize];
            self.stream.read_exact(&mut data)?;
            Ok((socket_command, data))
        } else {
            Ok((socket_command, Vec::new()))
        }
    }

    /// Send platform data with socket message header
    fn send_platform_data(&mut self, command: SocketSpdmCommand, data: &[u8]) -> IoResult<()> {
        // Send header in big-endian format to match validator expectations
        let command_bytes = (command as u32).to_be_bytes();
        let transport_bytes = (3u32).to_be_bytes(); // TCP transport type = 3
        let size_bytes = (data.len() as u32).to_be_bytes();

        self.stream.write_all(&command_bytes)?;
        self.stream.write_all(&transport_bytes)?;
        self.stream.write_all(&size_bytes)?;

        // Send data if any
        if !data.is_empty() {
            self.stream.write_all(data)?;
        }

        self.stream.flush()?;
        Ok(())
    }
}

impl SpdmTransport for SpdmSocketTransport {
    /// This function is only relevant for the SPDM Requester.
    /// Send the SPDM Request encoded into [_req] (header|payload]) via the platform transport
    /// to and SPDM endpoint with EID [_dest_eid].
    fn send_request<'a>(&mut self, dest_eid: u8, req: &mut MessageBuf<'a>) -> TransportResult<()> {
        let message_data = req
            .message_data()
            .map_err(|_| TransportError::BufferTooSmall)?;

        self.send_platform_data(SocketSpdmCommand::Normal, message_data)
            .map_err(|_| TransportError::SendError)?;
        Ok(())
    }

    fn receive_response<'a>(&mut self, rsp: &mut MessageBuf<'a>) -> TransportResult<()> {
        // Err(TransportError::DriverError)
        loop {
            match self.receive_platform_data() {
                Ok((command, data)) => {
                    if !data.is_empty() {
                        match command {
                            SocketSpdmCommand::Normal => {
                                if !data.is_empty() {
                                    rsp.reset();
                                    rsp.put_data(data.len())
                                        .map_err(|_| TransportError::BufferTooSmall)?;

                                    rsp.data_mut(data.len())
                                        .map_err(|_| TransportError::BufferTooSmall)?
                                        .copy_from_slice(&data);

                                    return Ok(());
                                }
                            }

                            SocketSpdmCommand::ClientHello => {}
                            _ => {} // SocketSpdmCommand::Shutdown => {}
                        }
                    }
                }

                Err(_) => {
                    return Err(TransportError::ReceiveError);
                }
            }
        }
    }

    fn receive_request<'a>(&mut self, req: &mut MessageBuf<'a>) -> TransportResult<()> {
        // Handle socket protocol and extract SPDM data
        loop {
            match self.receive_platform_data() {
                Ok((command, data)) => {
                    match command {
                        SocketSpdmCommand::Normal => {
                            if !data.is_empty() {
                                // This is an SPDM message
                                req.reset();
                                let data_len = data.len();
                                req.put_data(data_len)
                                    .map_err(|_| TransportError::BufferTooSmall)?;
                                let buf = req
                                    .data_mut(data_len)
                                    .map_err(|_| TransportError::BufferTooSmall)?;
                                buf.copy_from_slice(&data);
                                return Ok(());
                            } else {
                                // Empty data - send empty response
                                self.send_platform_data(SocketSpdmCommand::Unknown, &[])
                                    .map_err(|_| TransportError::SendError)?;
                                continue;
                            }
                        }
                        SocketSpdmCommand::ClientHello => {
                            // Handle client hello
                            let response = b"Server Hello!";
                            self.send_platform_data(SocketSpdmCommand::ClientHello, response)
                                .map_err(|_| TransportError::SendError)?;
                            continue;
                        }
                        SocketSpdmCommand::Shutdown => {
                            // Send shutdown response first
                            let _ = self.send_platform_data(SocketSpdmCommand::Shutdown, &[]);
                            return Err(TransportError::ReceiveError);
                        }
                        SocketSpdmCommand::Unknown => {
                            self.send_platform_data(SocketSpdmCommand::Unknown, &[])
                                .map_err(|_| TransportError::SendError)?;
                            continue;
                        }
                    }
                }
                Err(_) => {
                    return Err(TransportError::ReceiveError);
                }
            }
        }
    }

    fn send_response<'a>(&mut self, resp: &mut MessageBuf<'a>) -> TransportResult<()> {
        // Extract response data and send with socket protocol
        let message_data = resp
            .message_data()
            .map_err(|_| TransportError::BufferTooSmall)?;
        self.send_platform_data(SocketSpdmCommand::Normal, message_data)
            .map_err(|_| TransportError::SendError)?;
        Ok(())
    }

    fn max_message_size(&self) -> TransportResult<usize> {
        Ok(4096)
    }

    fn header_size(&self) -> usize {
        0 // No additional header for SPDM messages
    }
}
