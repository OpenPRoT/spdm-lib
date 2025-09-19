// Licensed under the Apache-2.0 license

//! TCP Transport Implementation for SPDM over TCP
//! 
//! This module provides a TCP-based transport implementation for SPDM communication.

use std::net::TcpStream;
use std::io::{Read, Write, ErrorKind};
use crate::platform::transport::SpdmTransport;
use crate::codec::MessageBuf;
use crate::error::{TransportError, TransportResult};

/// TCP-based SPDM transport implementation
pub struct TcpTransport {
    stream: TcpStream,
    header_size: usize,
}

impl TcpTransport {
    /// Create a new TCP transport with the given stream
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            header_size: 4, // SPDM over TCP typically uses 4-byte length header
        }
    }
}

impl SpdmTransport for TcpTransport {
    fn header_size(&self) -> usize {
        self.header_size
    }

    fn receive_request(&mut self, msg_buf: &mut MessageBuf) -> TransportResult<()> {
        // Read the message length header (4 bytes)
        let mut length_bytes = [0u8; 4];
        self.stream.read_exact(&mut length_bytes)
            .map_err(|e| match e.kind() {
                ErrorKind::UnexpectedEof | ErrorKind::ConnectionAborted | ErrorKind::ConnectionReset => {
                    TransportError::ConnectionClosed
                }
                _ => TransportError::IoError(format!("Failed to read message length: {}", e))
            })?;

        let message_length = u32::from_be_bytes(length_bytes) as usize;
        
        // Validate message length
        if message_length == 0 {
            return Err(TransportError::InvalidMessage("Zero-length message".to_string()));
        }
        
        if message_length > 65536 { // Reasonable maximum
            return Err(TransportError::InvalidMessage(
                format!("Message too large: {} bytes", message_length)
            ));
        }

        // Prepare the message buffer
        msg_buf.reset();
        msg_buf.reserve(self.header_size)
            .map_err(|_| TransportError::BufferTooSmall)?;

        // Resize buffer to accommodate the message
        if msg_buf.remaining_capacity() < message_length {
            return Err(TransportError::BufferTooSmall);
        }

        // Read the actual message
        let mut message_data = vec![0u8; message_length];
        self.stream.read_exact(&mut message_data)
            .map_err(|e| match e.kind() {
                ErrorKind::UnexpectedEof | ErrorKind::ConnectionAborted | ErrorKind::ConnectionReset => {
                    TransportError::ConnectionClosed
                }
                _ => TransportError::IoError(format!("Failed to read message data: {}", e))
            })?;

        // Add message to buffer
        msg_buf.append_data(&message_data)
            .map_err(|_| TransportError::BufferTooSmall)?;

        Ok(())
    }

    fn send_response(&mut self, msg_buf: &mut MessageBuf) -> TransportResult<()> {
        let response_data = msg_buf.message_data()
            .map_err(|e| TransportError::InvalidMessage(format!("Invalid response data: {:?}", e)))?;

        // Send length header (4 bytes, big-endian)
        let length = response_data.len() as u32;
        let length_bytes = length.to_be_bytes();
        
        self.stream.write_all(&length_bytes)
            .map_err(|e| match e.kind() {
                ErrorKind::BrokenPipe | ErrorKind::ConnectionAborted | ErrorKind::ConnectionReset => {
                    TransportError::ConnectionClosed
                }
                _ => TransportError::IoError(format!("Failed to send response length: {}", e))
            })?;

        // Send the actual response data
        self.stream.write_all(response_data)
            .map_err(|e| match e.kind() {
                ErrorKind::BrokenPipe | ErrorKind::ConnectionAborted | ErrorKind::ConnectionReset => {
                    TransportError::ConnectionClosed
                }
                _ => TransportError::IoError(format!("Failed to send response data: {}", e))
            })?;

        // Ensure data is sent immediately
        self.stream.flush()
            .map_err(|e| TransportError::IoError(format!("Failed to flush stream: {}", e)))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::io::Write;

    #[test]
    fn test_tcp_transport_creation() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        
        thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let _transport = TcpTransport::new(stream);
        });

        let stream = TcpStream::connect(addr).unwrap();
        let transport = TcpTransport::new(stream);
        assert_eq!(transport.header_size(), 4);
    }

    #[test]
    fn test_tcp_transport_header_size() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        
        thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let transport = TcpTransport::new(stream);
            assert_eq!(transport.header_size(), 4);
        });

        let _stream = TcpStream::connect(addr).unwrap();
    }
}