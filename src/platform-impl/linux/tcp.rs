// Licensed under the Apache-2.0 license

//! TCP transport implementation for SPDM (Linux), behind the `tcp-transport` feature.
//! Blocking implementation intended for host/testing usage.

#![cfg(feature = "tcp-transport")]

use core::time::Duration;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};

use crate::codec::MessageBuf;
use crate::platform::transport::{SpdmTransport, TransportError, TransportResult};

pub struct SpdmTcp {
    stream: TcpStream,
    max_msg: usize,
    header_len: usize,
}

impl SpdmTcp {
    pub fn connect<A: ToSocketAddrs>(addr: A) -> TransportResult<Self> {
        let stream = TcpStream::connect(addr).map_err(|_| TransportError::DriverError)?;
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5))); 
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
        Ok(Self { stream, max_msg: 4096, header_len: 2 })
    }

    pub fn from_stream(stream: TcpStream) -> Self { Self { stream, max_msg: 4096, header_len: 2 } }
    pub fn set_max_message_size(&mut self, size: usize) { self.max_msg = size; }
}

impl SpdmTransport for SpdmTcp {
    fn send_request<'a>(&mut self, _dest_eid: u8, req: &mut MessageBuf<'a>) -> TransportResult<()> { self.send_internal(req) }
    fn receive_response<'a>(&mut self, rsp: &mut MessageBuf<'a>) -> TransportResult<()> { self.recv_internal(rsp) }
    fn receive_request<'a>(&mut self, req: &mut MessageBuf<'a>) -> TransportResult<()> { self.recv_internal(req) }
    fn send_response<'a>(&mut self, resp: &mut MessageBuf<'a>) -> TransportResult<()> { self.send_internal(resp) }
    fn max_message_size(&self) -> TransportResult<usize> { Ok(self.max_msg) }
    fn header_size(&self) -> usize { self.header_len }
}

impl SpdmTcp {
    fn send_internal<'a>(&mut self, msg: &mut MessageBuf<'a>) -> TransportResult<()> {
        let len = msg.msg_len();
        if len > self.max_msg { return Err(TransportError::BufferTooSmall); }
        let len_hdr = (len as u16).to_le_bytes();
        self.stream.write_all(&len_hdr).map_err(|_| TransportError::SendError)?;
        let data = msg.data(len).map_err(|_| TransportError::BufferTooSmall)?;
        self.stream.write_all(data).map_err(|_| TransportError::SendError)?;
        Ok(())
    }
    fn recv_internal<'a>(&mut self, msg: &mut MessageBuf<'a>) -> TransportResult<()> {
        msg.reset();
        let mut hdr = [0u8; 2];
        self.stream.read_exact(&mut hdr).map_err(|_| TransportError::ReceiveError)?;
        let len = u16::from_le_bytes(hdr) as usize;
        if len > self.max_msg { return Err(TransportError::BufferTooSmall); }
        msg.put_data(len).map_err(|_| TransportError::BufferTooSmall)?;
        let dst = msg.data_mut(len).map_err(|_| TransportError::BufferTooSmall)?;
        self.stream.read_exact(dst).map_err(|_| TransportError::ReceiveError)?;
        msg.pull_data(len).map_err(|_| TransportError::BufferTooSmall)?;
        Ok(())
    }
}
