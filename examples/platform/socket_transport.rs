// Licensed under the Apache-2.0 license

//! Socket Transport Platform Implementation
//!
//! Provides TCP socket transport compatible with DMTF SPDM validator/emulator of type SOCKET_TRANSPORT_TYPE_NONE.
// Defined in DMTF Spec [DSP0287](https://www.dmtf.org/sites/default/files/standards/documents/DSP0287_1.0.0.pdf) "SPDM over TCP Binding Specification".

use std::io::{Read, Result as IoResult, Write};
use std::net::TcpStream;

use clap::{Parser, ValueEnum};
use spdm_lib::codec::{Codec, CodecError, CommonCodec, MessageBuf};
use spdm_lib::platform::transport::{SpdmTransport, TransportError, TransportResult};
use zerocopy::byteorder::{BigEndian, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::platform;

/// Socket platform command types (from DMTF emulator)
/// This is **NOT** part of the official DMTF spec, but is necessary to implement
/// [SocketTransportType::None].
///
/// # Protocol Flow
/// 1. Requester: Send (SOCKET_SPDM_COMMAND_TEST, b'Client Hello') to Responder
/// 2. Responder: Send (SOCKET_SPDM_COMMAND_TEST, b'Server Hello') to Requester

#[repr(u32)]
#[allow(unused)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Socket Command definitions.
///
/// See [spdm-emu/spdm_emu_common/command.h](https://github.com/DMTF/spdm-emu/blob/main/spdm_emu/spdm_emu_common/command.h).
pub enum SocketSpdmCommand {
    Normal = 0x00000001,
    ClientHello = 0x00000003,
    // Shutdown = 0x00000004,
    Shutdown = 0xFFFE,
    // Unknown = 0x00000000,
    Unknown = 0xFFFF,
    Test = 0xDEAD,
}

impl From<u32> for SocketSpdmCommand {
    fn from(value: u32) -> Self {
        match value {
            0x00000001 => SocketSpdmCommand::Normal,
            0x00000003 => SocketSpdmCommand::ClientHello,
            0x00000004 => SocketSpdmCommand::Shutdown,
            0xdead => SocketSpdmCommand::Test,
            _ => SocketSpdmCommand::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, ValueEnum)]
#[repr(u32)]
#[allow(non_camel_case_types, unused)]
pub enum SocketTransportType {
    /// SOCKET_TRANSPORT_TYPE_NONE
    None = 0x00,
    MCTP = 0x01,
    PCI_DOE = 0x02,
    TCP = 0x03,
}

impl From<u32> for SocketTransportType {
    fn from(value: u32) -> Self {
        match value {
            0x00 => SocketTransportType::None,
            0x01 => SocketTransportType::MCTP,
            0x02 => SocketTransportType::PCI_DOE,
            0x03 => SocketTransportType::TCP,
            _ => SocketTransportType::None,
        }
    }
}

pub enum SocketMessageHeaderError {
    Reserved,
}

/// Socket transport implementation for SPDM over TCP
pub struct SpdmSocketTransport {
    stream: TcpStream,
    transport_type: SocketTransportType,
}

type BeU32 = U32<BigEndian>;

/// Socket Command Header that is used when using transport `SOCKET_TRANSPORT_TYPE_NONE`.
/// The payload of the according SPM message is appended to this.
#[repr(C)]
pub struct SocketSpdmCommandHdr {
    /// SPDM-EMU custom socket command.
    command: SocketSpdmCommand,
    transport_type: SocketTransportType,

    /// Size of the appended SPDM message payload
    payload_size: BeU32,
}

impl From<&[u8; 12]> for SocketSpdmCommandHdr {
    fn from(value: &[u8; 12]) -> Self {
        let command_bytes: [u8; 4] = [value[0], value[1], value[2], value[3]];
        let transport_bytes: [u8; 4] = [value[4], value[5], value[6], value[7]];
        let payload_bytes: [u8; 4] = [value[8], value[9], value[10], value[11]];

        SocketSpdmCommandHdr {
            command: SocketSpdmCommand::from(u32::from_be_bytes(command_bytes)),
            transport_type: SocketTransportType::from(u32::from_be_bytes(transport_bytes)),
            payload_size: BeU32::new(u32::from_be_bytes(payload_bytes)),
        }
    }
}

impl Into<[u8; 12]> for SocketSpdmCommandHdr {
    fn into(self) -> [u8; 12] {
        let mut result = [0u8; 12];
        result[0..4].copy_from_slice(&(self.command as u32).to_be_bytes());
        result[4..8].copy_from_slice(&(self.transport_type as u32).to_be_bytes());
        result[8..12].copy_from_slice(&self.payload_size.get().to_be_bytes());
        result
    }
}

#[repr(u8)]
pub enum SpdmSocketTransportError {
    /// The PayloadLen in the last received message is too large to be processed by the endpoint.
    PayloadLenTooLong = 0xC0,

    /// The BindingVer in the last received message is not supported by the endpoint.
    /// The binding version supported by the endpoint is indicated in the BindingVer
    /// field of this message with MessageType of 0xC1.
    BindVerNotSupported = 0xC1,

    /// In the reach out model, the listener receives a Role-Inquiry Message from
    /// the initiator. If the listener cannot operate as a Requester, then the listener
    /// should send a message with MessageType of 0xC2 to the initiator.
    CannotBeRequester = 0xC2,

    /// In the reach down model, if the listener receives an SPDM request message
    /// from the initiator but cannot operate as a Responder, then the listener should
    /// send a message with MessageType of 0xC3 to the initiator.
    CannotBeResponder = 0xC3,
    //0xC4 - 0xFF: Reserved.
}

impl TryFrom<u8> for SpdmSocketTransportError {
    type Error = SocketMessageHeaderError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0xC0 => Ok(SpdmSocketTransportError::PayloadLenTooLong),
            0xC1 => Ok(SpdmSocketTransportError::BindVerNotSupported),
            0xC2 => Ok(SpdmSocketTransportError::CannotBeRequester),
            0xC3 => Ok(SpdmSocketTransportError::CannotBeResponder),
            _ => Err(SocketMessageHeaderError::Reserved),
        }
    }
}

impl Into<u8> for SpdmSocketTransportError {
    fn into(self) -> u8 {
        match self {
            SpdmSocketTransportError::PayloadLenTooLong => 0xC0,
            SpdmSocketTransportError::BindVerNotSupported => 0xC1,
            SpdmSocketTransportError::CannotBeRequester => 0xC2,
            SpdmSocketTransportError::CannotBeResponder => 0xC3,
        }
    }
}

#[repr(u8)]
pub enum MessageType {
    /// Out-of-Session Message. An SPDM message follows the header.
    OutOfSession = 0x05,

    /// In-Session Message. An SPDM message follows the header.
    InSession = 0x06,

    /// Role-Inquiry Message. **No** SPDM message follows the header.
    RoleInquiry = 0xBF,

    /// Error messages. No SPDM message follows the header.
    Error(SpdmSocketTransportError),
    // Other values: reserved.
}

impl TryFrom<u8> for MessageType {
    type Error = SocketMessageHeaderError;

    fn try_from(value: u8) -> Result<Self, SocketMessageHeaderError> {
        match value {
            0x05 => Ok(MessageType::OutOfSession),
            0x06 => Ok(MessageType::InSession),
            0xBF => Ok(MessageType::RoleInquiry),
            0xC0..=u8::MAX => Ok(MessageType::Error(SpdmSocketTransportError::try_from(
                value,
            )?)),
            _ => Err(SocketMessageHeaderError::Reserved),
        }
    }
}

impl Into<u8> for MessageType {
    fn into(self) -> u8 {
        match self {
            Self::OutOfSession => 0x05,
            Self::InSession => 0x06,
            Self::RoleInquiry => 0xBf,
            Self::Error(ste) => ste.into(),
        }
    }
}

#[repr(C)]
#[derive(FromBytes, IntoBytes, Immutable)]
pub struct TcpSpdmBindingHeader {
    /// Shall be the length of the SPDM message that follows the header.
    payload_len: u16,

    /// Shall be 0x01 for this version of the binding specification.
    binding_ver: u8,

    /// Shall indicate the message type.
    message_type: u8,
}

impl TcpSpdmBindingHeader {
    pub fn new(payload_len: u16, message_type: MessageType) -> TcpSpdmBindingHeader {
        Self {
            payload_len,
            binding_ver: 0x01,
            message_type: message_type.into(),
        }
    }
}

impl TryFrom<&[u8; 4]> for TcpSpdmBindingHeader {
    type Error = SocketMessageHeaderError;

    fn try_from(value: &[u8; 4]) -> Result<Self, Self::Error> {
        let payload_len = u16::from_le_bytes([value[0], value[1]]);
        let binding_ver = value[2];
        let message_type = MessageType::try_from(value[3])?;

        Ok(TcpSpdmBindingHeader {
            payload_len,
            binding_ver,
            message_type: match message_type {
                MessageType::OutOfSession => 0x05,
                MessageType::InSession => 0x06,
                MessageType::RoleInquiry => 0xBF,
                MessageType::Error(code) => code as u8,
            },
        })
    }
}

impl Codec for TcpSpdmBindingHeader {
    fn encode(&self, buffer: &mut MessageBuf) -> spdm_lib::codec::CodecResult<usize> {
        let len = core::mem::size_of::<Self>();
        buffer.push_data(len)?;

        let header = buffer.data_mut(len)?;
        self.write_to(header).map_err(|_| CodecError::WriteError)?;
        buffer.push_head(len)?;

        Ok(len)
    }

    fn decode(buffer: &mut MessageBuf) -> spdm_lib::codec::CodecResult<Self>
    where
        Self: Sized,
    {
        let len = core::mem::size_of::<Self>();
        if buffer.data_len() < len {
            Err(CodecError::BufferTooSmall)?;
        }
        let data = buffer.data(len)?;
        let data = Self::read_from_bytes(data).map_err(|_| CodecError::ReadError)?;
        buffer.pull_data(len)?;

        // if Self::DATA_KIND == DataKind::Header {
        buffer.pull_head(len)?;
        // }
        Ok(data)
    }
}

/// For now, we ignore any TCP binding. This is a minimal example and the same
/// as the already implemented responder, we do use `SOCKET_TRANSPORT_TYPE_NONE`.
impl SpdmSocketTransport {
    /// Create a new socket transport
    pub fn new(stream: TcpStream, transport_type: SocketTransportType) -> Self {
        Self {
            stream,
            transport_type,
        }
    }

    /// Receive platform data with socket message header
    ///
    /// The transport specific headers such as MCTP header (see DSP0275) are encoded in the payload.
    /// Note, that the payload size needs to be adjusted accordingly when sending/ receiving messages with transport specific headers.
    pub(crate) fn receive_platform_data(&mut self) -> IoResult<(SocketSpdmCommand, Vec<u8>)> {
        // Read socket message header
        let mut header_bytes = [0u8; 12]; // sizeof(SocketMessageHeader)
        self.stream.read_exact(&mut header_bytes)?;
        let header = SocketSpdmCommandHdr::from(&header_bytes);
        let payload_size = header.payload_size.get();

        if payload_size > 0 {
            let mut data = vec![0u8; payload_size as usize];
            self.stream.read_exact(&mut data)?;

            // Parse and remove transport specific headers from the payload.
            match self.transport_type {
                SocketTransportType::None => {}
                SocketTransportType::MCTP => {
                    let mctp_header = data[0];
                    if mctp_header != 0x5 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            "Invalid MCTP header",
                        ));
                    }
                    data.remove(0);
                }
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Unsupported transport type",
                    ));
                }
            }

            Ok((header.command, data))
        } else {
            Ok((header.command, Vec::new()))
        }
    }

    /// Send platform data with socket message header
    ///
    /// Depending on the [SocketTransportType], this may prepend additional transport-specific headers to the data.
    fn send_platform_data(&mut self, command: SocketSpdmCommand, data: &[u8]) -> IoResult<()> {
        let mut platform_header: &[u8] = &[];
        match self.transport_type {
            SocketTransportType::None => {}

            SocketTransportType::MCTP => {
                platform_header = &[0x5];
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Unsupported transport type",
                ));
            }
        }

        let header_bytes: [u8; 12] = SocketSpdmCommandHdr {
            command: SocketSpdmCommand::from(command as u32),
            transport_type: self.transport_type,
            payload_size: BeU32::new((data.len() + platform_header.len()) as u32),
        }
        .into();

        self.stream.write_all(&header_bytes)?;

        if !data.is_empty() {
            self.stream.write_all(platform_header)?;
            self.stream.write_all(data)?;
        }

        self.stream.flush()?;
        Ok(())
    }

    pub fn send_client_hello<'a>(&mut self) -> TransportResult<()> {
        let message_data = b"Client Hello!\x00".as_bytes();

        self.send_platform_data(SocketSpdmCommand::Test, message_data)
            .map_err(|_| TransportError::SendError)?;
        Ok(())
    }
}

impl SpdmTransport for SpdmSocketTransport {
    /// This function is only relevant for the SPDM Requester.
    /// Send the SPDM Request encoded into [req] (header|payload]) via the platform transport
    /// to and SPDM endpoint.
    fn send_request<'a>(&mut self, dest_eid: u8, req: &mut MessageBuf<'a>) -> TransportResult<()> {
        let message_data = req
            .message_data()
            .map_err(|_| TransportError::BufferTooSmall)?;

        self.send_platform_data(SocketSpdmCommand::Normal, message_data)
            .map_err(|_| TransportError::SendError)?;
        Ok(())
    }

    /// Initialize any transport-specific sequence state.
    /// For SOCKET_TRANSPORT_TYPE_NONE, this means performing the handshake.
    /// This function is only valid for the SPDM Requester.
    fn init_sequence(&mut self) -> TransportResult<()> {
        self.send_client_hello()?;

        match self.receive_platform_data() {
            Ok((command, data)) => {
                if command != SocketSpdmCommand::Test || data != b"Server Hello!\x00" {
                    return Err(TransportError::HandshakeNoneError);
                }
                Ok(())
            }
            Err(_) => Err(TransportError::HandshakeNoneError),
        }
    }

    fn receive_response<'a>(&mut self, rsp: &mut MessageBuf<'a>) -> TransportResult<()> {
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
                            SocketSpdmCommand::Shutdown => {}
                            SocketSpdmCommand::Unknown => {}
                            SocketSpdmCommand::Test => {
                                if data != b"Server Hello!" {
                                    return Err(TransportError::HandshakeNoneError);
                                }
                            }
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

                        // In a correct flow, this can only happen for the responder
                        SocketSpdmCommand::Test => {
                            if data == b"Client Hello!\x00" {
                                self.send_platform_data(
                                    SocketSpdmCommand::Test,
                                    b"Server Hello!\x00",
                                )
                                .map_err(|_| TransportError::SendError)?;
                            } else {
                                return Err(TransportError::HandshakeNoneError);
                            }
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
