// Copyright 2025
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::codec::{CodecError, MessageBuf};

pub type TransportResult<T> = Result<T, TransportError>;

pub trait SpdmTransport {
    /// Initialize any transport-specific sequence state.
    ///
    /// # Note
    /// It is expected that this function may perform multiple I/O operations,
    /// such as sending and receiving messages, to establish the transport session.
    fn init_sequence(&mut self) -> TransportResult<()>;

    fn send_request<'a>(&mut self, dest_eid: u8, req: &mut MessageBuf<'a>) -> TransportResult<()>;
    fn receive_response<'a>(&mut self, rsp: &mut MessageBuf<'a>) -> TransportResult<()>;
    fn receive_request<'a>(&mut self, req: &mut MessageBuf<'a>) -> TransportResult<()>;
    fn send_response<'a>(&mut self, resp: &mut MessageBuf<'a>) -> TransportResult<()>;
    fn max_message_size(&self) -> TransportResult<usize>;
    fn header_size(&self) -> usize;
}

#[derive(Debug)]
pub enum TransportError {
    DriverError,
    BufferTooSmall,
    Codec(CodecError),
    UnexpectedMessageType,
    ReceiveError,
    SendError,
    ResponseNotExpected,
    NoRequestInFlight,
    UnsupportedTransportType,

    /// Error specific to SOCKET_TRANSPORT_TYPE_NONE handshake
    HandshakeNoneError,
}
