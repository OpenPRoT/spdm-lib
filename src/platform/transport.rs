
extern crate alloc;
use crate::codec::{MessageBuf, CodecError};

pub type TransportResult<T> = Result<T, TransportError>;

pub trait SpdmTransport {
    fn send_request<'a>(
        &mut self,
        dest_eid: u8,
        req: &mut MessageBuf<'a>,
    ) -> TransportResult<()>;
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
}