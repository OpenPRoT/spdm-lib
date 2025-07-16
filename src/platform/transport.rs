
extern crate alloc;
use alloc::boxed::Box;
use crate::codec::{MessageBuf, CodecError};
use async_trait::async_trait;

pub type TransportResult<T> = Result<T, TransportError>;

#[async_trait]
pub trait SpdmTransport {
    async fn send_request<'a>(
        &mut self,
        dest_eid: u8,
        req: &mut MessageBuf<'a>,
    ) -> TransportResult<()>;
    async fn receive_response<'a>(&mut self, rsp: &mut MessageBuf<'a>) -> TransportResult<()>;
    async fn receive_request<'a>(&mut self, req: &mut MessageBuf<'a>) -> TransportResult<()>;
    async fn send_response<'a>(&mut self, resp: &mut MessageBuf<'a>) -> TransportResult<()>;
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