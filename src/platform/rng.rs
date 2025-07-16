extern crate alloc;
use alloc::boxed::Box;
use async_trait::async_trait;

pub type SpdmRngResult<T> = Result<T, SpdmRngError>;

#[derive(Debug, PartialEq)]
pub enum SpdmRngError {
    InvalidSize,
}

#[async_trait]
pub trait SpdmRng {
    async fn get_random_bytes(&mut self, buf: &mut [u8]) -> SpdmRngResult<()>;
    async fn generate_random_number(&mut self, random_number: &mut [u8]) -> SpdmRngResult<()>;
}