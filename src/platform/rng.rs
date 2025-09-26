pub type SpdmRngResult<T> = Result<T, SpdmRngError>;

#[derive(Debug, PartialEq)]
pub enum SpdmRngError {
    InvalidSize,
}

pub trait SpdmRng {
    fn get_random_bytes(&mut self, buf: &mut [u8]) -> SpdmRngResult<()>;
    fn generate_random_number(&mut self, random_number: &mut [u8]) -> SpdmRngResult<()>;
}