extern crate alloc;

pub type SpdmHashResult<T> = Result<T, SpdmHashError>;

pub trait SpdmHash {
    fn hash(&mut self, hash_algo: SpdmHashAlgoType, data: &[u8], hash: &mut [u8]) -> SpdmHashResult<()>;
    fn init(&mut self, hash_algo: SpdmHashAlgoType, data: Option<&[u8]>) -> SpdmHashResult<()>;
    fn update(&mut self, data: &[u8]) -> SpdmHashResult<()>;
    fn finalize(&mut self, hash: &mut [u8]) -> SpdmHashResult<()>;

    fn reset(&mut self);
    fn algo(&self) -> SpdmHashAlgoType;  
}

#[derive(Debug, PartialEq)]
pub enum SpdmHashError {
    PlatformError,
    BufferTooSmall,
    InvalidAlgorithm,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SpdmHashAlgoType {
    SHA384,
    SHA512,
}

impl From<SpdmHashAlgoType> for u32 {
    fn from(algo: SpdmHashAlgoType) -> Self {
        match algo {
            SpdmHashAlgoType::SHA384 => 2u32,
            SpdmHashAlgoType::SHA512 => 4u32,
        }
    }
}

impl SpdmHashAlgoType {
    pub fn hash_size(&self) -> usize {
        match self {
            SpdmHashAlgoType::SHA384 => 48,
            SpdmHashAlgoType::SHA512 => 64,
        }
    }
}