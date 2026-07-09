// Licensed under the Apache-2.0 license

//! Platform-independent placeholder for `caliptra-mcu-libsyscall-caliptra`.
//!
//! Exposes only the syscall-driver surface the SPDM-Lib transports and PAL
//! actually use: [`mctp`], [`doe`], and [`flash`], plus the [`DefaultSyscalls`]
//! marker. All I/O bodies are stubs (`unimplemented!`) — this crate exists so
//! the library compiles standalone; real syscall bindings are wired later.

#![no_std]
#![forbid(unsafe_code)]

use spdm_platform::ErrorCode;

/// Placeholder for the platform's default syscall implementation.
///
/// Carried purely as a generic type parameter by the transport/flash types;
/// it is never constructed in the placeholder.
pub enum DefaultSyscalls {}

/// MCTP transport driver bindings.
pub mod mctp {
    use super::ErrorCode;
    use core::marker::PhantomData;

    /// MCTP endpoint id.
    pub type EndpointId = u8;
    /// MCTP message tag.
    pub type Tag = u8;

    /// Source metadata captured on receive and echoed back on send.
    #[derive(Copy, Clone, Debug)]
    pub struct MessageInfo {
        pub eid: EndpointId,
        pub tag: Tag,
    }

    impl From<u32> for MessageInfo {
        fn from(msg_info: u32) -> Self {
            MessageInfo {
                eid: ((msg_info & 0xFF0000) >> 16) as u8,
                tag: (msg_info & 0xFF) as u8,
            }
        }
    }

    /// MCTP syscall handle bound to a driver number.
    pub struct Mctp<S = super::DefaultSyscalls> {
        _driver_num: u32,
        _s: PhantomData<S>,
    }

    impl<S> Mctp<S> {
        pub fn new(driver_num: u32) -> Self {
            Self {
                _driver_num: driver_num,
                _s: PhantomData,
            }
        }

        pub async fn receive_request(
            &self,
            _req: &mut [u8],
        ) -> Result<(u32, MessageInfo), ErrorCode> {
            unimplemented!("spdm-transport-sys placeholder: mctp::receive_request")
        }

        pub async fn send_response(
            &self,
            _resp: &[u8],
            _info: MessageInfo,
        ) -> Result<(), ErrorCode> {
            unimplemented!("spdm-transport-sys placeholder: mctp::send_response")
        }
    }

    /// SPDM MCTP driver numbers.
    pub mod driver_num {
        pub const MCTP_SPDM: u32 = 0xA0000;
        pub const MCTP_SECURE: u32 = 0xA0001;
    }
}

/// DOE transport driver bindings.
pub mod doe {
    use super::ErrorCode;
    use core::marker::PhantomData;

    /// DOE syscall handle bound to a driver number.
    pub struct Doe<S = super::DefaultSyscalls> {
        _driver_num: u32,
        _s: PhantomData<S>,
    }

    impl<S> Doe<S> {
        pub fn new(driver_num: u32) -> Self {
            Self {
                _driver_num: driver_num,
                _s: PhantomData,
            }
        }

        pub fn exists(&self) -> bool {
            false
        }

        pub async fn receive_message(&self, _buf: &mut [u8]) -> Result<u32, ErrorCode> {
            unimplemented!("spdm-transport-sys placeholder: doe::receive_message")
        }

        pub async fn send_message(&self, _buf: &[u8]) -> Result<(), ErrorCode> {
            unimplemented!("spdm-transport-sys placeholder: doe::send_message")
        }

        pub fn max_message_size(&self) -> Result<u32, ErrorCode> {
            unimplemented!("spdm-transport-sys placeholder: doe::max_message_size")
        }
    }

    /// SPDM DOE driver number.
    pub mod driver_num {
        pub const DOE_SPDM: u32 = 0xA000_0010;
    }
}

/// SPI-flash driver bindings.
pub mod flash {
    use super::ErrorCode;
    use core::marker::PhantomData;

    /// Flash capacity in bytes.
    pub struct FlashCapacity(pub u32);

    /// SPI-flash syscall handle bound to a driver number.
    pub struct SpiFlash<S = super::DefaultSyscalls> {
        _driver_num: u32,
        _s: PhantomData<S>,
    }

    impl<S> SpiFlash<S> {
        pub fn new(driver_num: u32) -> Self {
            Self {
                _driver_num: driver_num,
                _s: PhantomData,
            }
        }

        pub fn exists(&self) -> Result<(), ErrorCode> {
            Err(ErrorCode::NoDevice)
        }

        pub fn get_capacity(&self) -> Result<FlashCapacity, ErrorCode> {
            unimplemented!("spdm-transport-sys placeholder: flash::get_capacity")
        }

        pub fn get_chunk_size(&self) -> Result<usize, ErrorCode> {
            unimplemented!("spdm-transport-sys placeholder: flash::get_chunk_size")
        }

        pub async fn read(
            &self,
            _address: usize,
            _len: usize,
            _buf: &mut [u8],
        ) -> Result<(), ErrorCode> {
            unimplemented!("spdm-transport-sys placeholder: flash::read")
        }

        pub async fn write(
            &self,
            _address: usize,
            _len: usize,
            _buf: &[u8],
        ) -> Result<(), ErrorCode> {
            unimplemented!("spdm-transport-sys placeholder: flash::write")
        }

        pub async fn erase(&self, _address: usize, _len: usize) -> Result<(), ErrorCode> {
            unimplemented!("spdm-transport-sys placeholder: flash::erase")
        }
    }
}
