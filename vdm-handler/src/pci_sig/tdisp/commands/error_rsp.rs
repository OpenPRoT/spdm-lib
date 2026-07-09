// Licensed under the Apache-2.0 license

//! TDISP ERROR response generation.

use spdm_codec::errors::SPDM_UNSPECIFIED;
use spdm_traits::{PalResult, VdmResponse};

use spdm_codec::vendor_defined::pci_sig::tdisp::{
    InterfaceId, TdispCommand, TdispErrorCode, TdispMessageHeader, ERROR_RSP_LEN, TDISP_HEADER_LEN,
};

pub(crate) fn write_error(
    version: u8,
    interface_id: InterfaceId,
    error: TdispErrorCode,
    error_data: u32,
    out: &mut [u8],
) -> PalResult<VdmResponse> {
    let out = out.get_mut(..ERROR_RSP_LEN).ok_or(SPDM_UNSPECIFIED)?;
    TdispMessageHeader::new(version, TdispCommand::ErrorResponse, interface_id).encode(out)?;
    out[TDISP_HEADER_LEN..TDISP_HEADER_LEN + 4].copy_from_slice(&error.to_le_bytes());
    out[TDISP_HEADER_LEN + 4..TDISP_HEADER_LEN + 8].copy_from_slice(&error_data.to_le_bytes());
    Ok(VdmResponse::Inline(ERROR_RSP_LEN))
}
