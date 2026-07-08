// Licensed under the Apache-2.0 license

use spdm_codec::errors::SPDM_INVALID_REQUEST;
use spdm_codec::{IdeKmHdr, KeySetGoStop, WireWriter};
use spdm_traits::McuResult;

pub(crate) fn write_key_go_stop_ack(
    req: KeySetGoStop,
    writer: &mut WireWriter<'_>,
) -> McuResult<usize> {
    writer
        .write(&IdeKmHdr {
            object_id: spdm_codec::IDE_KM_OBJECT_ID_KEY_GO_STOP_ACK,
        })
        .map_err(|_| SPDM_INVALID_REQUEST)?;
    writer
        .write(&KeySetGoStop {
            reserved1: 0.into(),
            stream_id: req.stream_id,
            reserved2: 0,
            key_info: req.key_info,
            port_index: req.port_index,
        })
        .map_err(|_| SPDM_INVALID_REQUEST)?;
    Ok(writer.position())
}
