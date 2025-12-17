// Licensed under the Apache-2.0 license

use crate::{codec::MessageBuf, context::SpdmContext, error::CommandResult, protocol::SpdmMsgHdr};

/// Requester function handling the parsing of the CAPABILITIES response sent by the Responder.
pub(crate) fn handle_capabilities_response<'a>(
    ctx: &mut SpdmContext<'a>,
    resp_header: SpdmMsgHdr,
    resp: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    todo!();
}
