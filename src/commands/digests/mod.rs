// Licensed under the Apache-2.0 license

use crate::cert_store::{cert_slot_mask, SpdmCertStore};
use crate::codec::{Codec, CommonCodec, MessageBuf};
use crate::context::SpdmContext;
use crate::error::{CommandError, CommandResult, PlatformError};
use crate::platform::hash::{SpdmHash, SpdmHashAlgoType};

use crate::protocol::*;

use zerocopy::{FromBytes, Immutable, IntoBytes};

pub mod request;
pub mod response;

pub(crate) use request::*;
pub(crate) use response::*;

#[derive(IntoBytes, FromBytes, Immutable, Default)]
#[repr(C)]
pub struct GetDigestsReq {
    param1: u8,
    param2: u8,
}

impl CommonCodec for GetDigestsReq {}

#[derive(IntoBytes, FromBytes, Immutable, Default)]
#[repr(C)]
pub struct GetDigestsRespCommon {
    pub supported_slot_mask: u8,   // param1: introduced in v13
    pub provisioned_slot_mask: u8, // param2
}

impl CommonCodec for GetDigestsRespCommon {}

pub(crate) fn compute_cert_chain_hash(
    digest_fn: &mut dyn SpdmHash,
    slot_id: u8,
    cert_store: &mut dyn SpdmCertStore,
    asym_algo: AsymAlgo,
    hash: &mut [u8],
) -> CommandResult<()> {
    if hash.len() != SHA384_HASH_SIZE {
        Err((false, CommandError::BufferTooSmall))?;
    }

    let crt_chain_len = cert_store
        .cert_chain_len(asym_algo, slot_id)
        .map_err(|e| (false, CommandError::CertStore(e)))?;
    let cert_chain_format_len = crt_chain_len + SPDM_CERT_CHAIN_METADATA_LEN as usize;

    let header = SpdmCertChainHeader::new(cert_chain_format_len as u32, SpdmVersion::V13)
        .map_err(|_| (false, CommandError::InternalError))?;

    // Length and reserved fields
    let header_bytes = header.as_bytes();

    digest_fn
        .init(SpdmHashAlgoType::SHA384, Some(header_bytes))
        .map_err(|e| (false, CommandError::Platform(PlatformError::HashError(e))))?;

    // Root certificate hash
    let mut root_hash = [0u8; SHA384_HASH_SIZE];

    cert_store
        .root_cert_hash(slot_id, asym_algo, &mut root_hash)
        .map_err(|e| (false, CommandError::CertStore(e)))?;
    digest_fn
        .update(&root_hash)
        .map_err(|e| (false, CommandError::Platform(PlatformError::HashError(e))))?;

    // Hash the certificate chain
    let mut cert_portion = [0u8; SPDM_MAX_CERT_CHAIN_PORTION_LEN as usize];
    let mut offset = 0;

    loop {
        let bytes_read = cert_store
            .get_cert_chain(slot_id, asym_algo, offset, &mut cert_portion)
            .map_err(|e| (false, CommandError::CertStore(e)))?;

        digest_fn
            .update(&cert_portion[..bytes_read])
            .map_err(|e| (false, CommandError::Platform(PlatformError::HashError(e))))?;

        offset += bytes_read;

        // If the bytes read is less than the length of the cert portion, it indicates the end of the chain
        if bytes_read < cert_portion.len() {
            break;
        }
    }
    digest_fn
        .finalize(hash)
        .map_err(|e| (false, CommandError::Platform(PlatformError::HashError(e))))
}

fn encode_cert_chain_digest(
    digest_fn: &mut dyn SpdmHash,
    slot_id: u8,
    cert_store: &mut dyn SpdmCertStore,
    asym_algo: AsymAlgo,
    rsp: &mut MessageBuf<'_>,
) -> CommandResult<usize> {
    // Fill the response buffer with the certificate chain digest
    rsp.put_data(SHA384_HASH_SIZE)
        .map_err(|e| (false, CommandError::Codec(e)))?;
    let cert_chain_digest_buf = rsp
        .data_mut(SHA384_HASH_SIZE)
        .map_err(|_| (false, CommandError::BufferTooSmall))?;

    compute_cert_chain_hash(
        digest_fn,
        slot_id,
        cert_store,
        asym_algo,
        cert_chain_digest_buf,
    )?;

    rsp.pull_data(SHA384_HASH_SIZE)
        .map_err(|_| (false, CommandError::BufferTooSmall))?;

    Ok(SHA384_HASH_SIZE)
}

fn encode_multi_key_conn_rsp_data(
    ctx: &mut SpdmContext,
    provisioned_slot_mask: u8,
    rsp: &mut MessageBuf,
) -> CommandResult<usize> {
    let slot_cnt = provisioned_slot_mask.count_ones() as usize;

    let key_pair_ids_size = size_of::<u8>() * slot_cnt;
    let cert_infos_size = size_of::<CertificateInfo>() * slot_cnt;
    let key_usage_masks_size = size_of::<KeyUsageMask>() * slot_cnt;
    let total_size = key_pair_ids_size + cert_infos_size + key_usage_masks_size;

    rsp.put_data(total_size)
        .map_err(|_| (false, CommandError::BufferTooSmall))?;
    let data_buf = rsp
        .data_mut(total_size)
        .map_err(|_| (false, CommandError::BufferTooSmall))?;
    data_buf.fill(0);

    let (key_pair_buf, rest) = data_buf.split_at_mut(key_pair_ids_size);
    let (cert_info_buf, key_usage_mask_buf) = rest.split_at_mut(cert_infos_size);

    let mut key_pair_offset = 0;
    let mut key_usage_offset = 0;
    let mut cert_info_offset = 0;

    for slot_id in 0..slot_cnt {
        let key_pair_id = ctx
            .device_certs_store
            .key_pair_id(slot_id as u8)
            .unwrap_or_default();
        let cert_info = ctx
            .device_certs_store
            .cert_info(slot_id as u8)
            .unwrap_or_default();
        let key_usage_mask = ctx
            .device_certs_store
            .key_usage_mask(slot_id as u8)
            .unwrap_or_default();

        // Fill the KeyPairIDs
        key_pair_buf[key_pair_offset..key_pair_offset + size_of::<u8>()]
            .copy_from_slice(key_pair_id.as_bytes());
        key_pair_offset += size_of::<u8>();

        // Fill the CertificateInfos
        cert_info_buf[cert_info_offset..cert_info_offset + size_of::<CertificateInfo>()]
            .copy_from_slice(cert_info.as_bytes());
        cert_info_offset += size_of::<CertificateInfo>();

        // Fill the KeyUsageMasks
        key_usage_mask_buf[key_usage_offset..key_usage_offset + size_of::<KeyUsageMask>()]
            .copy_from_slice(key_usage_mask.as_bytes());
        key_usage_offset += size_of::<KeyUsageMask>();
    }
    rsp.pull_data(total_size)
        .map_err(|_| (false, CommandError::BufferTooSmall))?;

    Ok(total_size)
}
