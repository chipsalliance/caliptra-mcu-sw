// Licensed under the Apache-2.0 license

//! Minimal `FW_INFO` mailbox helper.

use crate::raw::{raw_mailbox_execute, CMD_FW_INFO};
use crate::ApiAlloc;
use mcu_error::codes::INVARIANT;
use mcu_error::McuResult;

const REQ_SIZE: usize = 4;
const RSP_SIZE: usize = 376;
const FW_SVN_OFFSET: usize = 12;
const IMAGE_MANIFEST_PQC_TYPE_OFFSET: usize = 364;
const VENDOR_ECC384_PUB_KEY_INDEX_OFFSET: usize = 368;
const VENDOR_PQC_PUB_KEY_INDEX_OFFSET: usize = 372;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FwInfo {
    pub fw_svn: u32,
    pub image_manifest_pqc_type: u32,
    pub vendor_ecc384_pub_key_index: u32,
    pub vendor_pqc_pub_key_index: u32,
}

pub async fn fw_info<A: ApiAlloc>(alloc: &A) -> McuResult<FwInfo> {
    let mut req = alloc.alloc(REQ_SIZE)?;
    req.fill(0);
    let mut rsp = alloc.alloc(RSP_SIZE)?;

    let len = raw_mailbox_execute(CMD_FW_INFO, &mut req, &mut rsp).await?;
    if len < RSP_SIZE {
        return Err(INVARIANT);
    }

    Ok(FwInfo {
        fw_svn: read_u32(&rsp, FW_SVN_OFFSET)?,
        image_manifest_pqc_type: read_u32(&rsp, IMAGE_MANIFEST_PQC_TYPE_OFFSET)?,
        vendor_ecc384_pub_key_index: read_u32(&rsp, VENDOR_ECC384_PUB_KEY_INDEX_OFFSET)?,
        vendor_pqc_pub_key_index: read_u32(&rsp, VENDOR_PQC_PUB_KEY_INDEX_OFFSET)?,
    })
}

fn read_u32(buf: &[u8], offset: usize) -> McuResult<u32> {
    let bytes: [u8; 4] = buf
        .get(offset..offset + 4)
        .and_then(|s| s.try_into().ok())
        .ok_or(INVARIANT)?;
    Ok(u32::from_le_bytes(bytes))
}
