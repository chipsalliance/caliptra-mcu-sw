// Licensed under the Apache-2.0 license

//! Minimal `FW_INFO` mailbox helper.

use crate::raw::{raw_mailbox_execute, CMD_FW_INFO};
use crate::ScratchAlloc;
use caliptra_api::mailbox::FwInfoResp;
use core::mem::{offset_of, size_of};
use mcu_error::codes::INVARIANT;
use mcu_error::McuResult;

const REQ_SIZE: usize = 4;
const RSP_SIZE: usize = size_of::<FwInfoResp>();
const FW_SVN_OFFSET: usize = 12;
const IMAGE_MANIFEST_PQC_TYPE_OFFSET: usize = 364;
const VENDOR_ECC384_PUB_KEY_INDEX_OFFSET: usize = 368;
const VENDOR_PQC_PUB_KEY_INDEX_OFFSET: usize = 372;
const OWNER_AUTH_MANIFEST_CURRENT_SVN_OFFSET: usize =
    offset_of!(FwInfoResp, owner_auth_manifest_current_svn);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FwInfo {
    pub fw_svn: u32,
    pub image_manifest_pqc_type: u32,
    pub vendor_ecc384_pub_key_index: u32,
    pub vendor_pqc_pub_key_index: u32,
    pub owner_auth_manifest_current_svn: u32,
}

pub async fn fw_info<A: ScratchAlloc>(alloc: &A) -> McuResult<FwInfo> {
    let mut req = alloc.alloc(REQ_SIZE)?;
    req.fill(0);
    let mut rsp = alloc.alloc(RSP_SIZE)?;

    let len = raw_mailbox_execute(CMD_FW_INFO, &mut req, &mut rsp).await?;
    parse_fw_info(rsp.get(..len).ok_or(INVARIANT)?)
}

fn parse_fw_info(rsp: &[u8]) -> McuResult<FwInfo> {
    if rsp.len() < RSP_SIZE {
        return Err(INVARIANT);
    }

    Ok(FwInfo {
        fw_svn: read_u32(rsp, FW_SVN_OFFSET)?,
        image_manifest_pqc_type: read_u32(rsp, IMAGE_MANIFEST_PQC_TYPE_OFFSET)?,
        vendor_ecc384_pub_key_index: read_u32(rsp, VENDOR_ECC384_PUB_KEY_INDEX_OFFSET)?,
        vendor_pqc_pub_key_index: read_u32(rsp, VENDOR_PQC_PUB_KEY_INDEX_OFFSET)?,
        owner_auth_manifest_current_svn: read_u32(rsp, OWNER_AUTH_MANIFEST_CURRENT_SVN_OFFSET)?,
    })
}

fn read_u32(buf: &[u8], offset: usize) -> McuResult<u32> {
    let bytes: [u8; 4] = buf
        .get(offset..offset + 4)
        .and_then(|s| s.try_into().ok())
        .ok_or(INVARIANT)?;
    Ok(u32::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use zerocopy::{FromZeros, IntoBytes};

    #[test]
    fn parses_owner_svn_from_the_complete_fw_info_response() {
        let response = FwInfoResp {
            fw_svn: 7,
            image_manifest_pqc_type: 2,
            vendor_ecc384_pub_key_index: 3,
            vendor_pqc_pub_key_index: 4,
            owner_auth_manifest_current_svn: 64,
            owner_auth_manifest_min_svn: 12,
            ..FwInfoResp::new_zeroed()
        };
        assert_eq!(
            parse_fw_info(response.as_bytes()).unwrap(),
            FwInfo {
                fw_svn: 7,
                image_manifest_pqc_type: 2,
                vendor_ecc384_pub_key_index: 3,
                vendor_pqc_pub_key_index: 4,
                owner_auth_manifest_current_svn: 64,
            }
        );
    }

    #[test]
    fn owner_svn_rejects_truncated_fw_info_responses() {
        let response = [0u8; RSP_SIZE];
        for len in [0, 8, 376, RSP_SIZE - 1] {
            assert_eq!(parse_fw_info(&response[..len]), Err(INVARIANT));
        }
    }
}
