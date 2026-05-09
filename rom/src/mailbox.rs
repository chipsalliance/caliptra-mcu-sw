/*++

Licensed under the Apache-2.0 license.

File Name:

    mailbox.rs

Abstract:

    Caliptra mailbox commands.

--*/

use crate::{err_code, fatal_error};
use caliptra_api::mailbox::{
    CmShaFinalResp, CmShaInitResp, CommandId, CMB_SHA_CONTEXT_SIZE, MAX_CMB_DATA_SIZE,
};
use mcu_error::McuError;
use romtime::{CaliptraSoC, HexWord};

/// CmHashAlgorithm::Sha384 value (matches caliptra-api enum).
const CM_HASH_ALGORITHM_SHA384: u32 = 1;

/// Maximum number of u32 data words per CM_SHA chunk.
const CHUNK_DWORDS: usize = MAX_CMB_DATA_SIZE / 4;

/// Number of u32 words in a SHA context.
const CTX_DWORDS: usize = CMB_SHA_CONTEXT_SIZE / 4;

/// Wrapping byte-sum of a u32 word (sums its 4 LE bytes).
fn word_byte_sum(w: u32) -> u32 {
    let b = w.to_le_bytes();
    (b[0] as u32)
        .wrapping_add(b[1] as u32)
        .wrapping_add(b[2] as u32)
        .wrapping_add(b[3] as u32)
}

/// Wrapping byte-sum over a slice of u32 words.
fn u32_byte_sum(data: &[u32]) -> u32 {
    data.iter()
        .fold(0u32, |acc, &w| acc.wrapping_add(word_byte_sum(w)))
}

/// Interpret a `[u8; CMB_SHA_CONTEXT_SIZE]` as `&[u32; CTX_DWORDS]`.
fn ctx_as_u32(ctx: &[u8; CMB_SHA_CONTEXT_SIZE]) -> &[u32; CTX_DWORDS] {
    // Safety: CMB_SHA_CONTEXT_SIZE is a multiple of 4 and the array is
    // stack-allocated with natural alignment.
    unsafe { &*(ctx.as_ptr() as *const [u32; CTX_DWORDS]) }
}

/// Compute SHA-384 of `data` (a u32 slice representing the ROM) using
/// CM_SHA_INIT / UPDATE / FINAL streaming mailbox commands. Returns the
/// 48-byte digest.
///
/// Data words are passed directly to the mailbox via u32 iterators, avoiding
/// the ~4 KiB stack allocations that the request structs would otherwise
/// require.
pub fn cm_sha384(soc_manager: &mut CaliptraSoC, data: &[u32]) -> [u8; 48] {
    let mut offset = 0;
    let first_chunk = data.len().min(CHUNK_DWORDS);

    let mut sha_context = cm_sha_init(soc_manager, &data[..first_chunk]);
    offset += first_chunk;

    while data.len() - offset > CHUNK_DWORDS {
        cm_sha_update(
            soc_manager,
            &data[offset..offset + CHUNK_DWORDS],
            &mut sha_context,
        );
        offset += CHUNK_DWORDS;
    }

    cm_sha_final(soc_manager, &data[offset..], sha_context)
}

/// Send CM_SHA_INIT with the first data chunk and return the SHA context.
#[inline(never)]
fn cm_sha_init(soc_manager: &mut CaliptraSoC, chunk: &[u32]) -> [u8; CMB_SHA_CONTEXT_SIZE] {
    let cmd: u32 = CommandId::CM_SHA_INIT.into();
    let hash_algorithm = CM_HASH_ALGORITHM_SHA384;
    let input_size = (chunk.len() * 4) as u32;

    let mut sum = word_byte_sum(cmd);
    sum = sum.wrapping_add(word_byte_sum(hash_algorithm));
    sum = sum.wrapping_add(word_byte_sum(input_size));
    sum = sum.wrapping_add(u32_byte_sum(chunk));
    let checksum = 0u32.wrapping_sub(sum);

    // CmShaInitReq: chksum(4) + hash_algorithm(4) + input_size(4) + input(MAX_CMB_DATA_SIZE)
    let total_bytes = 4 + 4 + 4 + MAX_CMB_DATA_SIZE;
    let padding = CHUNK_DWORDS - chunk.len();

    let iter = core::iter::once(checksum)
        .chain(core::iter::once(hash_algorithm))
        .chain(core::iter::once(input_size))
        .chain(chunk.iter().copied())
        .chain(core::iter::repeat(0u32).take(padding));

    if let Err(err) = soc_manager.start_mailbox_req(cmd, total_bytes, iter) {
        romtime::println!(
            "[mcu-rom] CM_SHA_INIT start error: {}",
            HexWord(err_code(&err))
        );
        fatal_error(McuError::ROM_COLD_BOOT_ROM_DIGEST_MISMATCH);
    }

    let mut resp_buf = [0u8; core::mem::size_of::<CmShaInitResp>()];
    if let Err(err) = soc_manager.finish_mailbox_resp_bytes(&mut resp_buf) {
        romtime::println!(
            "[mcu-rom] CM_SHA_INIT finish error: {}",
            HexWord(err_code(&err))
        );
        fatal_error(McuError::ROM_COLD_BOOT_ROM_DIGEST_MISMATCH);
    }

    let mut sha_context = [0u8; CMB_SHA_CONTEXT_SIZE];
    match resp_buf.get(8..8 + CMB_SHA_CONTEXT_SIZE) {
        Some(src) => sha_context.copy_from_slice(src),
        None => fatal_error(McuError::ROM_COLD_BOOT_ROM_DIGEST_MISMATCH),
    }
    sha_context
}

/// Send CM_SHA_UPDATE for one middle chunk, updating the SHA context in place.
#[inline(never)]
fn cm_sha_update(
    soc_manager: &mut CaliptraSoC,
    chunk: &[u32],
    sha_context: &mut [u8; CMB_SHA_CONTEXT_SIZE],
) {
    let cmd: u32 = CommandId::CM_SHA_UPDATE.into();
    let input_size = (chunk.len() * 4) as u32;
    let ctx = ctx_as_u32(sha_context);

    let mut sum = word_byte_sum(cmd);
    sum = sum.wrapping_add(u32_byte_sum(ctx));
    sum = sum.wrapping_add(word_byte_sum(input_size));
    sum = sum.wrapping_add(u32_byte_sum(chunk));
    let checksum = 0u32.wrapping_sub(sum);

    let total_bytes = 4 + CMB_SHA_CONTEXT_SIZE + 4 + MAX_CMB_DATA_SIZE;
    let padding = CHUNK_DWORDS - chunk.len();

    let iter = core::iter::once(checksum)
        .chain(ctx.iter().copied())
        .chain(core::iter::once(input_size))
        .chain(chunk.iter().copied())
        .chain(core::iter::repeat(0u32).take(padding));

    if let Err(err) = soc_manager.start_mailbox_req(cmd, total_bytes, iter) {
        romtime::println!(
            "[mcu-rom] CM_SHA_UPDATE start error: {}",
            HexWord(err_code(&err))
        );
        fatal_error(McuError::ROM_COLD_BOOT_ROM_DIGEST_MISMATCH);
    }

    let mut resp_buf = [0u8; core::mem::size_of::<CmShaInitResp>()];
    if let Err(err) = soc_manager.finish_mailbox_resp_bytes(&mut resp_buf) {
        romtime::println!(
            "[mcu-rom] CM_SHA_UPDATE finish error: {}",
            HexWord(err_code(&err))
        );
        fatal_error(McuError::ROM_COLD_BOOT_ROM_DIGEST_MISMATCH);
    }

    match resp_buf.get(8..8 + CMB_SHA_CONTEXT_SIZE) {
        Some(src) => sha_context.copy_from_slice(src),
        None => fatal_error(McuError::ROM_COLD_BOOT_ROM_DIGEST_MISMATCH),
    }
}

/// Send CM_SHA_FINAL with any remaining data and return the 48-byte digest.
#[inline(never)]
fn cm_sha_final(
    soc_manager: &mut CaliptraSoC,
    remaining: &[u32],
    sha_context: [u8; CMB_SHA_CONTEXT_SIZE],
) -> [u8; 48] {
    let cmd: u32 = CommandId::CM_SHA_FINAL.into();
    let input_size = (remaining.len() * 4) as u32;
    let ctx = ctx_as_u32(&sha_context);

    let mut sum = word_byte_sum(cmd);
    sum = sum.wrapping_add(u32_byte_sum(ctx));
    sum = sum.wrapping_add(word_byte_sum(input_size));
    sum = sum.wrapping_add(u32_byte_sum(remaining));
    let checksum = 0u32.wrapping_sub(sum);

    let total_bytes = 4 + CMB_SHA_CONTEXT_SIZE + 4 + MAX_CMB_DATA_SIZE;
    let padding = CHUNK_DWORDS - remaining.len();

    let iter = core::iter::once(checksum)
        .chain(ctx.iter().copied())
        .chain(core::iter::once(input_size))
        .chain(remaining.iter().copied())
        .chain(core::iter::repeat(0u32).take(padding));

    if let Err(err) = soc_manager.start_mailbox_req(cmd, total_bytes, iter) {
        romtime::println!(
            "[mcu-rom] CM_SHA_FINAL start error: {}",
            HexWord(err_code(&err))
        );
        fatal_error(McuError::ROM_COLD_BOOT_ROM_DIGEST_MISMATCH);
    }

    let mut resp_buf = [0u8; core::mem::size_of::<CmShaFinalResp>()];
    if let Err(err) = soc_manager.finish_mailbox_resp_bytes(&mut resp_buf) {
        romtime::println!(
            "[mcu-rom] CM_SHA_FINAL finish error: {}",
            HexWord(err_code(&err))
        );
        fatal_error(McuError::ROM_COLD_BOOT_ROM_DIGEST_MISMATCH);
    }

    // CmShaFinalResp: hdr(8) + data_len(4) + hash(64)
    let mut digest = [0u8; 48];
    match resp_buf.get(12..12 + 48) {
        Some(src) => digest.copy_from_slice(src),
        None => fatal_error(McuError::ROM_COLD_BOOT_ROM_DIGEST_MISMATCH),
    }
    digest
}
