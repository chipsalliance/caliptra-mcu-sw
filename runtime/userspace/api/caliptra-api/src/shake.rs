// Licensed under the Apache-2.0 license

//! Running SHAKE256 via Caliptra `CM_SHAKE256_*` mailbox commands.

use caliptra_api::mailbox::{
    CmShake256FinalReq, CmShake256FinalResp, CmShake256InitReq, CmShake256InitResp,
    CmShake256UpdateReq, CommandId, CMB_SHAKE256_CONTEXT_SIZE, MAX_CMB_DATA_SIZE,
    SHAKE256_MAX_DIGEST_BYTE_SIZE,
};
use core::mem::{offset_of, size_of};
use core::ops::{Deref, DerefMut};
use mcu_error::codes::{INTERNAL_BUG, INVARIANT};
use mcu_error::McuResult;
use zerocopy::{little_endian::U32, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::slice::{checked_slice, checked_slice_mut, copy_bytes};
use crate::wire::{pad4, populate_checksum};
use crate::ApiAlloc;

/// Maximum input bytes sent in one SHAKE256 mailbox request.
pub const SHAKE256_CHUNK_SIZE: usize = 512;

/// Size of the caller-owned encrypted SHAKE256 running context.
pub const SHAKE256_CONTEXT_SIZE: usize = CMB_SHAKE256_CONTEXT_SIZE;

/// SHAKE256 output width exposed by the Caliptra mailbox API.
pub const SHAKE256_OUTPUT_SIZE: usize = SHAKE256_MAX_DIGEST_BYTE_SIZE;

const CMD_CM_SHAKE256_INIT: u32 = CommandId::CM_SHAKE256_INIT.0;
const CMD_CM_SHAKE256_UPDATE: u32 = CommandId::CM_SHAKE256_UPDATE.0;
const CMD_CM_SHAKE256_FINAL: u32 = CommandId::CM_SHAKE256_FINAL.0;
const _: () = assert!(SHAKE256_CHUNK_SIZE <= MAX_CMB_DATA_SIZE);

/// Caliptra-mailbox SHAKE256 running context.
pub struct Shake256State<B> {
    inner: B,
}

impl<B: Deref<Target = [u8]> + DerefMut> Shake256State<B> {
    #[inline]
    fn context(&self) -> McuResult<&[u8]> {
        checked_slice(&self.inner, 0, SHAKE256_CONTEXT_SIZE)
    }

    #[inline]
    fn context_mut(&mut self) -> McuResult<&mut [u8]> {
        checked_slice_mut(&mut self.inner, 0, SHAKE256_CONTEXT_SIZE)
    }
}

#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct Shake256InitPrefix {
    chksum: U32,
    input_size: U32,
}

#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct Shake256UpdatePrefix {
    chksum: U32,
    context: [u8; SHAKE256_CONTEXT_SIZE],
    input_size: U32,
}

#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct Shake256ContextResp {
    _chksum: U32,
    _fips_status: U32,
    context: [u8; SHAKE256_CONTEXT_SIZE],
}

#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct Shake256FinalResp {
    _chksum: U32,
    _fips_status: U32,
    output: [u8; SHAKE256_OUTPUT_SIZE],
}

const _: () = assert!(offset_of!(CmShake256InitReq, input) == size_of::<Shake256InitPrefix>());
const _: () = assert!(offset_of!(CmShake256UpdateReq, input) == size_of::<Shake256UpdatePrefix>());
const _: () = assert!(offset_of!(CmShake256FinalReq, input) == size_of::<Shake256UpdatePrefix>());
const _: () = assert!(size_of::<CmShake256InitResp>() == size_of::<Shake256ContextResp>());
const _: () =
    assert!(offset_of!(CmShake256InitResp, context) == offset_of!(Shake256ContextResp, context));
const _: () = assert!(size_of::<CmShake256FinalResp>() == size_of::<Shake256FinalResp>());
const _: () =
    assert!(offset_of!(CmShake256FinalResp, hash) == offset_of!(Shake256FinalResp, output));

/// Begin a SHAKE256 operation using caller-owned context storage.
#[inline(never)]
pub async fn shake256_init<A: ApiAlloc, B: Deref<Target = [u8]> + DerefMut>(
    alloc: &A,
    mut buffer: B,
    seed: &[u8],
) -> McuResult<Shake256State<B>> {
    checked_slice_mut(&mut buffer, 0, SHAKE256_CONTEXT_SIZE)?.fill(0);
    let mut state = Shake256State { inner: buffer };
    let first_len = seed.len().min(SHAKE256_CHUNK_SIZE);
    shake256_call(
        alloc,
        CMD_CM_SHAKE256_INIT,
        checked_slice(seed, 0, first_len)?,
        &mut state,
        None,
    )
    .await?;
    let remaining = checked_slice(seed, first_len, seed.len() - first_len)?;
    if !remaining.is_empty() {
        shake256_update(alloc, &mut state, remaining).await?;
    }
    Ok(state)
}

/// Append data to a running SHAKE256 operation.
#[inline(never)]
pub async fn shake256_update<A: ApiAlloc, B: Deref<Target = [u8]> + DerefMut>(
    alloc: &A,
    state: &mut Shake256State<B>,
    data: &[u8],
) -> McuResult<()> {
    for chunk in data.chunks(SHAKE256_CHUNK_SIZE) {
        shake256_call(alloc, CMD_CM_SHAKE256_UPDATE, chunk, state, None).await?;
    }
    Ok(())
}

/// Finalize SHAKE256 and return its 64-byte output.
#[inline(never)]
pub async fn shake256_finish<A: ApiAlloc, B: Deref<Target = [u8]> + DerefMut>(
    alloc: &A,
    state: &mut Shake256State<B>,
    output: &mut [u8; SHAKE256_OUTPUT_SIZE],
) -> McuResult<()> {
    shake256_call(alloc, CMD_CM_SHAKE256_FINAL, &[], state, Some(output)).await
}

/// Compute a 64-byte SHAKE256 output over one contiguous input.
#[inline(never)]
pub async fn shake256_hash<A: ApiAlloc>(
    alloc: &A,
    data: &[u8],
    output: &mut [u8; SHAKE256_OUTPUT_SIZE],
) -> McuResult<()> {
    let context = alloc.alloc(SHAKE256_CONTEXT_SIZE)?;
    let mut state = shake256_init(alloc, context, data).await?;
    shake256_finish(alloc, &mut state, output).await
}

async fn shake256_call<A: ApiAlloc, B: Deref<Target = [u8]> + DerefMut>(
    alloc: &A,
    command: u32,
    data: &[u8],
    state: &mut Shake256State<B>,
    output: Option<&mut [u8; SHAKE256_OUTPUT_SIZE]>,
) -> McuResult<()> {
    let request = if command == CMD_CM_SHAKE256_INIT {
        build_shake256_request(alloc, command, None, data)?
    } else {
        build_shake256_request(alloc, command, Some(state.context()?), data)?
    };

    if let Some(output) = output {
        let mut response = alloc.alloc(size_of::<Shake256FinalResp>())?;
        let response_len = crate::wire::mbox_execute(command, &request, &mut response).await?;
        if response_len < size_of::<Shake256FinalResp>() {
            return Err(INTERNAL_BUG);
        }
        let response = Shake256FinalResp::ref_from_bytes(checked_slice(
            &response,
            0,
            size_of::<Shake256FinalResp>(),
        )?)
        .map_err(|_| INTERNAL_BUG)?;
        *output = response.output;
    } else {
        let mut response = alloc.alloc(size_of::<Shake256ContextResp>())?;
        let response_len = crate::wire::mbox_execute(command, &request, &mut response).await?;
        if response_len < size_of::<Shake256ContextResp>() {
            return Err(INTERNAL_BUG);
        }
        let response = Shake256ContextResp::ref_from_bytes(checked_slice(
            &response,
            0,
            size_of::<Shake256ContextResp>(),
        )?)
        .map_err(|_| INTERNAL_BUG)?;
        copy_bytes(state.context_mut()?, &response.context)?;
    }
    Ok(())
}

fn build_shake256_request<'a, A: ApiAlloc>(
    alloc: &'a A,
    command: u32,
    context: Option<&[u8]>,
    data: &[u8],
) -> McuResult<A::Buf<'a>> {
    if data.len() > MAX_CMB_DATA_SIZE {
        return Err(INVARIANT);
    }

    let is_init = command == CMD_CM_SHAKE256_INIT;
    if !is_init && command != CMD_CM_SHAKE256_UPDATE && command != CMD_CM_SHAKE256_FINAL {
        return Err(INVARIANT);
    }
    if is_init != context.is_none() {
        return Err(INVARIANT);
    }

    let prefix_len = if is_init {
        size_of::<Shake256InitPrefix>()
    } else {
        size_of::<Shake256UpdatePrefix>()
    };
    let mut request = alloc.alloc(pad4(prefix_len.checked_add(data.len()).ok_or(INVARIANT)?))?;
    request.fill(0);

    if is_init {
        let prefix =
            Shake256InitPrefix::mut_from_bytes(checked_slice_mut(&mut request, 0, prefix_len)?)
                .map_err(|_| INVARIANT)?;
        prefix.input_size = U32::new(data.len() as u32);
    } else {
        let prefix =
            Shake256UpdatePrefix::mut_from_bytes(checked_slice_mut(&mut request, 0, prefix_len)?)
                .map_err(|_| INVARIANT)?;
        copy_bytes(
            &mut prefix.context,
            checked_slice(context.ok_or(INVARIANT)?, 0, SHAKE256_CONTEXT_SIZE)?,
        )?;
        prefix.input_size = U32::new(data.len() as u32);
    }

    copy_bytes(
        checked_slice_mut(&mut request, prefix_len, data.len())?,
        data,
    )?;
    populate_checksum(command, &mut request)?;
    Ok(request)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::wire::calc_checksum;
    use std::vec::Vec;

    struct TestAlloc;

    impl ApiAlloc for TestAlloc {
        type Buf<'a>
            = Vec<u8>
        where
            Self: 'a;

        fn alloc(&self, len: usize) -> McuResult<Self::Buf<'_>> {
            Ok(std::vec![0; len])
        }
    }

    #[test]
    fn shake256_init_request_preserves_input_and_checksum() {
        let data = [0x5au8; 17];
        let request =
            build_shake256_request(&TestAlloc, CMD_CM_SHAKE256_INIT, None, &data).unwrap();
        let prefix = Shake256InitPrefix::ref_from_prefix(&request).unwrap().0;
        let mut checksum_input = request.clone();
        checksum_input[..4].fill(0);

        assert_eq!(prefix.input_size.get(), data.len() as u32);
        assert_eq!(
            &request[size_of::<Shake256InitPrefix>()..][..data.len()],
            &data
        );
        assert_eq!(
            prefix.chksum.get(),
            calc_checksum(CMD_CM_SHAKE256_INIT, &checksum_input)
        );
    }

    #[test]
    fn shake256_update_request_preserves_context_and_input() {
        let context = [0xa5u8; SHAKE256_CONTEXT_SIZE];
        let data = [0x3cu8; 9];
        let request =
            build_shake256_request(&TestAlloc, CMD_CM_SHAKE256_UPDATE, Some(&context), &data)
                .unwrap();
        let prefix = Shake256UpdatePrefix::ref_from_prefix(&request).unwrap().0;

        assert_eq!(prefix.context, context);
        assert_eq!(prefix.input_size.get(), data.len() as u32);
        assert_eq!(
            &request[size_of::<Shake256UpdatePrefix>()..][..data.len()],
            &data
        );
    }
}
