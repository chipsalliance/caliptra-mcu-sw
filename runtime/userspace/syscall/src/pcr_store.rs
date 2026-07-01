// Licensed under the Apache-2.0 license

//! Userspace API for the Software PCR (Platform Configuration Register) store.
//!
//! ## Kernel commands (synchronous)
//!
//! | Command | Name                 | Arg0      | Allow         |
//! |---------|----------------------|-----------|---------------|
//! | 0       | EXISTS               | —         | —             |
//! | 1       | READ_MEASUREMENT     | pcr_index | RW 0 (output) |
//! | 2       | WRITE_MEASUREMENT    | pcr_index | RO 0 (input)  |
//! | 3       | CLEAR_MEASUREMENTS   | —         | —             |
//!
//! `EXTEND_MEASUREMENT` is implemented entirely in userspace: it reads the
//! current PCR value, computes SHA-384(old || new_data) via the Caliptra
//! mailbox, then calls WRITE_MEASUREMENT with the resulting hash.

use crate::mailbox::Mailbox;
use caliptra_api::mailbox::{
    CmHashAlgorithm, CmShaFinalReq, CmShaFinalResp, CmShaInitReq, CmShaInitResp, CmShaUpdateReq,
    CommandId, MailboxReqHeader, CMB_SHA_CONTEXT_SIZE,
};
use caliptra_mcu_libtock_platform::{ErrorCode, Syscalls};
use zerocopy::{FromBytes, IntoBytes};

use crate::DefaultSyscalls;

/// Driver number for the Software PCR Store kernel capsule.
pub const PCR_STORE_DRIVER_NUM: u32 = 0x8000_0021;

/// Size of one PCR measurement value (SHA-384 = 48 bytes).
pub const PCR_MEASUREMENT_SIZE: usize = 48;

/// Maximum number of PCR indices supported.
pub const PCR_COUNT: usize = 32;

/// Maximum size of data that can be fed into `extend_measurement` in one call.
/// We chunk input through SHA Update calls of this size.
const SHA_CHUNK_SIZE: usize = 256;

mod cmd {
    pub const EXISTS: u32 = 0;
    pub const READ_MEASUREMENT: u32 = 1;
    pub const WRITE_MEASUREMENT: u32 = 2;
    pub const CLEAR_MEASUREMENTS: u32 = 3;
}

/// Synchronous/async interface to the Software PCR Store.
pub struct PcrStore<S: Syscalls = DefaultSyscalls> {
    _syscalls: core::marker::PhantomData<S>,
    driver_num: u32,
}

impl<S: Syscalls> PcrStore<S> {
    pub fn new(driver_num: u32) -> Self {
        Self {
            _syscalls: core::marker::PhantomData,
            driver_num,
        }
    }

    /// Verify the capsule is present.
    pub fn exists(&self) -> Result<(), ErrorCode> {
        S::command(self.driver_num, cmd::EXISTS, 0, 0).to_result()
    }

    /// Read the measurement stored at `pcr_index` into `out`.
    ///
    /// Returns `ErrorCode::Fail` if the PCR index has never been written.
    pub fn read_measurement(
        &self,
        pcr_index: u32,
        out: &mut [u8; PCR_MEASUREMENT_SIZE],
    ) -> Result<(), ErrorCode> {
        allow_rw_command_unallow::<S>(self.driver_num, cmd::READ_MEASUREMENT, pcr_index, out)
    }

    /// Overwrite the measurement at `pcr_index` with `data`.
    pub fn write_measurement(
        &self,
        pcr_index: u32,
        data: &[u8; PCR_MEASUREMENT_SIZE],
    ) -> Result<(), ErrorCode> {
        allow_ro_command_unallow::<S>(self.driver_num, cmd::WRITE_MEASUREMENT, pcr_index, data)
    }

    /// Clear all stored PCR measurements.
    pub fn clear_measurements(&self) -> Result<(), ErrorCode> {
        S::command(self.driver_num, cmd::CLEAR_MEASUREMENTS, 0, 0).to_result()
    }

    /// Extend PCR at `pcr_index`: computes SHA-384(current_value || new_data)
    /// via the Caliptra mailbox and writes the resulting hash back.
    ///
    /// If the PCR has never been written, the current value is treated as
    /// 48 zero bytes.
    pub async fn extend_measurement(
        &self,
        pcr_index: u32,
        new_data: &[u8],
    ) -> Result<(), ErrorCode> {
        // 1. Read the current PCR value (zeros if unset).
        let mut old_value = [0u8; PCR_MEASUREMENT_SIZE];
        let _ = self.read_measurement(pcr_index, &mut old_value);
        // (Ignore error — if unset, old_value remains all-zeros, which is correct.)

        // 2. SHA-384: init with old_value, update with new_data, finalize.
        let new_hash = sha384_extend(&old_value, new_data).await?;

        // 3. Write the new hash back.
        self.write_measurement(pcr_index, &new_hash)
    }
}

/// Compute SHA-384(old_value || new_data) via the Caliptra mailbox.
async fn sha384_extend(
    old_value: &[u8; PCR_MEASUREMENT_SIZE],
    new_data: &[u8],
) -> Result<[u8; PCR_MEASUREMENT_SIZE], ErrorCode> {
    let mbox = Mailbox::new();

    // --- Init: feed old_value ---
    let context = sha384_init(&mbox, old_value).await?;

    // --- Update: feed new_data in chunks ---
    let mut context = context;
    let mut offset = 0;
    while offset < new_data.len() {
        let end = (offset + SHA_CHUNK_SIZE).min(new_data.len());
        context = sha384_update(&mbox, context, &new_data[offset..end]).await?;
        offset = end;
    }

    // --- Finalize ---
    sha384_final(&mbox, context).await
}

async fn sha384_init(mbox: &Mailbox, data: &[u8]) -> Result<[u8; CMB_SHA_CONTEXT_SIZE], ErrorCode> {
    let mut req = CmShaInitReq {
        hdr: MailboxReqHeader::default(),
        hash_algorithm: CmHashAlgorithm::Sha384 as u32,
        input_size: data.len() as u32,
        input: [0u8; caliptra_api::mailbox::MAX_CMB_DATA_SIZE],
    };
    let len = data.len().min(req.input.len());
    req.input[..len].copy_from_slice(&data[..len]);

    let cmd = CommandId::CM_SHA_INIT.0;
    // Trim request bytes to the actual used size to avoid sending 4 KB of zeros.
    let req_len = core::mem::size_of::<MailboxReqHeader>()
        + 4 // hash_algorithm
        + 4 // input_size
        + data.len();
    let req_bytes = &mut req.as_mut_bytes()[..req_len];
    mbox.populate_checksum(cmd, req_bytes)
        .map_err(|_| ErrorCode::Fail)?;

    let resp_buf = &mut [0u8; core::mem::size_of::<CmShaInitResp>()];
    mbox.execute(cmd, req_bytes, resp_buf)
        .await
        .map_err(|_| ErrorCode::Fail)?;

    let resp = CmShaInitResp::ref_from_bytes(resp_buf).map_err(|_| ErrorCode::Fail)?;
    Ok(resp.context)
}

async fn sha384_update(
    mbox: &Mailbox,
    context: [u8; CMB_SHA_CONTEXT_SIZE],
    data: &[u8],
) -> Result<[u8; CMB_SHA_CONTEXT_SIZE], ErrorCode> {
    let mut req = CmShaUpdateReq {
        hdr: MailboxReqHeader::default(),
        context,
        input_size: data.len() as u32,
        input: [0u8; caliptra_api::mailbox::MAX_CMB_DATA_SIZE],
    };
    let len = data.len().min(req.input.len());
    req.input[..len].copy_from_slice(&data[..len]);

    let cmd = CommandId::CM_SHA_UPDATE.0;
    let req_len = core::mem::size_of::<MailboxReqHeader>()
        + CMB_SHA_CONTEXT_SIZE
        + 4 // input_size
        + data.len();
    let req_bytes = &mut req.as_mut_bytes()[..req_len];
    mbox.populate_checksum(cmd, req_bytes)
        .map_err(|_| ErrorCode::Fail)?;

    // CmShaUpdateReq reuses CmShaInitResp for the response.
    let resp_buf = &mut [0u8; core::mem::size_of::<CmShaInitResp>()];
    mbox.execute(cmd, req_bytes, resp_buf)
        .await
        .map_err(|_| ErrorCode::Fail)?;

    let resp = CmShaInitResp::ref_from_bytes(resp_buf).map_err(|_| ErrorCode::Fail)?;
    Ok(resp.context)
}

async fn sha384_final(
    mbox: &Mailbox,
    context: [u8; CMB_SHA_CONTEXT_SIZE],
) -> Result<[u8; PCR_MEASUREMENT_SIZE], ErrorCode> {
    let mut req = CmShaFinalReq {
        hdr: MailboxReqHeader::default(),
        context,
        input_size: 0,
        input: [0u8; caliptra_api::mailbox::MAX_CMB_DATA_SIZE],
    };

    let cmd = CommandId::CM_SHA_FINAL.0;
    // Send only the header + context + input_size (no input bytes).
    let req_len = core::mem::size_of::<MailboxReqHeader>() + CMB_SHA_CONTEXT_SIZE + 4; // input_size = 0
    let req_bytes = &mut req.as_mut_bytes()[..req_len];
    mbox.populate_checksum(cmd, req_bytes)
        .map_err(|_| ErrorCode::Fail)?;

    let resp_buf = &mut [0u8; core::mem::size_of::<CmShaFinalResp>()];
    mbox.execute(cmd, req_bytes, resp_buf)
        .await
        .map_err(|_| ErrorCode::Fail)?;

    let resp = CmShaFinalResp::ref_from_bytes(resp_buf).map_err(|_| ErrorCode::Fail)?;
    let mut hash = [0u8; PCR_MEASUREMENT_SIZE];
    hash.copy_from_slice(&resp.hash[..PCR_MEASUREMENT_SIZE]);
    Ok(hash)
}

// ---------------------------------------------------------------------------
// Shared raw-syscall helpers (same pattern as dpe_handle_store.rs)
// ---------------------------------------------------------------------------

use caliptra_mcu_libtock_platform::{return_variant, syscall_class};

fn allow_rw_command_unallow<S: Syscalls>(
    driver_num: u32,
    cmd: u32,
    arg0: u32,
    buf: &mut [u8],
) -> Result<(), ErrorCode> {
    let allow_result = unsafe {
        S::syscall4::<{ syscall_class::ALLOW_RW }>([
            driver_num.into(),
            0u32.into(), // buffer number 0
            buf.as_mut_ptr().into(),
            buf.len().into(),
        ])
    };

    let rv: return_variant::ReturnVariant = allow_result[0].as_u32().into();
    if rv == return_variant::FAILURE_2_U32 {
        return Err(allow_result[1]
            .as_u32()
            .try_into()
            .unwrap_or(ErrorCode::Fail));
    }

    let result = S::command(driver_num, cmd, arg0, 0).to_result::<(), ErrorCode>();
    S::unallow_rw(driver_num, 0);
    result
}

fn allow_ro_command_unallow<S: Syscalls>(
    driver_num: u32,
    cmd: u32,
    arg0: u32,
    buf: &[u8],
) -> Result<(), ErrorCode> {
    let allow_result = unsafe {
        S::syscall4::<{ syscall_class::ALLOW_RO }>([
            driver_num.into(),
            0u32.into(),
            buf.as_ptr().into(),
            buf.len().into(),
        ])
    };

    let rv: return_variant::ReturnVariant = allow_result[0].as_u32().into();
    if rv == return_variant::FAILURE_2_U32 {
        return Err(allow_result[1]
            .as_u32()
            .try_into()
            .unwrap_or(ErrorCode::Fail));
    }

    let result = S::command(driver_num, cmd, arg0, 0).to_result::<(), ErrorCode>();
    S::unallow_ro(driver_num, 0);
    result
}
