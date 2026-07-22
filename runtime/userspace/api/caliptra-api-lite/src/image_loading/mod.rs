// Licensed under the Apache-2.0 license

mod flash_client;
mod pldm_client;
mod pldm_context;
mod pldm_fdops;

extern crate alloc;

use core::mem::size_of;

use alloc::boxed::Box;
use async_trait::async_trait;
use caliptra_mcu_flash_image::SOC_MANIFEST_IDENTIFIER;
use caliptra_mcu_libsyscall_caliptra::dma::{AXIAddr, DMAMapping};
use caliptra_mcu_libsyscall_caliptra::flash::SpiFlash as FlashSyscall;
use caliptra_mcu_libsyscall_caliptra::mailbox::PayloadStream;
use caliptra_mcu_pldm_common::message::firmware_update::get_fw_params::FirmwareParameters;
use caliptra_mcu_pldm_common::message::firmware_update::verify_complete::VerifyResult;
use caliptra_mcu_pldm_common::protocol::firmware_update::Descriptor;
use embassy_executor::Spawner;
use mcu_error::codes::MAILBOX_BUSY;
use mcu_error::McuResult;
use zerocopy::{little_endian::U32, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::errors::image_loading as image_errors;
use crate::slice::{checked_slice_mut, internal_slice};
use crate::wire::{
    mbox_execute, mbox_execute_with_payload_stream, populate_checksum, CMD_ACTIVATE_FIRMWARE,
    CMD_GET_IMAGE_INFO, CMD_VERIFY_AUTH_MANIFEST, MBOX_RESP_HEADER_SIZE,
};
use crate::ApiAlloc;

/// Width in bytes of an image measurement digest returned by `GET_IMAGE_INFO`.
pub const IMAGE_MEASUREMENT_DIGEST_SIZE: usize = 48;

const MAX_FW_ID_COUNT: usize = 128;
const AUTH_MANIFEST_HEADER_LEN: usize = 8;
const MAX_AUTH_MANIFEST_SIZE: usize = 34 * 1024;
const AUTH_MANIFEST_CHECKSUM_CHUNK: usize = 256;

const GET_IMAGE_INFO_REQ_LEN: usize = size_of::<GetImageInfoReq>();
const GET_IMAGE_INFO_RESP_LEN: usize = size_of::<GetImageInfoResp>();
const ACTIVATE_FIRMWARE_REQ_LEN: usize = size_of::<ActivateFirmwareReq>();
const ACTIVATE_FIRMWARE_RESP_LEN: usize = MBOX_RESP_HEADER_SIZE;

const _: () = assert!(GET_IMAGE_INFO_REQ_LEN == 8);
const _: () = assert!(GET_IMAGE_INFO_RESP_LEN == 80);
const _: () = assert!(ACTIVATE_FIRMWARE_REQ_LEN == 524);
const _: () = assert!(ACTIVATE_FIRMWARE_RESP_LEN == 8);
const _: () = assert!(AUTH_MANIFEST_HEADER_LEN == 8);

/// Image metadata returned after a load operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadedImage {
    pub image_size: u32,
    pub measurement: [u8; IMAGE_MEASUREMENT_DIGEST_SIZE],
}

/// Generic trait for performing source-to-AXI DMA transfers.
#[async_trait(?Send)]
pub trait DmaTransfer: DMAMapping {
    /// Maximum transfer size in one operation.
    fn max_transfer_size(&self) -> usize;

    /// Transfer `length` bytes from `src_offset` to `dest_addr`.
    async fn transfer<A: ApiAlloc>(
        &self,
        alloc: &A,
        src_offset: usize,
        dest_addr: AXIAddr,
        length: usize,
    ) -> McuResult<()>;
}

/// High-level image loader interface.
#[async_trait(?Send)]
pub trait ImageLoader {
    /// Load `image_id` and return Caliptra-provided image metadata.
    async fn load<A: ApiAlloc>(&self, alloc: &A, image_id: u32) -> McuResult<LoadedImage>;
}

pub struct FlashImageLoader<'a, T: DmaTransfer> {
    flash: FlashSyscall,
    dma_transfer: &'a T,
}

pub struct PldmImageLoader<'a, D: DMAMapping + 'static> {
    spawner: Spawner,
    params: &'a PldmFirmwareDeviceParams<'static>,
    dma_mapping: &'static D,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PldmFirmwareDeviceParams<'a> {
    pub descriptors: &'a [Descriptor],
    pub fw_params: &'a FirmwareParameters,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ImageInfo {
    component_id: u32,
    load_address: u64,
    digest: [u8; IMAGE_MEASUREMENT_DIGEST_SIZE],
}

#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct GetImageInfoReq {
    chksum: U32,
    fw_id: [u8; 4],
}

#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct GetImageInfoResp {
    _chksum: U32,
    _fips_status: U32,
    component_id: U32,
    _flags: U32,
    image_load_address_high: U32,
    image_load_address_low: U32,
    _image_staging_address_high: U32,
    _image_staging_address_low: U32,
    digest: [u8; IMAGE_MEASUREMENT_DIGEST_SIZE],
}

#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct ActivateFirmwareReq {
    chksum: U32,
    fw_id_count: U32,
    fw_ids: [U32; MAX_FW_ID_COUNT],
    mcu_fw_image_size: U32,
}

impl<'a, T: DmaTransfer> FlashImageLoader<'a, T> {
    pub fn new(flash_syscall: FlashSyscall, dma_transfer: &'a T) -> Self {
        Self {
            flash: flash_syscall,
            dma_transfer,
        }
    }

    pub async fn set_auth_manifest<A: ApiAlloc>(&self, alloc: &A) -> McuResult<()> {
        let mut header = [0u8; size_of::<caliptra_mcu_flash_image::FlashHeader>()];
        flash_client::flash_read_header(&self.flash, &mut header).await?;
        let (offset, size) =
            flash_client::flash_read_toc(&self.flash, &header, SOC_MANIFEST_IDENTIFIER).await?;
        verify_auth_manifest_from_flash(alloc, &self.flash, offset as usize, size as usize).await
    }
}

#[async_trait(?Send)]
impl<T: DmaTransfer> ImageLoader for FlashImageLoader<'_, T> {
    async fn load<A: ApiAlloc>(&self, alloc: &A, image_id: u32) -> McuResult<LoadedImage> {
        let image_info = get_image_info(alloc, image_id).await?;
        let load_address =
            convert_dma_cptra_addr_to_mcu_addr(self.dma_transfer, image_info.load_address)?;
        let mut header = [0u8; size_of::<caliptra_mcu_flash_image::FlashHeader>()];
        flash_client::flash_read_header(&self.flash, &mut header).await?;
        let (offset, size) =
            flash_client::flash_read_toc(&self.flash, &header, image_info.component_id).await?;
        flash_client::flash_load_image(
            self.dma_transfer,
            alloc,
            load_address,
            offset as usize,
            size as usize,
        )
        .await?;
        Ok(LoadedImage {
            image_size: size,
            measurement: image_info.digest,
        })
    }
}

impl<'a, D: DMAMapping + 'static> PldmImageLoader<'a, D> {
    pub fn new(
        params: &'a PldmFirmwareDeviceParams<'static>,
        spawner: Spawner,
        dma_mapping: &'static D,
    ) -> Self {
        Self {
            spawner,
            params,
            dma_mapping,
        }
    }

    pub fn finalize(&self) -> McuResult<()> {
        pldm_client::finalize(VerifyResult::VerifySuccess)
    }

    /// Wait for the PLDM service to fully stop.
    pub async fn wait_for_service_stopped(&self) {
        pldm_client::wait_service_stopped().await;
    }
}

#[async_trait(?Send)]
impl<D: DMAMapping + 'static> ImageLoader for PldmImageLoader<'_, D> {
    async fn load<A: ApiAlloc>(&self, alloc: &A, image_id: u32) -> McuResult<LoadedImage> {
        let image_info = get_image_info(alloc, image_id).await?;
        let load_address =
            convert_dma_cptra_addr_to_mcu_addr(self.dma_mapping, image_info.load_address)?;

        let result = async {
            pldm_client::initialize_pldm(
                self.spawner,
                self.params.descriptors,
                self.params.fw_params,
                self.dma_mapping,
            )
            .await?;
            let (offset, size) = pldm_client::pldm_download_toc(image_info.component_id).await?;
            pldm_client::pldm_download_image(load_address, offset, size).await?;
            Ok(LoadedImage {
                image_size: size,
                measurement: image_info.digest,
            })
        }
        .await;

        match result {
            Ok(loaded) => Ok(loaded),
            Err(e) => {
                self.finalize()?;
                Err(e)
            }
        }
    }
}

/// Activate a set of SoC firmware IDs.
pub async fn activate_firmware<A: ApiAlloc>(
    alloc: &A,
    fw_ids: &[u32],
    mcu_fw_image_size: u32,
) -> McuResult<()> {
    let req = build_activate_firmware_req(alloc, fw_ids, mcu_fw_image_size)?;
    let mut rsp = [0u8; ACTIVATE_FIRMWARE_RESP_LEN];
    execute_mailbox_retry(CMD_ACTIVATE_FIRMWARE, &req, &mut rsp)
        .await
        .map_err(|_| image_errors::FIRMWARE_ACTIVATION_FAILED)?;
    validate_response_header_len(&rsp, ACTIVATE_FIRMWARE_RESP_LEN)
}

fn build_activate_firmware_req<'a, A: ApiAlloc>(
    alloc: &'a A,
    fw_ids: &[u32],
    mcu_fw_image_size: u32,
) -> McuResult<A::Buf<'a>> {
    if fw_ids.len() > MAX_FW_ID_COUNT {
        return Err(image_errors::FW_ID_COUNT_TOO_LARGE);
    }

    let mut req = alloc.alloc(ACTIVATE_FIRMWARE_REQ_LEN)?;
    req.fill(0);
    {
        let cmd = ActivateFirmwareReq::mut_from_bytes(checked_slice_mut(
            &mut req,
            0,
            ACTIVATE_FIRMWARE_REQ_LEN,
        )?)
        .map_err(|_| image_errors::REQUEST_BUILD_FAILED)?;
        cmd.fw_id_count = U32::new(fw_ids.len() as u32);
        for (dst, fw_id) in cmd.fw_ids.iter_mut().zip(fw_ids.iter()) {
            *dst = U32::new(*fw_id);
        }
        cmd.mcu_fw_image_size = U32::new(mcu_fw_image_size);
    }
    populate_checksum(CMD_ACTIVATE_FIRMWARE, &mut req)?;
    Ok(req)
}

async fn get_image_info<A: ApiAlloc>(alloc: &A, fw_id: u32) -> McuResult<ImageInfo> {
    let mut req = alloc.alloc(GET_IMAGE_INFO_REQ_LEN)?;
    req.fill(0);
    {
        let cmd = GetImageInfoReq::mut_from_bytes(checked_slice_mut(
            &mut req,
            0,
            GET_IMAGE_INFO_REQ_LEN,
        )?)
        .map_err(|_| image_errors::REQUEST_BUILD_FAILED)?;
        cmd.fw_id = fw_id.to_le_bytes();
    }
    populate_checksum(CMD_GET_IMAGE_INFO, &mut req)?;

    let mut rsp = [0u8; GET_IMAGE_INFO_RESP_LEN];
    let rsp_len = execute_mailbox_retry(CMD_GET_IMAGE_INFO, &req, &mut rsp)
        .await
        .map_err(|_| image_errors::GET_IMAGE_INFO_FAILED)?;
    parse_image_info_response(&rsp, rsp_len)
}

fn parse_image_info_response(rsp: &[u8], rsp_len: usize) -> McuResult<ImageInfo> {
    validate_response_header_len(rsp, rsp_len)?;
    if rsp_len < GET_IMAGE_INFO_RESP_LEN {
        return Err(image_errors::IMAGE_INFO_RESPONSE_TOO_SHORT);
    }
    let resp = GetImageInfoResp::ref_from_bytes(internal_slice(rsp, 0, GET_IMAGE_INFO_RESP_LEN)?)
        .map_err(|_| image_errors::IMAGE_INFO_RESPONSE_TOO_SHORT)?;
    Ok(ImageInfo {
        component_id: resp.component_id.get(),
        load_address: ((resp.image_load_address_high.get() as u64) << 32)
            | (resp.image_load_address_low.get() as u64),
        digest: resp.digest,
    })
}

async fn verify_auth_manifest_from_flash<A: ApiAlloc>(
    alloc: &A,
    flash: &FlashSyscall,
    offset: usize,
    size: usize,
) -> McuResult<()> {
    if size > MAX_AUTH_MANIFEST_SIZE {
        return Err(image_errors::AUTH_MANIFEST_TOO_LARGE);
    }

    let mut stream = FlashMailboxPayloadStream::new(flash, offset, size);
    let mut header = [0u8; AUTH_MANIFEST_HEADER_LEN];
    header[4..8].copy_from_slice(&(size as u32).to_le_bytes());

    let mut checksum = stream.get_bytesum(alloc).await?;
    for b in CMD_VERIFY_AUTH_MANIFEST.to_le_bytes().iter() {
        checksum = checksum.wrapping_add(u32::from(*b));
    }
    for b in header.iter() {
        checksum = checksum.wrapping_add(u32::from(*b));
    }
    header[0..4].copy_from_slice(&0u32.wrapping_sub(checksum).to_le_bytes());

    let mut rsp = [0u8; MBOX_RESP_HEADER_SIZE];
    execute_mailbox_stream_retry(
        CMD_VERIFY_AUTH_MANIFEST,
        Some(&header),
        &mut stream,
        &mut rsp,
    )
    .await
    .map_err(|_| image_errors::AUTH_MANIFEST_VERIFICATION_FAILED)?;
    validate_response_header_len(&rsp, MBOX_RESP_HEADER_SIZE)
}

fn validate_response_header_len(rsp: &[u8], rsp_len: usize) -> McuResult<()> {
    if rsp_len < MBOX_RESP_HEADER_SIZE || rsp.len() < MBOX_RESP_HEADER_SIZE {
        return Err(image_errors::MAILBOX_RESPONSE_TOO_SHORT);
    }
    Ok(())
}

async fn execute_mailbox_retry(cmd: u32, req: &[u8], rsp: &mut [u8]) -> McuResult<usize> {
    loop {
        match mbox_execute(cmd, req, rsp).await {
            Err(e) if e == MAILBOX_BUSY => continue,
            result => return result,
        }
    }
}

async fn execute_mailbox_stream_retry(
    cmd: u32,
    header: Option<&[u8]>,
    payload: &mut impl PayloadStream,
    rsp: &mut [u8],
) -> McuResult<usize> {
    loop {
        match mbox_execute_with_payload_stream(cmd, header, payload, rsp).await {
            Err(e) if e == MAILBOX_BUSY => continue,
            result => return result,
        }
    }
}

fn convert_dma_cptra_addr_to_mcu_addr(
    dma_mapping: &(impl DMAMapping + ?Sized),
    caliptra_axi_addr: u64,
) -> McuResult<AXIAddr> {
    dma_mapping
        .cptra_axi_to_mcu_axi(caliptra_axi_addr)
        .map_err(Into::into)
}

struct FlashMailboxPayloadStream<'a> {
    flash: &'a FlashSyscall,
    offset: usize,
    cursor: usize,
    len: usize,
}

impl<'a> FlashMailboxPayloadStream<'a> {
    fn new(flash: &'a FlashSyscall, starting_offset: usize, len: usize) -> Self {
        Self {
            flash,
            offset: starting_offset,
            cursor: starting_offset,
            len,
        }
    }

    fn reset(&mut self) {
        self.cursor = self.offset;
    }

    async fn get_bytesum<A: ApiAlloc>(&mut self, alloc: &A) -> McuResult<u32> {
        self.reset();
        let mut sum = 0u32;
        let mut buffer = alloc.alloc(AUTH_MANIFEST_CHECKSUM_CHUNK)?;
        loop {
            let bytes_read = self.read_chunk(&mut buffer).await?;
            if bytes_read == 0 {
                break;
            }
            for byte in &buffer[..bytes_read] {
                sum = sum.wrapping_add(u32::from(*byte));
            }
        }
        self.reset();
        Ok(sum)
    }

    async fn read_chunk(&mut self, buffer: &mut [u8]) -> McuResult<usize> {
        let consumed = self
            .cursor
            .checked_sub(self.offset)
            .ok_or(image_errors::IMAGE_OFFSET_OVERFLOW)?;
        if consumed >= self.len {
            return Ok(0);
        }
        let bytes_to_read = (self.len - consumed).min(buffer.len());
        let dst = buffer
            .get_mut(..bytes_to_read)
            .ok_or(image_errors::AUTH_MANIFEST_STREAM_FAILED)?;
        self.flash
            .read(self.cursor, bytes_to_read, dst)
            .await
            .map_err(|_| image_errors::AUTH_MANIFEST_STREAM_FAILED)?;
        self.cursor = self
            .cursor
            .checked_add(bytes_to_read)
            .ok_or(image_errors::IMAGE_OFFSET_OVERFLOW)?;
        Ok(bytes_to_read)
    }
}

#[async_trait(?Send)]
impl PayloadStream for FlashMailboxPayloadStream<'_> {
    fn size(&self) -> usize {
        self.len
    }

    async fn read(
        &mut self,
        buffer: &mut [u8],
    ) -> Result<usize, caliptra_mcu_libtock_platform::ErrorCode> {
        self.read_chunk(buffer)
            .await
            .map_err(|_| caliptra_mcu_libtock_platform::ErrorCode::Fail)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec::Vec;

    struct TestAlloc;

    impl ApiAlloc for TestAlloc {
        type Buf<'a>
            = Vec<u8>
        where
            Self: 'a;

        fn alloc(&self, len: usize) -> McuResult<Self::Buf<'_>> {
            let mut buf = Vec::new();
            buf.resize(len, 0);
            Ok(buf)
        }
    }

    #[test]
    fn image_loading_wire_layout() {
        assert_eq!(CMD_GET_IMAGE_INFO, 0x494D_4530);
        assert_eq!(CMD_VERIFY_AUTH_MANIFEST, 0x4154_564D);
        assert_eq!(CMD_ACTIVATE_FIRMWARE, 0x4143_5446);
        assert_eq!(GET_IMAGE_INFO_REQ_LEN, 8);
        assert_eq!(GET_IMAGE_INFO_RESP_LEN, 80);
        assert_eq!(ACTIVATE_FIRMWARE_REQ_LEN, 524);
        assert_eq!(MAX_FW_ID_COUNT, 128);
        assert_eq!(MAX_AUTH_MANIFEST_SIZE, 34 * 1024);
    }

    #[test]
    fn parse_image_info_response_preserves_digest() {
        let mut rsp = [0u8; GET_IMAGE_INFO_RESP_LEN];
        let result = GetImageInfoResp::mut_from_bytes(&mut rsp).map(|resp| {
            resp.component_id = U32::new(0x1000);
            resp.image_load_address_high = U32::new(0x2000);
            resp.image_load_address_low = U32::new(0x3000);
            resp.digest = [0xa5; IMAGE_MEASUREMENT_DIGEST_SIZE];
        });
        assert!(result.is_ok());

        let parsed = parse_image_info_response(&rsp, rsp.len());
        match parsed {
            Ok(parsed) => {
                assert_eq!(parsed.component_id, 0x1000);
                assert_eq!(parsed.load_address, 0x2000_0000_3000);
                assert_eq!(parsed.digest, [0xa5; IMAGE_MEASUREMENT_DIGEST_SIZE]);
            }
            Err(e) => assert_eq!(Some(e), None),
        }
    }

    #[test]
    fn activate_request_rejects_too_many_fw_ids() {
        let alloc = TestAlloc;
        let fw_ids = [0u32; MAX_FW_ID_COUNT + 1];
        assert_eq!(
            build_activate_firmware_req(&alloc, &fw_ids, 0).err(),
            Some(image_errors::FW_ID_COUNT_TOO_LARGE)
        );
    }
}
