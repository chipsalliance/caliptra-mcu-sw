// Licensed under the Apache-2.0 license

//! IDE-KM platform driver abstraction.

use mcu_spdm_lite_codec::{
    IdeRegBlock, KeyInfo, LinkIdeStreamRegBlock, PortConfig, SelectiveIdeStreamRegBlock,
    IDE_STREAM_IV_SIZE_DW, IDE_STREAM_KEY_SIZE_DW,
};
use mcu_spdm_lite_errors::VDM_NO_RESPONSE;
use mcu_spdm_lite_traits::{McuErrorCode, SpdmPalAlloc};
use zerocopy::little_endian::U32;

/// IDE-KM driver-level failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IdeDriverError {
    InvalidPortIndex = 0x01,
    UnsupportedPortIndex = 0x02,
    InvalidStreamId = 0x03,
    InvalidArgument = 0x04,
    GetPortConfigFail = 0x05,
    KeyProgFail = 0x06,
    KeySetGoFail = 0x07,
    KeySetStopFail = 0x08,
    NoMemory = 0x09,
}

/// IDE-KM driver result alias.
pub type IdeDriverResult<T> = core::result::Result<T, IdeDriverError>;

/// Platform abstraction for PCIe IDE key-management hardware.
///
/// The trait uses static dispatch and borrowed little-endian key arrays so
/// spdm-lite does not allocate or copy the KEY_PROG key material before handing
/// it to the platform.
#[allow(async_fn_in_trait)]
pub trait IdeDriver {
    /// Gets the port configuration for a given port index.
    fn port_config<Alloc>(&self, port_index: u8, scratch: &Alloc) -> IdeDriverResult<PortConfig>
    where
        Alloc: SpdmPalAlloc;

    /// Gets the IDE capability/control register block.
    fn ide_reg_block<Alloc>(&self, port_index: u8, scratch: &Alloc) -> IdeDriverResult<IdeRegBlock>
    where
        Alloc: SpdmPalAlloc;

    /// Gets one Link IDE stream register block.
    fn link_ide_reg_block<Alloc>(
        &self,
        port_index: u8,
        block_index: u8,
        scratch: &Alloc,
    ) -> IdeDriverResult<LinkIdeStreamRegBlock>
    where
        Alloc: SpdmPalAlloc;

    /// Gets one Selective IDE stream register block.
    fn selective_ide_reg_block<Alloc>(
        &self,
        port_index: u8,
        block_index: u8,
        scratch: &Alloc,
    ) -> IdeDriverResult<SelectiveIdeStreamRegBlock>
    where
        Alloc: SpdmPalAlloc;

    /// Programs a stream key and IV.
    async fn key_prog<Alloc>(
        &self,
        stream_id: u8,
        key_info: KeyInfo,
        port_index: u8,
        key: &[U32; IDE_STREAM_KEY_SIZE_DW],
        iv: &[U32; IDE_STREAM_IV_SIZE_DW],
        scratch: &Alloc,
    ) -> IdeDriverResult<u8>
    where
        Alloc: SpdmPalAlloc;

    /// Starts using a key set for a stream.
    ///
    /// The IDE-KM `KEY_GO_STOP_ACK` response echoes the request `KeyInfo` for
    /// the wire response, so this hook reports only operation success or failure.
    async fn key_set_go<Alloc>(
        &self,
        stream_id: u8,
        key_info: KeyInfo,
        port_index: u8,
        scratch: &Alloc,
    ) -> IdeDriverResult<()>
    where
        Alloc: SpdmPalAlloc;

    /// Stops using a key set for a stream.
    ///
    /// The IDE-KM `KEY_GO_STOP_ACK` response echoes the request `KeyInfo` for
    /// the wire response, so this hook reports only operation success or failure.
    async fn key_set_stop<Alloc>(
        &self,
        stream_id: u8,
        key_info: KeyInfo,
        port_index: u8,
        scratch: &Alloc,
    ) -> IdeDriverResult<()>
    where
        Alloc: SpdmPalAlloc;
}

impl<T: IdeDriver> IdeDriver for &T {
    fn port_config<Alloc>(&self, port_index: u8, scratch: &Alloc) -> IdeDriverResult<PortConfig>
    where
        Alloc: SpdmPalAlloc,
    {
        (**self).port_config(port_index, scratch)
    }

    fn ide_reg_block<Alloc>(&self, port_index: u8, scratch: &Alloc) -> IdeDriverResult<IdeRegBlock>
    where
        Alloc: SpdmPalAlloc,
    {
        (**self).ide_reg_block(port_index, scratch)
    }

    fn link_ide_reg_block<Alloc>(
        &self,
        port_index: u8,
        block_index: u8,
        scratch: &Alloc,
    ) -> IdeDriverResult<LinkIdeStreamRegBlock>
    where
        Alloc: SpdmPalAlloc,
    {
        (**self).link_ide_reg_block(port_index, block_index, scratch)
    }

    fn selective_ide_reg_block<Alloc>(
        &self,
        port_index: u8,
        block_index: u8,
        scratch: &Alloc,
    ) -> IdeDriverResult<SelectiveIdeStreamRegBlock>
    where
        Alloc: SpdmPalAlloc,
    {
        (**self).selective_ide_reg_block(port_index, block_index, scratch)
    }

    async fn key_prog<Alloc>(
        &self,
        stream_id: u8,
        key_info: KeyInfo,
        port_index: u8,
        key: &[U32; IDE_STREAM_KEY_SIZE_DW],
        iv: &[U32; IDE_STREAM_IV_SIZE_DW],
        scratch: &Alloc,
    ) -> IdeDriverResult<u8>
    where
        Alloc: SpdmPalAlloc,
    {
        (**self)
            .key_prog(stream_id, key_info, port_index, key, iv, scratch)
            .await
    }

    async fn key_set_go<Alloc>(
        &self,
        stream_id: u8,
        key_info: KeyInfo,
        port_index: u8,
        scratch: &Alloc,
    ) -> IdeDriverResult<()>
    where
        Alloc: SpdmPalAlloc,
    {
        (**self)
            .key_set_go(stream_id, key_info, port_index, scratch)
            .await
    }

    async fn key_set_stop<Alloc>(
        &self,
        stream_id: u8,
        key_info: KeyInfo,
        port_index: u8,
        scratch: &Alloc,
    ) -> IdeDriverResult<()>
    where
        Alloc: SpdmPalAlloc,
    {
        (**self)
            .key_set_stop(stream_id, key_info, port_index, scratch)
            .await
    }
}

pub(crate) fn map_ide_error(_err: IdeDriverError) -> McuErrorCode {
    VDM_NO_RESPONSE
}
