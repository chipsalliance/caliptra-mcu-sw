// Licensed under the Apache-2.0 license

//! PCI-SIG IDE-KM VDM responder for SPDM-Lite.

use mcu_spdm_lite_codec::{
    AddrAssociationRegBlock, IdeKmCommand, IdeKmHdr, IdeRegBlock, KeyInfo, LinkIdeStreamRegBlock,
    PciSigProtocolHdr, PortConfig, Query, SelectiveIdeStreamRegBlock, StandardsBodyId, WireReader,
    WireWriter, IDE_KM_PROTOCOL_ID, IDE_STREAM_IV_SIZE_DW, IDE_STREAM_KEY_SIZE_DW,
    MAX_SELECTIVE_IDE_ADDR_ASSOC_BLOCK_COUNT,
};
#[cfg(any(test, feature = "emulated-ide-km"))]
use mcu_spdm_lite_codec::{
    IdeCapabilityReg, IdeControlReg, LinkIdeStreamControlReg, LinkIdeStreamStatusReg,
    SelectiveIdeRidAssociationReg1, SelectiveIdeRidAssociationReg2,
    SelectiveIdeStreamCapabilityReg, SelectiveIdeStreamControlReg, SelectiveIdeStreamStatusReg,
};
use zerocopy::little_endian::U32;

use mcu_spdm_lite_codec::errors::{
    SPDM_INVALID_REQUEST, SPDM_UNSPECIFIED, SPDM_UNSUPPORTED_REQUEST,
};
use mcu_spdm_lite_traits::{
    McuErrorCode, McuResult, SpdmPalAlloc, SpdmPalIo, SpdmVdmBackend, VdmRegistry, VdmResponse,
    VdmResponseBuffer,
};

const MAX_IDE_KM_QUERY_RESPONSE_SIZE: usize = PciSigProtocolHdr::SIZE
    + IdeKmHdr::SIZE
    + Query::SIZE
    + PortConfig::SIZE
    + IdeRegBlock::SIZE
    + (7 * LinkIdeStreamRegBlock::SIZE)
    + (255
        * (SelectiveIdeStreamRegBlock::FIXED_SIZE
            + MAX_SELECTIVE_IDE_ADDR_ASSOC_BLOCK_COUNT * AddrAssociationRegBlock::SIZE));

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
/// The trait mirrors the libspdm IDE-KM driver API but uses static dispatch and
/// borrowed little-endian key arrays so spdm-lite does not allocate or copy the
/// KEY_PROG key material before handing it to the platform.
#[allow(async_fn_in_trait)]
pub trait IdeDriver: Sync {
    /// Gets the port configuration for a given port index.
    fn port_config(&self, port_index: u8) -> IdeDriverResult<PortConfig>;

    /// Gets the IDE capability/control register block.
    fn ide_reg_block(&self, port_index: u8) -> IdeDriverResult<IdeRegBlock>;

    /// Gets one Link IDE stream register block.
    fn link_ide_reg_block(
        &self,
        port_index: u8,
        block_index: u8,
    ) -> IdeDriverResult<LinkIdeStreamRegBlock>;

    /// Gets one Selective IDE stream register block.
    fn selective_ide_reg_block(
        &self,
        port_index: u8,
        block_index: u8,
    ) -> IdeDriverResult<SelectiveIdeStreamRegBlock>;

    /// Programs a stream key and IV.
    async fn key_prog(
        &self,
        stream_id: u8,
        key_info: KeyInfo,
        port_index: u8,
        key: &[U32; IDE_STREAM_KEY_SIZE_DW],
        iv: &[U32; IDE_STREAM_IV_SIZE_DW],
    ) -> IdeDriverResult<u8>;

    /// Starts using a key set for a stream.
    ///
    /// The IDE-KM `KEY_GO_STOP_ACK` response echoes the request `KeyInfo` for
    /// libspdm compatibility, so this hook reports only operation success or
    /// failure.
    async fn key_set_go(
        &self,
        stream_id: u8,
        key_info: KeyInfo,
        port_index: u8,
    ) -> IdeDriverResult<()>;

    /// Stops using a key set for a stream.
    ///
    /// The IDE-KM `KEY_GO_STOP_ACK` response echoes the request `KeyInfo` for
    /// libspdm compatibility, so this hook reports only operation success or
    /// failure.
    async fn key_set_stop(
        &self,
        stream_id: u8,
        key_info: KeyInfo,
        port_index: u8,
    ) -> IdeDriverResult<()>;
}

impl<T: IdeDriver + ?Sized> IdeDriver for &T {
    fn port_config(&self, port_index: u8) -> IdeDriverResult<PortConfig> {
        (**self).port_config(port_index)
    }

    fn ide_reg_block(&self, port_index: u8) -> IdeDriverResult<IdeRegBlock> {
        (**self).ide_reg_block(port_index)
    }

    fn link_ide_reg_block(
        &self,
        port_index: u8,
        block_index: u8,
    ) -> IdeDriverResult<LinkIdeStreamRegBlock> {
        (**self).link_ide_reg_block(port_index, block_index)
    }

    fn selective_ide_reg_block(
        &self,
        port_index: u8,
        block_index: u8,
    ) -> IdeDriverResult<SelectiveIdeStreamRegBlock> {
        (**self).selective_ide_reg_block(port_index, block_index)
    }

    async fn key_prog(
        &self,
        stream_id: u8,
        key_info: KeyInfo,
        port_index: u8,
        key: &[U32; IDE_STREAM_KEY_SIZE_DW],
        iv: &[U32; IDE_STREAM_IV_SIZE_DW],
    ) -> IdeDriverResult<u8> {
        (**self)
            .key_prog(stream_id, key_info, port_index, key, iv)
            .await
    }

    async fn key_set_go(
        &self,
        stream_id: u8,
        key_info: KeyInfo,
        port_index: u8,
    ) -> IdeDriverResult<()> {
        (**self).key_set_go(stream_id, key_info, port_index).await
    }

    async fn key_set_stop(
        &self,
        stream_id: u8,
        key_info: KeyInfo,
        port_index: u8,
    ) -> IdeDriverResult<()> {
        (**self).key_set_stop(stream_id, key_info, port_index).await
    }
}

/// IDE-KM protocol responder.
pub struct IdeKmResponder<D> {
    driver: D,
}

impl<D> IdeKmResponder<D> {
    /// Creates an IDE-KM responder over a platform driver.
    pub const fn new(driver: D) -> Self {
        Self { driver }
    }

    /// Returns the wrapped IDE driver.
    pub const fn driver(&self) -> &D {
        &self.driver
    }
}

impl<D: IdeDriver> IdeKmResponder<D> {
    /// Handles an IDE-KM request payload after the PCI-SIG protocol byte.
    pub async fn handle_request(&self, req: &[u8], rsp: &mut [u8]) -> McuResult<usize> {
        let mut reader = WireReader::new(req);
        let hdr = *reader
            .read::<IdeKmHdr>()
            .map_err(|_| SPDM_INVALID_REQUEST)?;
        let command = IdeKmCommand::from_u8(hdr.object_id).ok_or(SPDM_INVALID_REQUEST)?;
        if reader.remaining() != command.payload_len() || command.response().is_none() {
            return Err(SPDM_INVALID_REQUEST);
        }

        let mut writer = WireWriter::new(rsp);
        match command {
            IdeKmCommand::Query => self.handle_query(&mut reader, &mut writer),
            IdeKmCommand::KeyProg => self.handle_key_prog(&mut reader, &mut writer).await,
            IdeKmCommand::KeySetGo => {
                self.handle_key_set_go_stop(true, &mut reader, &mut writer)
                    .await
            }
            IdeKmCommand::KeySetStop => {
                self.handle_key_set_go_stop(false, &mut reader, &mut writer)
                    .await
            }
            _ => Err(SPDM_INVALID_REQUEST),
        }
    }

    fn handle_query(
        &self,
        reader: &mut WireReader<'_>,
        writer: &mut WireWriter<'_>,
    ) -> McuResult<usize> {
        let query = *reader.read::<Query>().map_err(|_| SPDM_INVALID_REQUEST)?;
        writer
            .write(&IdeKmHdr {
                object_id: IdeKmCommand::QueryResp as u8,
            })
            .map_err(|_| SPDM_INVALID_REQUEST)?;
        writer
            .write(&Query {
                reserved: 0,
                port_index: query.port_index,
            })
            .map_err(|_| SPDM_INVALID_REQUEST)?;

        let port_config = self
            .driver
            .port_config(query.port_index)
            .map_err(map_ide_error)?;
        writer
            .write(&port_config)
            .map_err(|_| SPDM_INVALID_REQUEST)?;

        let ide_reg_block = self
            .driver
            .ide_reg_block(query.port_index)
            .map_err(map_ide_error)?;
        writer
            .write(&ide_reg_block)
            .map_err(|_| SPDM_INVALID_REQUEST)?;

        let ide_cap_reg = ide_reg_block.ide_cap_reg;
        if ide_cap_reg.link_ide_stream_supported() == 1 {
            for block_index in 0..ide_cap_reg.num_tcs_supported_for_link_ide() {
                let block = self
                    .driver
                    .link_ide_reg_block(query.port_index, block_index)
                    .map_err(map_ide_error)?;
                writer.write(&block).map_err(|_| SPDM_INVALID_REQUEST)?;
            }
        }

        if ide_cap_reg.selective_ide_stream_supported() == 1 {
            for block_index in 0..ide_cap_reg.num_selective_ide_streams_supported() {
                let block = self
                    .driver
                    .selective_ide_reg_block(query.port_index, block_index)
                    .map_err(map_ide_error)?;
                block.encode(writer).map_err(|_| SPDM_INVALID_REQUEST)?;
            }
        }

        Ok(writer.position())
    }

    async fn handle_key_prog(
        &self,
        reader: &mut WireReader<'_>,
        writer: &mut WireWriter<'_>,
    ) -> McuResult<usize> {
        let mut key_prog = *reader
            .read::<mcu_spdm_lite_codec::KeyProg>()
            .map_err(|_| SPDM_INVALID_REQUEST)?;
        let key_data = reader
            .read::<mcu_spdm_lite_codec::KeyData>()
            .map_err(|_| SPDM_INVALID_REQUEST)?;
        let status = self
            .driver
            .key_prog(
                key_prog.stream_id,
                key_prog.key_info,
                key_prog.port_index,
                &key_data.key,
                &key_data.iv,
            )
            .await
            .map_err(map_ide_error)?;

        key_prog.status = status;
        writer
            .write(&IdeKmHdr {
                object_id: IdeKmCommand::KeyProgAck as u8,
            })
            .map_err(|_| SPDM_INVALID_REQUEST)?;
        writer.write(&key_prog).map_err(|_| SPDM_INVALID_REQUEST)?;
        Ok(writer.position())
    }

    async fn handle_key_set_go_stop(
        &self,
        key_set_go: bool,
        reader: &mut WireReader<'_>,
        writer: &mut WireWriter<'_>,
    ) -> McuResult<usize> {
        let key_set_go_stop = *reader
            .read::<mcu_spdm_lite_codec::KeySetGoStop>()
            .map_err(|_| SPDM_INVALID_REQUEST)?;
        if key_set_go {
            self.driver
                .key_set_go(
                    key_set_go_stop.stream_id,
                    key_set_go_stop.key_info,
                    key_set_go_stop.port_index,
                )
                .await
                .map_err(map_ide_error)?;
        } else {
            self.driver
                .key_set_stop(
                    key_set_go_stop.stream_id,
                    key_set_go_stop.key_info,
                    key_set_go_stop.port_index,
                )
                .await
                .map_err(map_ide_error)?;
        }

        writer
            .write(&IdeKmHdr {
                object_id: IdeKmCommand::KeyGoStopAck as u8,
            })
            .map_err(|_| SPDM_INVALID_REQUEST)?;
        writer
            .write(&mcu_spdm_lite_codec::KeySetGoStop {
                reserved1: 0.into(),
                stream_id: key_set_go_stop.stream_id,
                reserved2: 0,
                key_info: key_set_go_stop.key_info,
                port_index: key_set_go_stop.port_index,
            })
            .map_err(|_| SPDM_INVALID_REQUEST)?;
        Ok(writer.position())
    }
}

/// PCI-SIG VDM backend with the IDE-KM protocol enabled.
pub struct PciSigIdeKmVdm<D> {
    vendor_id: u16,
    ide_km: IdeKmResponder<D>,
}

impl<D> PciSigIdeKmVdm<D> {
    /// Creates a PCI-SIG VDM backend for a PCI-SIG vendor ID and IDE-KM driver.
    pub const fn new(vendor_id: u16, driver: D) -> Self {
        Self {
            vendor_id,
            ide_km: IdeKmResponder::new(driver),
        }
    }

    /// Returns the PCI-SIG vendor ID matched by this backend.
    pub const fn vendor_id(&self) -> u16 {
        self.vendor_id
    }

    /// Returns the IDE-KM responder.
    pub const fn ide_km(&self) -> &IdeKmResponder<D> {
        &self.ide_km
    }
}

impl<D: IdeDriver> PciSigIdeKmVdm<D> {
    async fn handle_ide_km_protocol_payload(
        &self,
        protocol_id: u8,
        req: &[u8],
        out: &mut [u8],
    ) -> McuResult<usize> {
        let Some((protocol_out, ide_out)) = out.split_first_mut() else {
            return Err(SPDM_UNSPECIFIED);
        };
        *protocol_out = protocol_id;
        let ide_len = self.ide_km.handle_request(req, ide_out).await?;
        Ok(PciSigProtocolHdr::SIZE + ide_len)
    }

    fn query_response_size(&self, ide_km_payload: &[u8]) -> McuResult<Option<usize>> {
        if !is_query_request(ide_km_payload) {
            return Ok(None);
        }

        let mut reader = WireReader::new(ide_km_payload);
        let _hdr = reader
            .read::<IdeKmHdr>()
            .map_err(|_| SPDM_INVALID_REQUEST)?;
        if reader.remaining() != IdeKmCommand::Query.payload_len() {
            return Err(SPDM_INVALID_REQUEST);
        }
        let query = *reader.read::<Query>().map_err(|_| SPDM_INVALID_REQUEST)?;

        let ide_reg_block = self
            .ide_km
            .driver
            .ide_reg_block(query.port_index)
            .map_err(map_ide_error)?;
        let ide_cap_reg = ide_reg_block.ide_cap_reg;
        let mut len = PciSigProtocolHdr::SIZE
            + IdeKmHdr::SIZE
            + Query::SIZE
            + PortConfig::SIZE
            + IdeRegBlock::SIZE;

        if ide_cap_reg.link_ide_stream_supported() == 1 {
            len = len
                .checked_add(
                    ide_cap_reg.num_tcs_supported_for_link_ide() as usize
                        * LinkIdeStreamRegBlock::SIZE,
                )
                .ok_or(SPDM_UNSPECIFIED)?;
        }

        if ide_cap_reg.selective_ide_stream_supported() == 1 {
            for block_index in 0..ide_cap_reg.num_selective_ide_streams_supported() {
                let block = self
                    .ide_km
                    .driver
                    .selective_ide_reg_block(query.port_index, block_index)
                    .map_err(map_ide_error)?;
                let count = block.capability_reg.num_addr_association_reg_blocks() as usize;
                if count > MAX_SELECTIVE_IDE_ADDR_ASSOC_BLOCK_COUNT {
                    return Err(SPDM_UNSPECIFIED);
                }
                len = len
                    .checked_add(
                        SelectiveIdeStreamRegBlock::FIXED_SIZE
                            + count * AddrAssociationRegBlock::SIZE,
                    )
                    .ok_or(SPDM_UNSPECIFIED)?;
            }
        }

        Ok(Some(len))
    }
}

impl<D: IdeDriver> SpdmVdmBackend for PciSigIdeKmVdm<D> {
    const USES_LARGE_RESPONSE: bool = true;
    const LARGE_RESPONSE_CAPACITY: usize = MAX_IDE_KM_QUERY_RESPONSE_SIZE;

    fn large_response_capacity(&self, req: &[u8]) -> usize {
        let mut reader = WireReader::new(req);
        let Ok(pci_sig_hdr) = reader.read::<PciSigProtocolHdr>() else {
            return 0;
        };
        if pci_sig_hdr.protocol_id != IDE_KM_PROTOCOL_ID {
            return 0;
        }
        self.query_response_size(reader.rest())
            .ok()
            .flatten()
            .unwrap_or(0)
    }

    fn match_id(&self, registry: &VdmRegistry<'_>) -> bool {
        registry.standard_id == StandardsBodyId::PciSig.as_u16()
            && registry.vendor_id == self.vendor_id.to_le_bytes()
            && registry.secure_session
    }

    async fn handle_request<Alloc, Io>(
        &self,
        req: &[u8],
        rsp: VdmResponseBuffer<'_, Alloc, Io>,
    ) -> McuResult<VdmResponse>
    where
        Alloc: SpdmPalAlloc,
        Io: SpdmPalIo,
    {
        let mut reader = WireReader::new(req);
        let pci_sig_hdr = *reader
            .read::<PciSigProtocolHdr>()
            .map_err(|_| SPDM_INVALID_REQUEST)?;
        if pci_sig_hdr.protocol_id != IDE_KM_PROTOCOL_ID {
            return Err(SPDM_UNSUPPORTED_REQUEST);
        }

        let ide_km_payload = reader.rest();
        if let Some(query_rsp_len) = self.query_response_size(ide_km_payload)? {
            if query_rsp_len > rsp.inline.len() {
                if query_rsp_len <= rsp.large.len() {
                    let len = self
                        .handle_ide_km_protocol_payload(
                            pci_sig_hdr.protocol_id,
                            ide_km_payload,
                            rsp.large,
                        )
                        .await?;
                    return Ok(VdmResponse::Large(len));
                }
                return Err(SPDM_UNSPECIFIED);
            }
        }

        let len = self
            .handle_ide_km_protocol_payload(pci_sig_hdr.protocol_id, ide_km_payload, rsp.inline)
            .await?;
        Ok(VdmResponse::Inline(len))
    }
}

/// Simple no-allocation IDE-KM emulator driver used by validator tests.
#[cfg(any(test, feature = "emulated-ide-km"))]
#[derive(Debug, Clone, Copy)]
pub struct EmulatedIdeDriver {
    pub port_index: u8,
    pub function_num: u8,
    pub bus_num: u8,
    pub segment: u8,
    pub num_link_ide_streams: u8,
    pub num_selective_ide_streams: u8,
    pub num_addr_association_reg_blocks: u8,
}

#[cfg(any(test, feature = "emulated-ide-km"))]
impl Default for EmulatedIdeDriver {
    fn default() -> Self {
        Self {
            port_index: 0,
            function_num: 0,
            bus_num: 0,
            segment: 0,
            num_link_ide_streams: 1,
            num_selective_ide_streams: 1,
            num_addr_association_reg_blocks: 1,
        }
    }
}

#[cfg(any(test, feature = "emulated-ide-km"))]
impl IdeDriver for EmulatedIdeDriver {
    fn port_config(&self, port_index: u8) -> IdeDriverResult<PortConfig> {
        self.check_port(port_index)?;
        Ok(PortConfig {
            function_num: self.function_num,
            bus_num: self.bus_num,
            segment: self.segment,
            max_port_index: self.port_index,
        })
    }

    fn ide_reg_block(&self, port_index: u8) -> IdeDriverResult<IdeRegBlock> {
        self.check_port(port_index)?;
        let mut ide_cap_reg = IdeCapabilityReg::default();
        ide_cap_reg.set_link_ide_stream_supported(1);
        ide_cap_reg.set_selective_ide_stream_supported(1);
        ide_cap_reg.set_ide_km_protocol_supported(1);
        ide_cap_reg.set_num_tcs_supported_for_link_ide(self.num_link_ide_streams);
        ide_cap_reg.set_num_selective_ide_streams_supported(self.num_selective_ide_streams);

        let mut ide_ctrl_reg = IdeControlReg::default();
        ide_ctrl_reg.set_flow_through_ide_stream_enabled(1);
        Ok(IdeRegBlock {
            ide_cap_reg,
            ide_ctrl_reg,
        })
    }

    fn link_ide_reg_block(
        &self,
        port_index: u8,
        block_index: u8,
    ) -> IdeDriverResult<LinkIdeStreamRegBlock> {
        self.check_port(port_index)?;
        if block_index >= self.num_link_ide_streams {
            return Err(IdeDriverError::InvalidStreamId);
        }
        let mut ctrl_reg = LinkIdeStreamControlReg::default();
        ctrl_reg.set_link_ide_stream_enable(1);
        ctrl_reg.set_pcrc_enable(1);
        ctrl_reg.set_selected_algorithm(5);
        ctrl_reg.set_tc(block_index & 0x7);
        ctrl_reg.set_stream_id(block_index);

        let mut status_reg = LinkIdeStreamStatusReg::default();
        status_reg.set_link_ide_stream_state(7);
        Ok(LinkIdeStreamRegBlock {
            ctrl_reg,
            status_reg,
        })
    }

    fn selective_ide_reg_block(
        &self,
        port_index: u8,
        block_index: u8,
    ) -> IdeDriverResult<SelectiveIdeStreamRegBlock> {
        self.check_port(port_index)?;
        if block_index >= self.num_selective_ide_streams {
            return Err(IdeDriverError::InvalidStreamId);
        }

        let mut capability_reg = SelectiveIdeStreamCapabilityReg::default();
        capability_reg.set_num_addr_association_reg_blocks(
            self.num_addr_association_reg_blocks
                .min(MAX_SELECTIVE_IDE_ADDR_ASSOC_BLOCK_COUNT as u8),
        );

        let mut ctrl_reg = SelectiveIdeStreamControlReg::default();
        ctrl_reg.set_selective_ide_stream_enable(1);
        ctrl_reg.set_pcrc_enable(1);
        ctrl_reg.set_selective_ide_for_config_req_enable(1);
        ctrl_reg.set_selected_algorithm(4);
        ctrl_reg.set_tc(block_index & 0x7);
        ctrl_reg.set_default_stream(1);
        ctrl_reg.set_stream_id(block_index);

        let mut status_reg = SelectiveIdeStreamStatusReg::default();
        status_reg.set_selective_ide_stream_state(5);

        let mut rid_association_reg_1 = SelectiveIdeRidAssociationReg1::default();
        rid_association_reg_1.set_rid_limit(0x1234);
        let mut rid_association_reg_2 = SelectiveIdeRidAssociationReg2::default();
        rid_association_reg_2.set_valid(1);
        rid_association_reg_2.set_rid_base(0x5678);

        let mut addr_association_reg_block =
            [AddrAssociationRegBlock::default(); MAX_SELECTIVE_IDE_ADDR_ASSOC_BLOCK_COUNT];
        for reg in addr_association_reg_block
            .iter_mut()
            .take(capability_reg.num_addr_association_reg_blocks() as usize)
        {
            reg.reg1.set_valid(1);
            reg.reg1.set_memory_base_lower(0x12);
            reg.reg1.set_memory_limit_lower(0x34);
            reg.reg2.memory_limit_upper = U32::new(0x1234_5678);
            reg.reg3.memory_base_upper = U32::new(0x8765_4321);
        }

        Ok(SelectiveIdeStreamRegBlock {
            capability_reg,
            ctrl_reg,
            status_reg,
            rid_association_reg_1,
            rid_association_reg_2,
            addr_association_reg_block,
        })
    }

    async fn key_prog(
        &self,
        _stream_id: u8,
        _key_info: KeyInfo,
        port_index: u8,
        _key: &[U32; IDE_STREAM_KEY_SIZE_DW],
        _iv: &[U32; IDE_STREAM_IV_SIZE_DW],
    ) -> IdeDriverResult<u8> {
        self.check_port(port_index)?;
        Ok(0)
    }

    async fn key_set_go(
        &self,
        _stream_id: u8,
        key_info: KeyInfo,
        port_index: u8,
    ) -> IdeDriverResult<()> {
        self.check_port(port_index)?;
        let _ = key_info;
        Ok(())
    }

    async fn key_set_stop(
        &self,
        _stream_id: u8,
        key_info: KeyInfo,
        port_index: u8,
    ) -> IdeDriverResult<()> {
        self.check_port(port_index)?;
        let _ = key_info;
        Ok(())
    }
}

#[cfg(any(test, feature = "emulated-ide-km"))]
impl EmulatedIdeDriver {
    fn check_port(&self, port_index: u8) -> IdeDriverResult<()> {
        if port_index == self.port_index {
            Ok(())
        } else {
            Err(IdeDriverError::InvalidPortIndex)
        }
    }
}

fn is_query_request(ide_km_payload: &[u8]) -> bool {
    ide_km_payload.first().copied() == Some(IdeKmCommand::Query as u8)
}

fn map_ide_error(_: IdeDriverError) -> McuErrorCode {
    SPDM_UNSPECIFIED
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::marker::PhantomData;
    use core::ops::{Deref, DerefMut};

    use futures::executor::block_on;
    use mcu_spdm_lite_codec::IDE_KM_PROTOCOL_ID;
    use std::boxed::Box;
    use std::vec;
    use std::vec::Vec;

    use super::*;

    const VENDOR_ID_BYTES: [u8; 2] = 0x1234u16.to_le_bytes();

    #[derive(Clone, Copy)]
    struct StatusDriver {
        key_prog_status: u8,
    }

    impl IdeDriver for StatusDriver {
        fn port_config(&self, port_index: u8) -> IdeDriverResult<PortConfig> {
            EmulatedIdeDriver::default().port_config(port_index)
        }

        fn ide_reg_block(&self, port_index: u8) -> IdeDriverResult<IdeRegBlock> {
            EmulatedIdeDriver::default().ide_reg_block(port_index)
        }

        fn link_ide_reg_block(
            &self,
            port_index: u8,
            block_index: u8,
        ) -> IdeDriverResult<LinkIdeStreamRegBlock> {
            EmulatedIdeDriver::default().link_ide_reg_block(port_index, block_index)
        }

        fn selective_ide_reg_block(
            &self,
            port_index: u8,
            block_index: u8,
        ) -> IdeDriverResult<SelectiveIdeStreamRegBlock> {
            EmulatedIdeDriver::default().selective_ide_reg_block(port_index, block_index)
        }

        async fn key_prog(
            &self,
            _stream_id: u8,
            _key_info: KeyInfo,
            _port_index: u8,
            _key: &[U32; IDE_STREAM_KEY_SIZE_DW],
            _iv: &[U32; IDE_STREAM_IV_SIZE_DW],
        ) -> IdeDriverResult<u8> {
            Ok(self.key_prog_status)
        }

        async fn key_set_go(
            &self,
            _stream_id: u8,
            _key_info: KeyInfo,
            _port_index: u8,
        ) -> IdeDriverResult<()> {
            Ok(())
        }

        async fn key_set_stop(
            &self,
            _stream_id: u8,
            _key_info: KeyInfo,
            _port_index: u8,
        ) -> IdeDriverResult<()> {
            Ok(())
        }
    }

    #[derive(Clone, Copy)]
    struct StopOnlyDriver;

    impl IdeDriver for StopOnlyDriver {
        fn port_config(&self, port_index: u8) -> IdeDriverResult<PortConfig> {
            EmulatedIdeDriver::default().port_config(port_index)
        }

        fn ide_reg_block(&self, port_index: u8) -> IdeDriverResult<IdeRegBlock> {
            EmulatedIdeDriver::default().ide_reg_block(port_index)
        }

        fn link_ide_reg_block(
            &self,
            port_index: u8,
            block_index: u8,
        ) -> IdeDriverResult<LinkIdeStreamRegBlock> {
            EmulatedIdeDriver::default().link_ide_reg_block(port_index, block_index)
        }

        fn selective_ide_reg_block(
            &self,
            port_index: u8,
            block_index: u8,
        ) -> IdeDriverResult<SelectiveIdeStreamRegBlock> {
            EmulatedIdeDriver::default().selective_ide_reg_block(port_index, block_index)
        }

        async fn key_prog(
            &self,
            _stream_id: u8,
            _key_info: KeyInfo,
            _port_index: u8,
            _key: &[U32; IDE_STREAM_KEY_SIZE_DW],
            _iv: &[U32; IDE_STREAM_IV_SIZE_DW],
        ) -> IdeDriverResult<u8> {
            Err(IdeDriverError::KeyProgFail)
        }

        async fn key_set_go(
            &self,
            _stream_id: u8,
            _key_info: KeyInfo,
            _port_index: u8,
        ) -> IdeDriverResult<()> {
            Err(IdeDriverError::KeySetGoFail)
        }

        async fn key_set_stop(
            &self,
            _stream_id: u8,
            _key_info: KeyInfo,
            _port_index: u8,
        ) -> IdeDriverResult<()> {
            Ok(())
        }
    }

    #[derive(Clone, Copy)]
    struct VerifyingKeyProgDriver {
        expected_stream_id: u8,
        expected_key_info: KeyInfo,
        expected_port_index: u8,
        expected_key: [u32; IDE_STREAM_KEY_SIZE_DW],
        expected_iv: [u32; IDE_STREAM_IV_SIZE_DW],
        status: u8,
    }

    impl IdeDriver for VerifyingKeyProgDriver {
        fn port_config(&self, port_index: u8) -> IdeDriverResult<PortConfig> {
            EmulatedIdeDriver::default().port_config(port_index)
        }

        fn ide_reg_block(&self, port_index: u8) -> IdeDriverResult<IdeRegBlock> {
            EmulatedIdeDriver::default().ide_reg_block(port_index)
        }

        fn link_ide_reg_block(
            &self,
            port_index: u8,
            block_index: u8,
        ) -> IdeDriverResult<LinkIdeStreamRegBlock> {
            EmulatedIdeDriver::default().link_ide_reg_block(port_index, block_index)
        }

        fn selective_ide_reg_block(
            &self,
            port_index: u8,
            block_index: u8,
        ) -> IdeDriverResult<SelectiveIdeStreamRegBlock> {
            EmulatedIdeDriver::default().selective_ide_reg_block(port_index, block_index)
        }

        async fn key_prog(
            &self,
            stream_id: u8,
            key_info: KeyInfo,
            port_index: u8,
            key: &[U32; IDE_STREAM_KEY_SIZE_DW],
            iv: &[U32; IDE_STREAM_IV_SIZE_DW],
        ) -> IdeDriverResult<u8> {
            assert_eq!(stream_id, self.expected_stream_id);
            assert_eq!(key_info, self.expected_key_info);
            assert_eq!(port_index, self.expected_port_index);
            for (actual, expected) in key.iter().zip(self.expected_key.iter()) {
                assert_eq!(actual.get(), *expected);
            }
            for (actual, expected) in iv.iter().zip(self.expected_iv.iter()) {
                assert_eq!(actual.get(), *expected);
            }
            Ok(self.status)
        }

        async fn key_set_go(
            &self,
            _stream_id: u8,
            _key_info: KeyInfo,
            _port_index: u8,
        ) -> IdeDriverResult<()> {
            Err(IdeDriverError::KeySetGoFail)
        }

        async fn key_set_stop(
            &self,
            _stream_id: u8,
            _key_info: KeyInfo,
            _port_index: u8,
        ) -> IdeDriverResult<()> {
            Err(IdeDriverError::KeySetStopFail)
        }
    }

    fn pci_sig_registry(secure_session: bool) -> VdmRegistry<'static> {
        VdmRegistry {
            standard_id: StandardsBodyId::PciSig.as_u16(),
            vendor_id: &VENDOR_ID_BYTES,
            secure_session,
        }
    }

    struct TestBox<'a, T: 'a> {
        value: Box<T>,
        _lifetime: PhantomData<&'a ()>,
    }

    impl<T> Deref for TestBox<'_, T> {
        type Target = T;

        fn deref(&self) -> &Self::Target {
            &self.value
        }
    }

    impl<T> DerefMut for TestBox<'_, T> {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.value
        }
    }

    struct TestAlloc;

    impl mcu_caliptra_api_lite::ApiAlloc for TestAlloc {
        type Buf<'a>
            = Vec<u8>
        where
            Self: 'a;

        fn alloc(&self, len: usize) -> McuResult<Self::Buf<'_>> {
            Ok(vec![0; len])
        }
    }

    impl SpdmPalAlloc for TestAlloc {
        type Box<'a, T>
            = TestBox<'a, T>
        where
            Self: 'a,
            T: 'a;
        type Bytes<'a>
            = Vec<u8>
        where
            Self: 'a;
        type LargeBuf<'a>
            = Vec<u8>
        where
            Self: 'a;

        fn alloc<T: Sized>(&self, _io: &impl SpdmPalIo, value: T) -> McuResult<Self::Box<'_, T>> {
            Ok(TestBox {
                value: Box::new(value),
                _lifetime: PhantomData,
            })
        }

        fn alloc_bytes(&self, _io: &impl SpdmPalIo, len: usize) -> McuResult<Self::Bytes<'_>> {
            Ok(vec![0; len])
        }

        fn large_capacity(&self) -> usize {
            0
        }
        fn large_begin(&self, _len: usize) -> McuResult<()> {
            Ok(())
        }
        fn large_write(&self, _offset: usize, _data: &[u8]) -> McuResult<()> {
            Ok(())
        }
        fn large_read(&self, _offset: usize, _out: &mut [u8]) -> McuResult<()> {
            Ok(())
        }
        fn large_end(&self) {}
        fn large_take(&self, len: usize) -> McuResult<Self::LargeBuf<'_>> {
            Ok(vec![0; len])
        }
    }

    struct TestIo;
    impl SpdmPalIo for TestIo {
        fn kind(&self) -> mcu_spdm_lite_traits::SpdmPalIoKind {
            mcu_spdm_lite_traits::SpdmPalIoKind::SecuredMessage
        }

        fn request(&self) -> &[u8] {
            &[]
        }
    }

    fn response_buffer<'a>(
        inline: &'a mut [u8],
        large: &'a mut [u8],
    ) -> VdmResponseBuffer<'a, TestAlloc, TestIo> {
        static ALLOC: TestAlloc = TestAlloc;
        static IO: TestIo = TestIo;
        VdmResponseBuffer {
            inline,
            large,
            alloc: &ALLOC,
            io: &IO,
        }
    }

    #[test]
    fn pci_sig_ide_km_matches_only_secure_session() {
        let backend = PciSigIdeKmVdm::new(0x1234, EmulatedIdeDriver::default());
        assert!(backend.match_id(&pci_sig_registry(true)));
        assert!(!backend.match_id(&pci_sig_registry(false)));
    }

    #[test]
    fn large_response_capacity_is_only_requested_for_query() {
        let backend = PciSigIdeKmVdm::new(0x1234, EmulatedIdeDriver::default());
        let query = [IDE_KM_PROTOCOL_ID, IdeKmCommand::Query as u8, 0, 0];
        assert!(backend.large_response_capacity(&query) > 0);

        let mut key_prog = [0u8; PciSigProtocolHdr::SIZE
            + IdeKmHdr::SIZE
            + mcu_spdm_lite_codec::KeyProg::SIZE
            + mcu_spdm_lite_codec::KeyData::SIZE];
        key_prog[0] = IDE_KM_PROTOCOL_ID;
        key_prog[1] = IdeKmCommand::KeyProg as u8;
        assert_eq!(backend.large_response_capacity(&key_prog), 0);
    }

    #[test]
    fn query_response_prefers_inline_when_it_fits_even_with_large_buffer() {
        let backend = PciSigIdeKmVdm::new(0x1234, EmulatedIdeDriver::default());
        let payload = [IDE_KM_PROTOCOL_ID, IdeKmCommand::Query as u8, 0, 0];
        let mut inline = [0u8; 256];
        let mut large = [0u8; 512];
        let response =
            block_on(backend.handle_request(&payload, response_buffer(&mut inline, &mut large)))
                .unwrap();

        let VdmResponse::Inline(len) = response else {
            panic!("IDE-KM query should be inline");
        };
        assert!(len > 1 + IdeKmHdr::SIZE + Query::SIZE);
        assert_eq!(inline[0], IDE_KM_PROTOCOL_ID);
        assert_eq!(inline[1], IdeKmCommand::QueryResp as u8);
        assert_eq!(inline[2], 0);
        assert_eq!(inline[3], 0);
        assert_eq!(large[0], 0);
    }

    #[test]
    fn query_response_uses_large_buffer_only_when_inline_is_too_small() {
        let backend = PciSigIdeKmVdm::new(0x1234, EmulatedIdeDriver::default());
        let payload = [IDE_KM_PROTOCOL_ID, IdeKmCommand::Query as u8, 0, 0];
        let mut inline = [0u8; 1];
        let mut large = [0u8; 256];
        let response =
            block_on(backend.handle_request(&payload, response_buffer(&mut inline, &mut large)))
                .unwrap();

        let VdmResponse::Large(len) = response else {
            panic!("IDE-KM query should use available large storage");
        };
        assert!(len > 1 + IdeKmHdr::SIZE + Query::SIZE);
        assert_eq!(large[0], IDE_KM_PROTOCOL_ID);
        assert_eq!(large[1], IdeKmCommand::QueryResp as u8);
    }

    #[test]
    fn key_prog_ack_stays_inline_when_large_buffer_is_available() {
        let driver = StatusDriver {
            key_prog_status: 0x5a,
        };
        let backend = PciSigIdeKmVdm::new(0x1234, driver);
        let mut payload = [0u8; PciSigProtocolHdr::SIZE
            + IdeKmHdr::SIZE
            + mcu_spdm_lite_codec::KeyProg::SIZE
            + mcu_spdm_lite_codec::KeyData::SIZE];
        payload[0] = IDE_KM_PROTOCOL_ID;
        payload[1] = IdeKmCommand::KeyProg as u8;
        let mut inline = [0u8; 16];
        let mut large = [0u8; 256];
        let response =
            block_on(backend.handle_request(&payload, response_buffer(&mut inline, &mut large)))
                .unwrap();

        let VdmResponse::Inline(len) = response else {
            panic!("IDE-KM KEY_PROG ACK should stay inline");
        };
        assert_eq!(
            len,
            PciSigProtocolHdr::SIZE + IdeKmHdr::SIZE + mcu_spdm_lite_codec::KeyProg::SIZE
        );
        assert_eq!(inline[0], IDE_KM_PROTOCOL_ID);
        assert_eq!(inline[1], IdeKmCommand::KeyProgAck as u8);
        assert_eq!(inline[5], driver.key_prog_status);
        assert_eq!(large[0], 0);
    }

    #[test]
    fn key_set_ack_echoes_request_key_info_after_driver_success() {
        let driver = StatusDriver { key_prog_status: 0 };
        let responder = IdeKmResponder::new(driver);
        let request_key_info = KeyInfo::new(false, false, 0x01);
        let req = [
            IdeKmCommand::KeySetGo as u8,
            0,
            0,
            0x22,
            0,
            request_key_info.raw(),
            0,
        ];
        let mut rsp = [0u8; 16];
        let len = block_on(responder.handle_request(&req, &mut rsp)).unwrap();

        assert_eq!(
            len,
            IdeKmHdr::SIZE + mcu_spdm_lite_codec::KeySetGoStop::SIZE
        );
        assert_eq!(rsp[0], IdeKmCommand::KeyGoStopAck as u8);
        assert_eq!(rsp[5], request_key_info.raw());
    }

    #[test]
    fn key_set_stop_ack_echoes_request_key_info_after_driver_success() {
        let driver = StopOnlyDriver;
        let responder = IdeKmResponder::new(driver);
        let request_key_info = KeyInfo::new(false, true, 0x02);
        let req = [
            IdeKmCommand::KeySetStop as u8,
            0,
            0,
            0x44,
            0,
            request_key_info.raw(),
            0,
        ];
        let mut rsp = [0u8; 16];
        let len = block_on(responder.handle_request(&req, &mut rsp)).unwrap();

        assert_eq!(
            len,
            IdeKmHdr::SIZE + mcu_spdm_lite_codec::KeySetGoStop::SIZE
        );
        assert_eq!(rsp[0], IdeKmCommand::KeyGoStopAck as u8);
        assert_eq!(rsp[5], request_key_info.raw());
    }

    #[test]
    fn key_prog_success_path_forwards_fields_and_key_material() {
        let expected_key = [
            0x0302_0100,
            0x0706_0504,
            0x0b0a_0908,
            0x0f0e_0d0c,
            0x1312_1110,
            0x1716_1514,
            0x1b1a_1918,
            0x1f1e_1d1c,
        ];
        let expected_iv = [0x2322_2120, 0x2726_2524];
        let expected_key_info = KeyInfo::new(true, false, 0x02);
        let driver = VerifyingKeyProgDriver {
            expected_stream_id: 0x33,
            expected_key_info,
            expected_port_index: 0,
            expected_key,
            expected_iv,
            status: 0xaa,
        };
        let responder = IdeKmResponder::new(driver);
        let mut req = [0u8; IdeKmHdr::SIZE
            + mcu_spdm_lite_codec::KeyProg::SIZE
            + mcu_spdm_lite_codec::KeyData::SIZE];
        req[0] = IdeKmCommand::KeyProg as u8;
        req[3] = driver.expected_stream_id;
        req[5] = expected_key_info.raw();
        let mut offset = IdeKmHdr::SIZE + mcu_spdm_lite_codec::KeyProg::SIZE;
        for value in expected_key {
            req[offset..offset + core::mem::size_of::<u32>()].copy_from_slice(&value.to_le_bytes());
            offset += core::mem::size_of::<u32>();
        }
        for value in expected_iv {
            req[offset..offset + core::mem::size_of::<u32>()].copy_from_slice(&value.to_le_bytes());
            offset += core::mem::size_of::<u32>();
        }

        let mut rsp = [0u8; 16];
        let len = block_on(responder.handle_request(&req, &mut rsp)).unwrap();

        assert_eq!(len, IdeKmHdr::SIZE + mcu_spdm_lite_codec::KeyProg::SIZE);
        assert_eq!(rsp[0], IdeKmCommand::KeyProgAck as u8);
        assert_eq!(rsp[4], driver.status);
    }

    #[test]
    fn unsupported_pci_sig_protocol_is_rejected() {
        let backend = PciSigIdeKmVdm::new(0x1234, EmulatedIdeDriver::default());
        let mut rsp = [0u8; 16];
        let result = block_on(backend.handle_request(&[0x7f], response_buffer(&mut rsp, &mut [])));

        let Err(err) = result else {
            panic!("unsupported PCI-SIG protocol should fail");
        };
        assert_eq!(err, SPDM_UNSUPPORTED_REQUEST);
    }

    #[test]
    fn invalid_and_response_only_ide_km_object_ids_are_rejected() {
        let responder = IdeKmResponder::new(EmulatedIdeDriver::default());
        let mut rsp = [0u8; 16];

        assert_eq!(
            block_on(responder.handle_request(&[0xff], &mut rsp)).unwrap_err(),
            SPDM_INVALID_REQUEST
        );
        assert_eq!(
            block_on(responder.handle_request(&[IdeKmCommand::QueryResp as u8], &mut rsp))
                .unwrap_err(),
            SPDM_INVALID_REQUEST
        );
    }

    #[test]
    fn malformed_payload_lengths_are_rejected() {
        let responder = IdeKmResponder::new(EmulatedIdeDriver::default());
        let mut rsp = [0u8; 16];

        assert_eq!(
            block_on(responder.handle_request(&[IdeKmCommand::Query as u8, 0], &mut rsp))
                .unwrap_err(),
            SPDM_INVALID_REQUEST
        );
        assert_eq!(
            block_on(responder.handle_request(&[IdeKmCommand::Query as u8, 0, 0, 0], &mut rsp))
                .unwrap_err(),
            SPDM_INVALID_REQUEST
        );
    }

    #[test]
    fn short_output_buffer_is_rejected() {
        let responder = IdeKmResponder::new(EmulatedIdeDriver::default());
        let req = [IdeKmCommand::Query as u8, 0, 0];
        let mut rsp = [0u8; 1];

        assert_eq!(
            block_on(responder.handle_request(&req, &mut rsp)).unwrap_err(),
            SPDM_INVALID_REQUEST
        );
    }
}
