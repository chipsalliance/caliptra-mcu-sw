// Licensed under the Apache-2.0 license

//! PCI-SIG IDE-KM VDM responder for SPDM-Lite.

use mcu_spdm_lite_codec::{
    IdeKmCommand, IdeKmHdr, PciSigProtocolHdr, StandardsBodyId, WireReader, WireWriter,
    IDE_KM_PROTOCOL_ID,
};

use mcu_spdm_lite_codec::errors::{
    SPDM_INVALID_REQUEST, SPDM_UNSPECIFIED, SPDM_UNSUPPORTED_REQUEST,
};
use mcu_spdm_lite_errors::VDM_NO_RESPONSE;
use mcu_spdm_lite_traits::{
    McuResult, SpdmPalAlloc, SpdmPalIo, SpdmVdmBackend, VdmRegistry, VdmResponse, VdmResponseBuffer,
};

use super::{handle_tdisp_protocol_payload, pci_sig_envelope_matches, tdisp, TDISP_PROTOCOL_ID};

mod commands;
mod driver;

pub(crate) use driver::map_ide_error;
pub use driver::{IdeDriver, IdeDriverError, IdeDriverResult};

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
    pub async fn handle_request<Alloc>(
        &self,
        req: &[u8],
        rsp: &mut [u8],
        scratch: &Alloc,
    ) -> McuResult<usize>
    where
        Alloc: SpdmPalAlloc,
    {
        let mut reader = WireReader::new(req);
        let hdr = *reader
            .read::<IdeKmHdr>()
            .map_err(|_| SPDM_INVALID_REQUEST)?;
        let command = IdeKmCommand::from_u8(hdr.object_id).ok_or(SPDM_INVALID_REQUEST)?;

        // Decode object ID, check the command payload length, then reject
        // response-only object IDs.
        if reader.remaining() != command.payload_len() {
            return Err(SPDM_INVALID_REQUEST);
        }

        let mut writer = WireWriter::new(rsp);
        match command {
            IdeKmCommand::Query => {
                commands::handle_query(&self.driver, scratch, &mut reader, &mut writer)
            }
            IdeKmCommand::KeyProg => {
                commands::handle_key_prog(&self.driver, scratch, &mut reader, &mut writer).await
            }
            IdeKmCommand::KeySetGo => {
                commands::handle_key_set_go(&self.driver, scratch, &mut reader, &mut writer).await
            }
            IdeKmCommand::KeySetStop => {
                commands::handle_key_set_stop(&self.driver, scratch, &mut reader, &mut writer).await
            }
            _ => Err(SPDM_INVALID_REQUEST),
        }
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
    async fn handle_ide_km_protocol_payload<Alloc>(
        &self,
        protocol_id: u8,
        req: &[u8],
        out: &mut [u8],
        scratch: &Alloc,
    ) -> McuResult<usize>
    where
        Alloc: SpdmPalAlloc,
    {
        let Some((protocol_out, ide_out)) = out.split_first_mut() else {
            return Err(SPDM_UNSPECIFIED);
        };
        *protocol_out = protocol_id;
        let ide_len = self.ide_km.handle_request(req, ide_out, scratch).await?;
        Ok(PciSigProtocolHdr::SIZE + ide_len)
    }
}

impl<D: IdeDriver> SpdmVdmBackend for PciSigIdeKmVdm<D> {
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
            .map_err(|_| VDM_NO_RESPONSE)?;
        if pci_sig_hdr.protocol_id != IDE_KM_PROTOCOL_ID {
            return Err(VDM_NO_RESPONSE);
        }

        let ide_km_payload = reader.rest();
        let scratch = rsp.scratch();
        let len = self
            .handle_ide_km_protocol_payload(
                pci_sig_hdr.protocol_id,
                ide_km_payload,
                rsp.inline,
                scratch,
            )
            .await
            .map_err(|_| VDM_NO_RESPONSE)?;
        Ok(VdmResponse::Inline(len))
    }
}

/// PCI-SIG VDM backend with IDE-KM and TDISP enabled for the same vendor ID.
pub struct PciSigIdeKmTdispVdm<Ide, Tdisp> {
    vendor_id: u16,
    ide_km: PciSigIdeKmVdm<Ide>,
    tdisp: tdisp::TdispResponder<Tdisp>,
}

impl<Ide, Tdisp> PciSigIdeKmTdispVdm<Ide, Tdisp> {
    /// Creates a PCI-SIG VDM backend that routes by PCI-SIG protocol id.
    pub const fn new(vendor_id: u16, ide_driver: Ide, tdisp: tdisp::TdispResponder<Tdisp>) -> Self {
        Self {
            vendor_id,
            ide_km: PciSigIdeKmVdm::new(vendor_id, ide_driver),
            tdisp,
        }
    }

    /// Returns the PCI-SIG vendor ID matched by this backend.
    pub const fn vendor_id(&self) -> u16 {
        self.vendor_id
    }
}

impl<Ide, Tdisp> SpdmVdmBackend for PciSigIdeKmTdispVdm<Ide, Tdisp>
where
    Ide: IdeDriver,
    Tdisp: tdisp::TdispDriver,
{
    fn match_id(&self, registry: &VdmRegistry<'_>) -> bool {
        pci_sig_envelope_matches(registry, self.vendor_id)
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
        let Some((&protocol_id, payload)) = req.split_first() else {
            return Err(SPDM_INVALID_REQUEST);
        };
        match protocol_id {
            IDE_KM_PROTOCOL_ID => self.ide_km.handle_request(req, rsp).await,
            TDISP_PROTOCOL_ID => {
                let VdmResponseBuffer { inline, alloc, .. } = rsp;
                handle_tdisp_protocol_payload(&self.tdisp, protocol_id, payload, inline, alloc)
                    .await
            }
            _ => Err(SPDM_UNSUPPORTED_REQUEST),
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::marker::PhantomData;
    use core::ops::{Deref, DerefMut};

    use futures::executor::block_on;
    use mcu_spdm_lite_codec::{
        AddrAssociationRegBlock, IdeCapabilityReg, IdeControlReg, IdeRegBlock, KeyInfo,
        LinkIdeStreamControlReg, LinkIdeStreamRegBlock, LinkIdeStreamStatusReg, PortConfig, Query,
        SelectiveIdeRidAssociationReg1, SelectiveIdeRidAssociationReg2,
        SelectiveIdeStreamCapabilityReg, SelectiveIdeStreamControlReg, SelectiveIdeStreamRegBlock,
        SelectiveIdeStreamStatusReg, IDE_KM_PROTOCOL_ID, IDE_STREAM_IV_SIZE_DW,
        IDE_STREAM_KEY_SIZE_DW, MAX_SELECTIVE_IDE_ADDR_ASSOC_BLOCK_COUNT,
    };

    use std::boxed::Box;
    use std::vec;
    use std::vec::Vec;
    use zerocopy::little_endian::U32;

    use super::*;

    const VENDOR_ID_BYTES: [u8; 2] = 0x1234u16.to_le_bytes();

    #[derive(Debug, Clone, Copy)]
    struct TestIdeDriver {
        port_index: u8,
        function_num: u8,
        bus_num: u8,
        segment: u8,
        num_link_ide_streams: u8,
        num_selective_ide_streams: u8,
        num_addr_association_reg_blocks: u8,
    }

    impl Default for TestIdeDriver {
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

    impl IdeDriver for TestIdeDriver {
        fn port_config<Alloc>(
            &self,
            port_index: u8,
            _scratch: &Alloc,
        ) -> IdeDriverResult<PortConfig>
        where
            Alloc: SpdmPalAlloc,
        {
            self.check_port(port_index)?;
            Ok(PortConfig {
                function_num: self.function_num,
                bus_num: self.bus_num,
                segment: self.segment,
                max_port_index: self.port_index,
            })
        }

        fn ide_reg_block<Alloc>(
            &self,
            port_index: u8,
            _scratch: &Alloc,
        ) -> IdeDriverResult<IdeRegBlock>
        where
            Alloc: SpdmPalAlloc,
        {
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

        fn link_ide_reg_block<Alloc>(
            &self,
            port_index: u8,
            block_index: u8,
            _scratch: &Alloc,
        ) -> IdeDriverResult<LinkIdeStreamRegBlock>
        where
            Alloc: SpdmPalAlloc,
        {
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

        fn selective_ide_reg_block<Alloc>(
            &self,
            port_index: u8,
            block_index: u8,
            _scratch: &Alloc,
        ) -> IdeDriverResult<SelectiveIdeStreamRegBlock>
        where
            Alloc: SpdmPalAlloc,
        {
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

        async fn key_prog<Alloc>(
            &self,
            _stream_id: u8,
            _key_info: KeyInfo,
            port_index: u8,
            _key: &[U32; IDE_STREAM_KEY_SIZE_DW],
            _iv: &[U32; IDE_STREAM_IV_SIZE_DW],
            _scratch: &Alloc,
        ) -> IdeDriverResult<u8>
        where
            Alloc: SpdmPalAlloc,
        {
            self.check_port(port_index)?;
            Ok(0)
        }

        async fn key_set_go<Alloc>(
            &self,
            _stream_id: u8,
            key_info: KeyInfo,
            port_index: u8,
            _scratch: &Alloc,
        ) -> IdeDriverResult<()>
        where
            Alloc: SpdmPalAlloc,
        {
            self.check_port(port_index)?;
            let _ = key_info;
            Ok(())
        }

        async fn key_set_stop<Alloc>(
            &self,
            _stream_id: u8,
            key_info: KeyInfo,
            port_index: u8,
            _scratch: &Alloc,
        ) -> IdeDriverResult<()>
        where
            Alloc: SpdmPalAlloc,
        {
            self.check_port(port_index)?;
            let _ = key_info;
            Ok(())
        }
    }

    impl TestIdeDriver {
        fn check_port(&self, port_index: u8) -> IdeDriverResult<()> {
            if port_index == self.port_index {
                Ok(())
            } else {
                Err(IdeDriverError::InvalidPortIndex)
            }
        }
    }

    #[derive(Clone, Copy)]
    struct StatusDriver {
        key_prog_status: u8,
    }

    impl IdeDriver for StatusDriver {
        fn port_config<Alloc>(&self, port_index: u8, scratch: &Alloc) -> IdeDriverResult<PortConfig>
        where
            Alloc: SpdmPalAlloc,
        {
            TestIdeDriver::default().port_config(port_index, scratch)
        }

        fn ide_reg_block<Alloc>(
            &self,
            port_index: u8,
            scratch: &Alloc,
        ) -> IdeDriverResult<IdeRegBlock>
        where
            Alloc: SpdmPalAlloc,
        {
            TestIdeDriver::default().ide_reg_block(port_index, scratch)
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
            TestIdeDriver::default().link_ide_reg_block(port_index, block_index, scratch)
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
            TestIdeDriver::default().selective_ide_reg_block(port_index, block_index, scratch)
        }

        async fn key_prog<Alloc>(
            &self,
            _stream_id: u8,
            _key_info: KeyInfo,
            _port_index: u8,
            _key: &[U32; IDE_STREAM_KEY_SIZE_DW],
            _iv: &[U32; IDE_STREAM_IV_SIZE_DW],
            _scratch: &Alloc,
        ) -> IdeDriverResult<u8>
        where
            Alloc: SpdmPalAlloc,
        {
            Ok(self.key_prog_status)
        }

        async fn key_set_go<Alloc>(
            &self,
            _stream_id: u8,
            _key_info: KeyInfo,
            _port_index: u8,
            _scratch: &Alloc,
        ) -> IdeDriverResult<()>
        where
            Alloc: SpdmPalAlloc,
        {
            Ok(())
        }

        async fn key_set_stop<Alloc>(
            &self,
            _stream_id: u8,
            _key_info: KeyInfo,
            _port_index: u8,
            _scratch: &Alloc,
        ) -> IdeDriverResult<()>
        where
            Alloc: SpdmPalAlloc,
        {
            Ok(())
        }
    }

    #[derive(Clone, Copy)]
    struct StopOnlyDriver;

    impl IdeDriver for StopOnlyDriver {
        fn port_config<Alloc>(&self, port_index: u8, scratch: &Alloc) -> IdeDriverResult<PortConfig>
        where
            Alloc: SpdmPalAlloc,
        {
            TestIdeDriver::default().port_config(port_index, scratch)
        }

        fn ide_reg_block<Alloc>(
            &self,
            port_index: u8,
            scratch: &Alloc,
        ) -> IdeDriverResult<IdeRegBlock>
        where
            Alloc: SpdmPalAlloc,
        {
            TestIdeDriver::default().ide_reg_block(port_index, scratch)
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
            TestIdeDriver::default().link_ide_reg_block(port_index, block_index, scratch)
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
            TestIdeDriver::default().selective_ide_reg_block(port_index, block_index, scratch)
        }

        async fn key_prog<Alloc>(
            &self,
            _stream_id: u8,
            _key_info: KeyInfo,
            _port_index: u8,
            _key: &[U32; IDE_STREAM_KEY_SIZE_DW],
            _iv: &[U32; IDE_STREAM_IV_SIZE_DW],
            _scratch: &Alloc,
        ) -> IdeDriverResult<u8>
        where
            Alloc: SpdmPalAlloc,
        {
            Err(IdeDriverError::KeyProgFail)
        }

        async fn key_set_go<Alloc>(
            &self,
            _stream_id: u8,
            _key_info: KeyInfo,
            _port_index: u8,
            _scratch: &Alloc,
        ) -> IdeDriverResult<()>
        where
            Alloc: SpdmPalAlloc,
        {
            Err(IdeDriverError::KeySetGoFail)
        }

        async fn key_set_stop<Alloc>(
            &self,
            _stream_id: u8,
            _key_info: KeyInfo,
            _port_index: u8,
            _scratch: &Alloc,
        ) -> IdeDriverResult<()>
        where
            Alloc: SpdmPalAlloc,
        {
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
        fn port_config<Alloc>(&self, port_index: u8, scratch: &Alloc) -> IdeDriverResult<PortConfig>
        where
            Alloc: SpdmPalAlloc,
        {
            TestIdeDriver::default().port_config(port_index, scratch)
        }

        fn ide_reg_block<Alloc>(
            &self,
            port_index: u8,
            scratch: &Alloc,
        ) -> IdeDriverResult<IdeRegBlock>
        where
            Alloc: SpdmPalAlloc,
        {
            TestIdeDriver::default().ide_reg_block(port_index, scratch)
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
            TestIdeDriver::default().link_ide_reg_block(port_index, block_index, scratch)
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
            TestIdeDriver::default().selective_ide_reg_block(port_index, block_index, scratch)
        }

        async fn key_prog<Alloc>(
            &self,
            stream_id: u8,
            key_info: KeyInfo,
            port_index: u8,
            key: &[U32; IDE_STREAM_KEY_SIZE_DW],
            iv: &[U32; IDE_STREAM_IV_SIZE_DW],
            _scratch: &Alloc,
        ) -> IdeDriverResult<u8>
        where
            Alloc: SpdmPalAlloc,
        {
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

        async fn key_set_go<Alloc>(
            &self,
            _stream_id: u8,
            _key_info: KeyInfo,
            _port_index: u8,
            _scratch: &Alloc,
        ) -> IdeDriverResult<()>
        where
            Alloc: SpdmPalAlloc,
        {
            Err(IdeDriverError::KeySetGoFail)
        }

        async fn key_set_stop<Alloc>(
            &self,
            _stream_id: u8,
            _key_info: KeyInfo,
            _port_index: u8,
            _scratch: &Alloc,
        ) -> IdeDriverResult<()>
        where
            Alloc: SpdmPalAlloc,
        {
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
        type LargeBuf = Vec<u8>;
        type PersistentBox<T: Sized + 'static> = Box<T>;

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

        fn alloc_large_buf(&self, len: usize) -> McuResult<Self::LargeBuf> {
            Ok(vec![0; len])
        }

        fn alloc_persistent<T: Sized + 'static>(
            &self,
            value: T,
        ) -> McuResult<Self::PersistentBox<T>> {
            Ok(Box::new(value))
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

    static TEST_ALLOC: TestAlloc = TestAlloc;
    static TEST_IO: TestIo = TestIo;

    fn scratch() -> &'static TestAlloc {
        &TEST_ALLOC
    }

    fn response_buffer<'a>(
        inline: &'a mut [u8],
        large: &'a mut [u8],
    ) -> VdmResponseBuffer<'a, TestAlloc, TestIo> {
        VdmResponseBuffer {
            inline,
            large,
            alloc: &TEST_ALLOC,
            io: &TEST_IO,
        }
    }

    #[test]
    fn pci_sig_ide_km_matches_only_secure_session() {
        let backend = PciSigIdeKmVdm::new(0x1234, TestIdeDriver::default());
        assert!(backend.match_id(&pci_sig_registry(true)));
        assert!(!backend.match_id(&pci_sig_registry(false)));
    }

    #[test]
    fn large_response_capacity_is_not_requested_for_ide_km() {
        let backend = PciSigIdeKmVdm::new(0x1234, TestIdeDriver::default());
        let query = [IDE_KM_PROTOCOL_ID, IdeKmCommand::Query as u8, 0, 0];
        assert_eq!(backend.large_response_capacity(&query), 0);

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
        let backend = PciSigIdeKmVdm::new(0x1234, TestIdeDriver::default());
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
    fn query_response_does_not_use_large_buffer_when_inline_is_too_small() {
        let backend = PciSigIdeKmVdm::new(0x1234, TestIdeDriver::default());
        let payload = [IDE_KM_PROTOCOL_ID, IdeKmCommand::Query as u8, 0, 0];
        let mut inline = [0u8; 1];
        let mut large = [0u8; 256];
        let err = match block_on(
            backend.handle_request(&payload, response_buffer(&mut inline, &mut large)),
        ) {
            Ok(_) => panic!("IDE-KM query should fail when inline storage is too small"),
            Err(err) => err,
        };

        assert_eq!(err, VDM_NO_RESPONSE);
        assert_eq!(large[0], 0);
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
        let len = block_on(responder.handle_request(&req, &mut rsp, scratch())).unwrap();

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
        let len = block_on(responder.handle_request(&req, &mut rsp, scratch())).unwrap();

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
        let len = block_on(responder.handle_request(&req, &mut rsp, scratch())).unwrap();

        assert_eq!(len, IdeKmHdr::SIZE + mcu_spdm_lite_codec::KeyProg::SIZE);
        assert_eq!(rsp[0], IdeKmCommand::KeyProgAck as u8);
        assert_eq!(rsp[4], driver.status);
    }

    #[test]
    fn ide_driver_errors_drop_vdm_response() {
        let responder = IdeKmResponder::new(StopOnlyDriver);
        let mut req = [0u8; IdeKmHdr::SIZE
            + mcu_spdm_lite_codec::KeyProg::SIZE
            + mcu_spdm_lite_codec::KeyData::SIZE];
        req[0] = IdeKmCommand::KeyProg as u8;
        let mut rsp = [0u8; 16];

        assert_eq!(
            block_on(responder.handle_request(&req, &mut rsp, scratch())).unwrap_err(),
            VDM_NO_RESPONSE
        );
    }

    #[test]
    fn unsupported_pci_sig_protocol_is_rejected() {
        let backend = PciSigIdeKmVdm::new(0x1234, TestIdeDriver::default());
        let mut rsp = [0u8; 16];
        let result = block_on(backend.handle_request(&[0x7f], response_buffer(&mut rsp, &mut [])));

        let Err(err) = result else {
            panic!("unsupported PCI-SIG protocol should fail");
        };
        assert_eq!(err, VDM_NO_RESPONSE);
    }

    #[test]
    fn invalid_and_response_only_ide_km_object_ids_are_rejected() {
        let responder = IdeKmResponder::new(TestIdeDriver::default());
        let mut rsp = [0u8; 16];

        assert_eq!(
            block_on(responder.handle_request(&[0xff], &mut rsp, scratch())).unwrap_err(),
            SPDM_INVALID_REQUEST
        );
        assert_eq!(
            block_on(responder.handle_request(
                &[IdeKmCommand::QueryResp as u8],
                &mut rsp,
                scratch()
            ))
            .unwrap_err(),
            SPDM_INVALID_REQUEST
        );
    }

    #[test]
    fn backend_drops_invalid_and_response_only_ide_km_object_ids() {
        let backend = PciSigIdeKmVdm::new(0x1234, TestIdeDriver::default());
        let mut rsp = [0u8; 16];

        for payload in [
            [IDE_KM_PROTOCOL_ID, 0xff],
            [IDE_KM_PROTOCOL_ID, IdeKmCommand::QueryResp as u8],
        ] {
            let result =
                block_on(backend.handle_request(&payload, response_buffer(&mut rsp, &mut [])));
            let Err(err) = result else {
                panic!("invalid IDE-KM object should fail without response");
            };
            assert_eq!(err, VDM_NO_RESPONSE);
        }
    }

    #[test]
    fn malformed_payload_lengths_are_rejected() {
        let responder = IdeKmResponder::new(TestIdeDriver::default());
        let mut rsp = [0u8; 16];

        assert_eq!(
            block_on(responder.handle_request(
                &[IdeKmCommand::Query as u8, 0],
                &mut rsp,
                scratch()
            ))
            .unwrap_err(),
            SPDM_INVALID_REQUEST
        );
        assert_eq!(
            block_on(responder.handle_request(
                &[IdeKmCommand::Query as u8, 0, 0, 0],
                &mut rsp,
                scratch()
            ))
            .unwrap_err(),
            SPDM_INVALID_REQUEST
        );
    }

    #[test]
    fn short_output_buffer_is_rejected() {
        let responder = IdeKmResponder::new(TestIdeDriver::default());
        let req = [IdeKmCommand::Query as u8, 0, 0];
        let mut rsp = [0u8; 1];

        assert_eq!(
            block_on(responder.handle_request(&req, &mut rsp, scratch())).unwrap_err(),
            SPDM_INVALID_REQUEST
        );
    }
}
