// Licensed under the Apache-2.0 license

use super::svn::{run_with_upcalls, TestAlloc, TestDmaMapping, TestMailbox, TestOtp};
use super::*;
use caliptra_api::mailbox::{
    CapabilitiesResp, CmShaDmaReq, CmShaInitResp, CmShaUpdateReq, MailboxRespHeader,
    MailboxRespHeaderVarSize,
};
use caliptra_api::Capabilities;
use caliptra_mcu_libsyscall_caliptra::system;
use caliptra_mcu_libtock_unittest::{command_return, ExpectedSyscall};
use core::mem::size_of;
use core::sync::atomic::AtomicUsize;
use std::{boxed::Box, rc::Rc, vec::Vec};
use zerocopy::FromZeros;

const AXI_BASE: u64 = 0x2_0000_0000;
const DIGEST: [u8; 48] = [0xa5; 48];
const CALIPTRA_OFFSET: usize = 0x200;
const MANIFEST_OFFSET: usize = 0x300 + size_of::<ImageManifest>();
const MCU_OFFSET: usize =
    (MANIFEST_OFFSET + size_of::<AuthorizationManifest>()).next_multiple_of(0x100);
// Three CM_SHA_UPDATE chunks on the fallback path.
const MCU_LEN: usize = 2 * SHA_CHUNK_SIZE + 76;
const MCU_TOC_ENTRY_OFFSET: usize = size_of::<FlashHeaderV1>() + 2 * size_of::<ImageHeaderV1V2>();

const CAPS: u32 = CommandId::CAPABILITIES.0;
const CMSA: u32 = CommandId::CM_SHA_DMA.0;
const CMSI: u32 = CommandId::CM_SHA_INIT.0;
const CMSU: u32 = CommandId::CM_SHA_UPDATE.0;
const CMSF: u32 = CommandId::CM_SHA_FINAL.0;
const CM_SHA: [u32; 5] = [CMSI, CMSU, CMSU, CMSU, CMSF];

#[derive(Debug)]
struct AxiStagingMemory {
    bytes: Vec<u8>,
    axi_base: Option<u64>,
    /// MCU TOC entry served after its first read, as if the TOC changed after
    /// the layout check.
    later_mcu_entry: Option<ImageHeaderV1V2>,
    mcu_entry_reads: AtomicUsize,
}

impl AxiStagingMemory {
    fn new(bytes: Vec<u8>, axi_base: Option<u64>) -> Self {
        Self {
            bytes,
            axi_base,
            later_mcu_entry: None,
            mcu_entry_reads: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl StagingMemory for AxiStagingMemory {
    async fn write(&self, _offset: usize, _data: &[u8]) -> Result<(), ErrorCode> {
        panic!("verification must not write staging memory");
    }

    async fn read(&self, offset: usize, data: &mut [u8]) -> Result<(), ErrorCode> {
        if let Some(entry) = &self.later_mcu_entry {
            if offset == MCU_TOC_ENTRY_OFFSET
                && self.mcu_entry_reads.fetch_add(1, Ordering::Relaxed) > 0
            {
                data.copy_from_slice(entry.as_bytes());
                return Ok(());
            }
        }
        data.copy_from_slice(&self.bytes[offset..offset + data.len()]);
        Ok(())
    }

    async fn image_valid(&self, _img_sz: usize) -> Result<(), ErrorCode> {
        panic!("verification must not apply the image");
    }

    fn size(&self) -> usize {
        self.bytes.len()
    }

    fn caliptra_axi_base(&self) -> Option<u64> {
        self.axi_base
    }
}

/// A Caliptra bundle, a SoC manifest authorizing `DIGEST` for MCU RT, and the
/// MCU RT image at `mcu_offset`.
fn package(mcu_offset: usize) -> Vec<u8> {
    let mut manifest = AuthorizationManifest::default();
    manifest.image_metadata_col.entry_count = 1;
    manifest.image_metadata_col.image_metadata_list[0] = AuthManifestImageMetadata {
        fw_id: MCU_RT_IDENTIFIER,
        component_id: MCU_RT_IDENTIFIER,
        digest: DIGEST,
        ..Default::default()
    };
    let images = [
        (
            CALIPTRA_FMC_RT_IDENTIFIER,
            CALIPTRA_OFFSET,
            ImageManifest::default().as_bytes().to_vec(),
        ),
        (
            SOC_MANIFEST_IDENTIFIER,
            MANIFEST_OFFSET,
            manifest.as_bytes().to_vec(),
        ),
        // Non-uniform, so a chunk read from the wrong offset is detected.
        (
            MCU_RT_IDENTIFIER,
            mcu_offset,
            (0..MCU_LEN).map(|i| (i % 251) as u8).collect(),
        ),
    ];
    let mut bytes = std::vec![0; mcu_offset + MCU_LEN];
    bytes[..size_of::<FlashHeaderV1>()]
        .copy_from_slice(FlashHeaderV1::new(images.len() as u16).as_bytes());
    for (index, (identifier, offset, payload)) in images.iter().enumerate() {
        bytes[*offset..*offset + payload.len()].copy_from_slice(payload);
        let image = toc_entry(*identifier, *offset, payload.len());
        let at = size_of::<FlashHeaderV1>() + index * size_of::<ImageHeaderV1V2>();
        bytes[at..at + size_of::<ImageHeaderV1V2>()].copy_from_slice(image.as_bytes());
    }
    bytes
}

fn toc_entry(identifier: u32, offset: usize, size: usize) -> ImageHeaderV1V2 {
    let mut image = ImageHeaderV1V2 {
        identifier,
        offset: offset as u32,
        size: size as u32,
        image_checksum: 0,
        image_header_checksum: 0,
    };
    image.image_header_checksum =
        calculate_checksum(&image.as_bytes()[..offset_of!(ImageHeaderV1V2, image_header_checksum)]);
    image
}

fn capabilities_response(sha_dma: bool) -> Vec<u8> {
    let mut caps = Capabilities::RT_BASE;
    if sha_dma {
        caps |= Capabilities::RT_SHA_DMA;
    }
    let mut rsp = CapabilitiesResp::new_zeroed();
    rsp.capabilities = caps.to_bytes();
    rsp.as_bytes().to_vec()
}

/// `CM_SHA_DMA` and `CM_SHA_FINAL` share this variable-size digest response.
fn digest_response(digest: &[u8; 48]) -> Vec<u8> {
    let hdr = MailboxRespHeaderVarSize {
        data_len: digest.len() as u32,
        ..Default::default()
    };
    [hdr.as_bytes(), digest].concat()
}

struct Fixture {
    kernel: fake::Kernel,
    mailbox: Rc<TestMailbox>,
    staging: &'static AxiStagingMemory,
    updater: FirmwareUpdater<'static, TestDmaMapping, TestAlloc>,
    _otp: Rc<TestOtp>,
}

impl Fixture {
    fn new(axi_base: Option<u64>, mcu_offset: usize) -> Self {
        Self::with_staging(AxiStagingMemory::new(package(mcu_offset), axi_base))
    }

    fn with_staging(staging: AxiStagingMemory) -> Self {
        static ALLOC: TestAlloc = TestAlloc;
        static DMA_MAPPING: TestDmaMapping = TestDmaMapping;

        let kernel = fake::Kernel::new();
        let otp = Rc::new(TestOtp::new());
        // Anti-rollback off: these tests cover hashing, not the SVN gates.
        otp.disable.set(Ok(1));
        let mailbox = Rc::new(TestMailbox::default());
        kernel.add_driver(&otp);
        kernel.add_driver(&mailbox);
        let staging = Box::leak(Box::new(staging));
        let params = Box::leak(Box::new(PldmFirmwareDeviceParams {
            descriptors: &[],
            fw_params: Box::leak(Box::new(FirmwareParameters::default())),
        }));
        let executor = Box::leak(Box::new(TockExecutor::new()));
        let updater = FirmwareUpdater::new(
            staging,
            &ALLOC,
            params,
            &[],
            &DMA_MAPPING,
            executor.spawner(),
            None,
        );
        Self {
            kernel,
            mailbox,
            staging,
            updater,
            _otp: otp,
        }
    }

    fn for_verify(axi_base: Option<u64>, mcu_offset: usize) -> Self {
        let fixture = Self::new(axi_base, mcu_offset);
        fixture.expect_verify();
        fixture
    }

    fn respond_cm_sha(&self, digest: &[u8; 48]) {
        let ctx = CmShaInitResp::new_zeroed();
        self.mailbox.respond(CommandId::CM_SHA_INIT, ctx.as_bytes());
        for _ in 0..3 {
            self.mailbox
                .respond(CommandId::CM_SHA_UPDATE, ctx.as_bytes());
        }
        self.mailbox
            .respond(CommandId::CM_SHA_FINAL, &digest_response(digest));
    }

    /// Queue the ROM version query and the Caliptra bundle and SoC manifest
    /// checks that `verify()` makes before it hashes any image.
    fn expect_verify(&self) {
        self.kernel.add_expected_syscall(ExpectedSyscall::Command {
            driver_id: system::DRIVER_NUM,
            command_id: 4,
            argument0: 0,
            argument1: 0,
            override_return: Some(command_return::failure(ErrorCode::NoSupport)),
        });
        self.mailbox.respond(
            CommandId::FIRMWARE_VERIFY,
            FirmwareVerifyResp {
                verify_result: FirmwareVerifyResult::Success as u32,
                ..Default::default()
            }
            .as_bytes(),
        );
        self.mailbox.respond(
            CommandId::VERIFY_AUTH_MANIFEST,
            &[0; size_of::<MailboxRespHeader>()],
        );
    }

    fn verify(&mut self) -> Result<FlashHeader, ErrorCode> {
        run_with_upcalls(self.updater.verify(self.staging.size()))
    }

    /// Assert that the `CM_SHA_UPDATE` requests streamed the MCU image at
    /// `mcu_offset`, in order.
    fn assert_cm_sha_streamed(&self, mcu_offset: usize) {
        let size_at = offset_of!(CmShaUpdateReq, input_size);
        let input_at = offset_of!(CmShaUpdateReq, input);
        let mut input = Vec::new();
        for (cmd, req) in self.mailbox.requests.borrow().iter() {
            if *cmd == CMSU {
                let size = u32::from_le_bytes(req[size_at..input_at].try_into().unwrap());
                input.extend_from_slice(&req[input_at..input_at + size as usize]);
            }
        }
        assert_eq!(input, self.staging.bytes[mcu_offset..mcu_offset + MCU_LEN]);
    }

    /// Commands sent after Caliptra bundle and SoC manifest verification.
    fn hashing_commands(&self) -> Vec<u32> {
        let commands = self.mailbox.commands.borrow();
        assert_eq!(
            commands[..2],
            [
                CommandId::FIRMWARE_VERIFY.0,
                CommandId::VERIFY_AUTH_MANIFEST.0
            ]
        );
        commands[2..].to_vec()
    }
}

#[test]
fn verify_hashes_an_axi_staged_image_with_one_sha_dma() {
    let _guard = PLDM_TEST_LOCK.lock().unwrap();
    let mut fixture = Fixture::for_verify(Some(AXI_BASE), MCU_OFFSET);
    fixture
        .mailbox
        .respond(CommandId::CAPABILITIES, &capabilities_response(true));
    fixture
        .mailbox
        .respond(CommandId::CM_SHA_DMA, &digest_response(&DIGEST));
    fixture.verify().unwrap();
    assert_eq!(fixture.hashing_commands(), [CAPS, CMSA]);

    let requests = fixture.mailbox.requests.borrow();
    let (_, request) = requests.iter().find(|(cmd, _)| *cmd == CMSA).unwrap();
    let request = CmShaDmaReq::read_from_bytes(request).unwrap();
    let axi_addr = AXI_BASE + MCU_OFFSET as u64;
    assert_eq!(request.flags, 0);
    assert_eq!(request.hash_algorithm, 1);
    assert_eq!(request.axi_addr_lo, axi_addr as u32);
    assert_eq!(request.axi_addr_hi, (axi_addr >> 32) as u32);
    assert_eq!(request.length, MCU_LEN as u32);
}

#[test]
fn verify_uses_cm_sha_when_caliptra_lacks_sha_dma() {
    let _guard = PLDM_TEST_LOCK.lock().unwrap();
    let mut fixture = Fixture::for_verify(Some(AXI_BASE), MCU_OFFSET);
    fixture
        .mailbox
        .respond(CommandId::CAPABILITIES, &capabilities_response(false));
    fixture.respond_cm_sha(&DIGEST);
    fixture.verify().unwrap();
    assert_eq!(fixture.hashing_commands(), [&[CAPS][..], &CM_SHA].concat());
    fixture.assert_cm_sha_streamed(MCU_OFFSET);
}

#[test]
fn verify_uses_cm_sha_when_capabilities_fails() {
    let _guard = PLDM_TEST_LOCK.lock().unwrap();
    let mut fixture = Fixture::for_verify(Some(AXI_BASE), MCU_OFFSET);
    // One byte short, so the response does not parse.
    let caps = capabilities_response(true);
    fixture
        .mailbox
        .respond(CommandId::CAPABILITIES, &caps[..caps.len() - 1]);
    fixture.respond_cm_sha(&DIGEST);
    fixture.verify().unwrap();
    assert_eq!(fixture.hashing_commands(), [&[CAPS][..], &CM_SHA].concat());
    fixture.assert_cm_sha_streamed(MCU_OFFSET);
}

#[test]
fn verify_skips_capabilities_without_an_axi_staging_address() {
    let _guard = PLDM_TEST_LOCK.lock().unwrap();
    let mut fixture = Fixture::for_verify(None, MCU_OFFSET);
    fixture.respond_cm_sha(&DIGEST);
    fixture.verify().unwrap();
    assert_eq!(fixture.hashing_commands(), CM_SHA);
    fixture.assert_cm_sha_streamed(MCU_OFFSET);
}

#[test]
fn verify_uses_cm_sha_for_an_unaligned_image() {
    let _guard = PLDM_TEST_LOCK.lock().unwrap();
    let mut fixture = Fixture::for_verify(Some(AXI_BASE), MCU_OFFSET + 2);
    fixture
        .mailbox
        .respond(CommandId::CAPABILITIES, &capabilities_response(true));
    fixture.respond_cm_sha(&DIGEST);
    fixture.verify().unwrap();
    assert_eq!(fixture.hashing_commands(), [&[CAPS][..], &CM_SHA].concat());
    fixture.assert_cm_sha_streamed(MCU_OFFSET + 2);
}

#[test]
fn sha_dma_failure_or_mismatch_fails_verification_without_cm_sha() {
    let _guard = PLDM_TEST_LOCK.lock().unwrap();
    for response in [
        digest_response(&DIGEST)[..size_of::<MailboxRespHeaderVarSize>()].to_vec(),
        digest_response(&[0x11; 48]),
    ] {
        let mut fixture = Fixture::for_verify(Some(AXI_BASE), MCU_OFFSET);
        fixture
            .mailbox
            .respond(CommandId::CAPABILITIES, &capabilities_response(true));
        fixture.mailbox.respond(CommandId::CM_SHA_DMA, &response);
        assert!(matches!(fixture.verify(), Err(ErrorCode::Fail)));
        assert_eq!(fixture.hashing_commands(), [CAPS, CMSA]);
    }
}

#[test]
fn running_image_match_hashes_with_sha_dma() {
    let _guard = PLDM_TEST_LOCK.lock().unwrap();
    let mut fixture = Fixture::new(Some(AXI_BASE), MCU_OFFSET);
    let header = FlashHeader::parse(&fixture.staging.bytes).unwrap();
    fixture
        .mailbox
        .respond(CommandId::FW_INFO, FwInfoResp::new_zeroed().as_bytes());
    fixture
        .mailbox
        .respond(CommandId::CAPABILITIES, &capabilities_response(true));
    fixture
        .mailbox
        .respond(CommandId::CM_SHA_DMA, &digest_response(&DIGEST));
    assert_eq!(
        run_with_upcalls(fixture.updater.verify_running_image_match(&header)),
        Ok(())
    );
    assert_eq!(
        *fixture.mailbox.commands.borrow(),
        [CommandId::FW_INFO.0, CAPS, CMSA]
    );
}

#[test]
fn staged_range_past_the_limit_is_not_hashed() {
    let _guard = PLDM_TEST_LOCK.lock().unwrap();
    let fixture = Fixture::new(Some(AXI_BASE), MCU_OFFSET);
    let limit = fixture.staging.size();
    for (offset, len) in [(MCU_OFFSET, MCU_LEN + 4), (usize::MAX - 3, 8)] {
        assert_eq!(
            run_with_upcalls(
                fixture
                    .updater
                    .hash_staged_image(Some(AXI_BASE), offset, len, limit)
            ),
            Err(ErrorCode::Size)
        );
    }
    assert!(fixture.mailbox.commands.borrow().is_empty());
}

#[test]
fn toc_entry_grown_after_the_layout_check_is_not_hashed() {
    let _guard = PLDM_TEST_LOCK.lock().unwrap();
    // verify() bounds an entry by the downloaded length, which is 4 bytes
    // short of size(); the running-image check bounds it by size().
    for (growth, running) in [(4, false), (8, true)] {
        let mut bytes = package(MCU_OFFSET);
        let image_len = bytes.len();
        bytes.resize(image_len + 4, 0);
        let mut staging = AxiStagingMemory::new(bytes, Some(AXI_BASE));
        staging.later_mcu_entry = Some(toc_entry(MCU_RT_IDENTIFIER, MCU_OFFSET, MCU_LEN + growth));
        let mut fixture = Fixture::with_staging(staging);
        if running {
            fixture
                .mailbox
                .respond(CommandId::FW_INFO, FwInfoResp::new_zeroed().as_bytes());
        } else {
            fixture.expect_verify();
        }
        fixture
            .mailbox
            .respond(CommandId::CAPABILITIES, &capabilities_response(true));
        let result = if running {
            let header = FlashHeader::parse(&fixture.staging.bytes).unwrap();
            run_with_upcalls(fixture.updater.verify_running_image_match(&header))
        } else {
            run_with_upcalls(fixture.updater.verify(image_len)).map(|_| ())
        };
        assert_eq!(result, Err(ErrorCode::Size));
        assert_eq!(fixture.mailbox.commands.borrow().last(), Some(&CAPS));
    }
}

#[test]
fn sha_dma_range_requires_an_aligned_range_in_one_4gib_block() {
    assert_eq!(sha_dma_range(0x1000, 4, 8), Ok((0x1004, 8)));
    assert_eq!(
        sha_dma_range(0xffff_f000, 0, 0x1000),
        Ok((0xffff_f000, 0x1000))
    );
    for (base, offset, len) in [
        (0x1000, 0, 0),
        (0x1000, 2, 8),
        (0x1001, 0, 8),
        (0x1000, 0, 6),
        (0xffff_f000, 0, 0x2000),
        (u64::MAX - 3, 4, 4),
        (u64::MAX - 3, 0, 8),
    ] {
        assert!(sha_dma_range(base, offset, len).is_err());
    }
    #[cfg(target_pointer_width = "64")]
    assert!(sha_dma_range(0, 0, 1 << 32).is_err());
}
