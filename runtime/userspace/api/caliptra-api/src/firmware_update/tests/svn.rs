// Licensed under the Apache-2.0 license

use super::*;
use caliptra_mcu_libsyscall_caliptra::{mailbox::MAILBOX_DRIVER_NUM, system};
use caliptra_mcu_libtock_platform::{CommandReturn, Syscalls};
use caliptra_mcu_libtock_unittest::{
    command_return, fake::SyscallDriver, DriverInfo, DriverShareRef, ExpectedSyscall,
    RoAllowBuffer, RwAllowBuffer,
};
use core::cell::{Cell, RefCell};
use core::mem::size_of;
use core::sync::atomic::AtomicUsize;
use std::{boxed::Box, collections::VecDeque, rc::Rc, vec::Vec};
use zerocopy::FromZeros;

#[derive(Clone, Copy)]
struct Component {
    identifier: u32,
    otp_reg: u32,
    offset: usize,
    len: usize,
    svn_offset: usize,
}

const COMPONENTS: [Component; 2] = [
    Component {
        identifier: CALIPTRA_FMC_RT_IDENTIFIER,
        otp_reg: otp::reg::CALIPTRA_FW_SVN,
        offset: 0x200,
        len: size_of::<ImageManifest>(),
        svn_offset: offset_of!(ImageManifest, header) + offset_of!(CaliptraImageHeader, svn),
    },
    Component {
        identifier: SOC_MANIFEST_IDENTIFIER,
        otp_reg: otp::reg::SOC_MANIFEST_SVN,
        offset: 0x300 + size_of::<ImageManifest>(),
        len: size_of::<AuthorizationManifest>(),
        svn_offset: offset_of!(AuthorizationManifest, preamble)
            + offset_of!(AuthManifestPreamble, svn),
    },
];

struct TestOtp {
    disable: Cell<Result<u32, ErrorCode>>,
    firmware_words: Cell<[u32; SVN_FUSE_WORD_COUNT]>,
    manifest_words: Cell<[u32; SVN_FUSE_WORD_COUNT]>,
    selected: Cell<(u32, u32)>,
    failed_word: Cell<Option<(u32, u32)>>,
    reads: RefCell<Vec<(u32, u32)>>,
    writes: RefCell<Vec<(u32, u32, u32)>>,
}

impl TestOtp {
    fn new() -> Self {
        Self {
            disable: Cell::new(Ok(0)),
            firmware_words: Cell::new(encode_linear_or_svn(3)),
            manifest_words: Cell::new(encode_linear_or_svn(3)),
            selected: Cell::new((0, 0)),
            failed_word: Cell::new(None),
            reads: RefCell::new(Vec::new()),
            writes: RefCell::new(Vec::new()),
        }
    }

    fn words(&self, reg: u32) -> &Cell<[u32; SVN_FUSE_WORD_COUNT]> {
        match reg {
            otp::reg::CALIPTRA_FW_SVN => &self.firmware_words,
            otp::reg::SOC_MANIFEST_SVN => &self.manifest_words,
            _ => panic!("unexpected SVN register {reg}"),
        }
    }

    fn set_floor(&self, reg: u32, svn: u32) {
        self.words(reg).set(encode_linear_or_svn(svn));
    }
}

impl SyscallDriver for TestOtp {
    fn info(&self) -> DriverInfo {
        DriverInfo::new(otp::OTP_DRIVER_NUM)
    }

    fn command(&self, command: u32, arg0: u32, arg1: u32) -> CommandReturn {
        match command {
            otp::cmd::OTP_READ_RAW => {
                let entry =
                    caliptra_mcu_registers_generated::fuses::OTP_CPTRA_CORE_ANTI_ROLLBACK_DISABLE;
                assert_eq!((arg0, arg1), ((entry.byte_offset / 4) as u32, 0));
                match self.disable.get() {
                    Ok(value) => command_return::success_u32(value),
                    Err(error) => command_return::failure(error),
                }
            }
            otp::cmd::OTP_SET_REGISTER => {
                self.selected.set((arg0, arg1));
                command_return::success()
            }
            otp::cmd::OTP_READ => {
                let selected = self.selected.get();
                assert_eq!(selected, (arg0, arg1));
                self.reads.borrow_mut().push(selected);
                if self.failed_word.get() == Some(selected) {
                    command_return::failure(ErrorCode::NoDevice)
                } else {
                    command_return::success_u32(self.words(arg0).get()[arg1 as usize])
                }
            }
            otp::cmd::OTP_WRITE => {
                let (reg, index) = self.selected.get();
                assert_eq!(arg1, 0);
                let mut words = self.words(reg).get();
                assert_eq!(words[index as usize] & arg0, words[index as usize]);
                words[index as usize] = arg0;
                self.words(reg).set(words);
                self.writes.borrow_mut().push((reg, index, arg0));
                command_return::success()
            }
            _ => panic!("unexpected OTP command {command}"),
        }
    }
}

#[derive(Default)]
struct TestMailbox {
    share_ref: DriverShareRef,
    responses: RefCell<VecDeque<(u32, Vec<u8>)>>,
    started: Cell<Option<u32>>,
    commands: RefCell<Vec<u32>>,
}

impl TestMailbox {
    fn respond(&self, command: CommandId, response: &[u8]) {
        self.responses
            .borrow_mut()
            .push_back((command.into(), response.to_vec()));
    }

    fn complete(&self, command: u32) -> CommandReturn {
        let (expected_command, response) = self
            .responses
            .borrow_mut()
            .pop_front()
            .expect("unexpected mailbox request");
        assert_eq!(expected_command, command);
        self.share_ref
            .schedule_upcall(0, (response.len() as u32, 0, 0))
            .unwrap();
        command_return::success()
    }
}

impl SyscallDriver for TestMailbox {
    fn info(&self) -> DriverInfo {
        DriverInfo::new(MAILBOX_DRIVER_NUM).upcall_count(1)
    }

    fn register(&self, share_ref: DriverShareRef) {
        self.share_ref.replace(share_ref);
    }

    fn command(&self, command: u32, arg0: u32, _arg1: u32) -> CommandReturn {
        // These are the private mailbox syscall IDs, not Caliptra command IDs.
        match command {
            1 => {
                self.commands.borrow_mut().push(arg0);
                self.complete(arg0)
            }
            2 => {
                assert_eq!(self.started.replace(Some(arg0)), None);
                self.commands.borrow_mut().push(arg0);
                command_return::success()
            }
            3 => {
                assert!(self.started.get().is_some());
                self.share_ref.schedule_upcall(0, (0, 0, 0)).unwrap();
                command_return::success()
            }
            4 => {
                assert_eq!(self.started.replace(None), Some(arg0));
                self.complete(arg0)
            }
            5 => {
                self.started.set(None);
                command_return::success()
            }
            _ => panic!("unexpected mailbox syscall {command}"),
        }
    }

    fn allow_readonly(
        &self,
        number: u32,
        buffer: RoAllowBuffer,
    ) -> Result<RoAllowBuffer, (RoAllowBuffer, ErrorCode)> {
        assert_eq!(number, 0);
        Ok(buffer)
    }

    fn allow_readwrite(
        &self,
        number: u32,
        mut buffer: RwAllowBuffer,
    ) -> Result<RwAllowBuffer, (RwAllowBuffer, ErrorCode)> {
        assert_eq!(number, 0);
        // Preload canned responses without retaining userspace buffers between chunks.
        let responses = self.responses.borrow();
        let (_, response) = responses
            .front()
            .expect("unexpected mailbox response buffer");
        buffer[..response.len()].copy_from_slice(response);
        Ok(buffer)
    }
}

#[derive(Debug)]
struct SvnStagingMemory {
    bytes: Vec<u8>,
    failed_offset: AtomicUsize,
    paused_offset: AtomicUsize,
    reads: AtomicUsize,
}

impl SvnStagingMemory {
    fn new(firmware_svn: u32, manifest_svn: u32) -> Self {
        let mut firmware = ImageManifest::default();
        firmware.header.svn = firmware_svn;
        let mut manifest = AuthorizationManifest::default();
        manifest.preamble.svn = manifest_svn;

        let mut bytes = std::vec![0; COMPONENTS[1].offset + COMPONENTS[1].len];
        bytes[..size_of::<FlashHeaderV1>()]
            .copy_from_slice(FlashHeaderV1::new(COMPONENTS.len() as u16).as_bytes());
        for (index, (component, payload)) in COMPONENTS
            .iter()
            .zip([firmware.as_bytes(), manifest.as_bytes()])
            .enumerate()
        {
            bytes[component.offset..component.offset + component.len].copy_from_slice(payload);
            let mut image = ImageHeaderV1V2 {
                identifier: component.identifier,
                offset: component.offset as u32,
                size: component.len as u32,
                image_checksum: 0,
                image_header_checksum: 0,
            };
            image.image_header_checksum = calculate_checksum(
                &image.as_bytes()[..offset_of!(ImageHeaderV1V2, image_header_checksum)],
            );
            let offset = size_of::<FlashHeaderV1>() + index * size_of::<ImageHeaderV1V2>();
            bytes[offset..offset + size_of::<ImageHeaderV1V2>()].copy_from_slice(image.as_bytes());
        }
        Self {
            bytes,
            failed_offset: AtomicUsize::new(usize::MAX),
            paused_offset: AtomicUsize::new(usize::MAX),
            reads: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl StagingMemory for SvnStagingMemory {
    async fn read(&self, offset: usize, data: &mut [u8]) -> Result<(), ErrorCode> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        if self.failed_offset.load(Ordering::SeqCst) == offset {
            return Err(ErrorCode::NoMem);
        }
        core::future::poll_fn(|_| {
            if self.paused_offset.load(Ordering::SeqCst) == offset {
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        })
        .await;
        data.copy_from_slice(&self.bytes[offset..offset + data.len()]);
        Ok(())
    }

    async fn write(&self, _offset: usize, _data: &[u8]) -> Result<(), ErrorCode> {
        panic!("SVN verification must not write staging memory");
    }

    async fn image_valid(&self, _img_sz: usize) -> Result<(), ErrorCode> {
        panic!("SVN verification must not apply the image");
    }

    fn size(&self) -> usize {
        self.bytes.len()
    }
}

struct TestAlloc;

impl ScratchAlloc for TestAlloc {
    type Buf<'a> = Vec<u8>;

    fn alloc(&self, len: usize) -> mcu_error::McuResult<Self::Buf<'_>> {
        Ok(std::vec![0; len])
    }
}

struct TestDmaMapping;

impl DMAMapping for TestDmaMapping {
    fn mcu_sram_to_mcu_axi(&self, _addr: u32) -> Result<AXIAddr, ErrorCode> {
        panic!("SVN verification must not perform DMA");
    }

    fn cptra_axi_to_mcu_axi(&self, _addr: AXIAddr) -> Result<AXIAddr, ErrorCode> {
        panic!("SVN verification must not perform DMA");
    }

    fn validate_image_load_range(
        &self,
        _range: core::ops::Range<AXIAddr>,
    ) -> Result<(), ErrorCode> {
        panic!("SVN verification must not perform DMA");
    }
}

fn run_with_upcalls<T>(future: impl Future<Output = T>) -> T {
    let mut future = core::pin::pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    for _ in 0..1024 {
        if let Poll::Ready(value) = future.as_mut().poll(&mut context) {
            return value;
        }
        fake::Syscalls::yield_no_wait();
    }
    panic!("firmware update test did not complete");
}

struct Fixture {
    kernel: fake::Kernel,
    otp: Rc<TestOtp>,
    mailbox: Rc<TestMailbox>,
    staging: &'static SvnStagingMemory,
    updater: FirmwareUpdater<'static, TestDmaMapping, TestAlloc>,
}

impl Fixture {
    fn new(firmware_svn: u32, manifest_svn: u32) -> Self {
        static ALLOC: TestAlloc = TestAlloc;
        static DMA_MAPPING: TestDmaMapping = TestDmaMapping;

        let kernel = fake::Kernel::new();
        let otp = Rc::new(TestOtp::new());
        let mailbox = Rc::new(TestMailbox::default());
        kernel.add_driver(&otp);
        kernel.add_driver(&mailbox);
        mailbox.respond(
            CommandId::FIRMWARE_VERIFY,
            FirmwareVerifyResp {
                verify_result: FirmwareVerifyResult::Success as u32,
                ..Default::default()
            }
            .as_bytes(),
        );
        mailbox.respond(
            CommandId::VERIFY_AUTH_MANIFEST,
            &[0; size_of::<caliptra_api::mailbox::MailboxRespHeader>()],
        );
        let staging = Box::leak(Box::new(SvnStagingMemory::new(firmware_svn, manifest_svn)));
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
            otp,
            mailbox,
            staging,
            updater,
        }
    }

    fn check(&self, component: Component) -> Result<(), ErrorCode> {
        run_ready(self.updater.verify_staged_svn_against_otp(
            component.offset,
            component.len,
            component.svn_offset,
            component.otp_reg,
            "test artifact",
        ))
    }

    fn expect_rom_version(&self) {
        self.kernel.add_expected_syscall(ExpectedSyscall::Command {
            driver_id: system::DRIVER_NUM,
            command_id: 4,
            argument0: 0,
            argument1: 0,
            override_return: Some(command_return::failure(ErrorCode::NoSupport)),
        });
    }

    fn verify(&mut self) -> Result<FlashHeader, ErrorCode> {
        self.expect_rom_version();
        run_with_upcalls(self.updater.verify(self.staging.size()))
    }

    fn activate(&mut self, component: Component, header: &FlashHeader) -> Result<(), ErrorCode> {
        let _svn_guard = run_ready(otp::SVN_UPDATE_LOCK.lock());
        if component.otp_reg == otp::reg::CALIPTRA_FW_SVN {
            self.mailbox.respond(
                CommandId::FIRMWARE_LOAD,
                &[0; size_of::<FirmwareVerifyResp>()],
            );
            self.mailbox
                .respond(CommandId::FW_INFO, &[0; size_of::<FwInfoResp>()]);
            run_with_upcalls(self.updater.update_caliptra(header))
        } else {
            self.mailbox.respond(
                CommandId::SET_AUTH_MANIFEST,
                &[0; size_of::<caliptra_api::mailbox::MailboxRespHeader>()],
            );
            run_with_upcalls(self.updater.set_auth_manifest())
        }
    }

    fn prepare_bundle_activation(&mut self) -> &'static ActivationHooks {
        self.mailbox.respond(
            CommandId::FIRMWARE_LOAD,
            &[0; size_of::<FirmwareVerifyResp>()],
        );
        self.mailbox
            .respond(CommandId::FW_INFO, &[0; size_of::<FwInfoResp>()]);
        self.mailbox.respond(
            CommandId::SET_AUTH_MANIFEST,
            &[0; size_of::<caliptra_api::mailbox::MailboxRespHeader>()],
        );
        let hooks = Box::leak(Box::new(ActivationHooks::default()));
        self.updater.set_hooks(hooks);
        hooks
    }
}

#[derive(Default)]
struct ActivationHooks {
    calls: std::sync::Mutex<Vec<&'static str>>,
}

#[async_trait]
impl FirmwareUpdateHooks for ActivationHooks {
    async fn pre_caliptra_activation(&self) -> Result<(), ErrorCode> {
        self.calls.lock().unwrap().push("caliptra");
        Ok(())
    }

    async fn pre_auth_manifest_activation(&self) -> Result<(), ErrorCode> {
        assert!(otp::SVN_UPDATE_LOCK.try_lock().is_err());
        self.calls.lock().unwrap().push("manifest");
        Ok(())
    }

    async fn pre_mcu_activation(&self) -> Result<(), ErrorCode> {
        assert!(otp::SVN_UPDATE_LOCK.try_lock().is_err());
        self.calls.lock().unwrap().push("mcu");
        Err(ErrorCode::NoMem)
    }
}

fn burn_floor(reg: u32, svn: u32) {
    let otp = Otp::<DefaultSyscalls>::new();
    for (index, word) in encode_linear_or_svn(svn).into_iter().enumerate() {
        otp.write(reg, index as u32, word).unwrap();
    }
}

#[test]
fn staged_gate_reads_each_artifact_at_nonzero_offset_and_uses_its_floor() {
    let _guard = PLDM_TEST_LOCK.lock().unwrap();
    for component in COMPONENTS {
        for candidate in [3, 4, 5, 6] {
            let fixture = Fixture::new(candidate, candidate);
            for other in COMPONENTS {
                fixture.otp.set_floor(other.otp_reg, 128);
            }
            fixture.otp.set_floor(component.otp_reg, 5);
            let expected = if candidate < 5 {
                Err(ErrorCode::Fail)
            } else {
                Ok(())
            };
            assert_eq!(fixture.check(component), expected);
            assert_eq!(
                *fixture.otp.reads.borrow(),
                (0..SVN_FUSE_WORD_COUNT as u32)
                    .map(|index| (component.otp_reg, index))
                    .collect::<Vec<_>>()
            );
        }
    }
}

#[test]
fn staged_gate_honors_only_the_disable_bit() {
    let _guard = PLDM_TEST_LOCK.lock().unwrap();
    for component in COMPONENTS {
        for (disable_word, disabled) in [(0, false), (1, true), (4, false), (7, true)] {
            let fixture = Fixture::new(4, 4);
            fixture.otp.set_floor(component.otp_reg, 5);
            fixture.otp.disable.set(Ok(disable_word));
            if disabled {
                fixture
                    .staging
                    .failed_offset
                    .store(component.offset + component.svn_offset, Ordering::SeqCst);
                fixture.otp.failed_word.set(Some((component.otp_reg, 0)));
            }
            assert_eq!(
                fixture.check(component),
                if disabled {
                    Ok(())
                } else {
                    Err(ErrorCode::Fail)
                }
            );
            assert_eq!(
                fixture.staging.reads.load(Ordering::SeqCst),
                usize::from(!disabled)
            );
            assert_eq!(fixture.otp.reads.borrow().is_empty(), disabled);
        }
    }
}

#[test]
fn staged_gate_rejects_truncated_headers_and_offset_overflow() {
    let _guard = PLDM_TEST_LOCK.lock().unwrap();
    for component in COMPONENTS {
        let fixture = Fixture::new(4, 4);
        assert_eq!(
            fixture.check(Component {
                len: component.svn_offset + size_of::<u32>() - 1,
                ..component
            }),
            Err(ErrorCode::Fail)
        );
        assert_eq!(
            fixture.check(Component {
                offset: usize::MAX,
                ..component
            }),
            Err(ErrorCode::Fail)
        );
        assert_eq!(fixture.staging.reads.load(Ordering::SeqCst), 0);
        assert!(fixture.otp.reads.borrow().is_empty());
    }
}

#[test]
fn staged_gate_propagates_disable_staging_and_each_floor_word_error() {
    let _guard = PLDM_TEST_LOCK.lock().unwrap();
    for component in COMPONENTS {
        let fixture = Fixture::new(4, 4);
        fixture.otp.disable.set(Err(ErrorCode::NoDevice));
        assert_eq!(fixture.check(component), Err(ErrorCode::NoDevice));
        assert_eq!(fixture.staging.reads.load(Ordering::SeqCst), 0);
        assert!(fixture.otp.reads.borrow().is_empty());

        fixture.otp.disable.set(Ok(0));
        fixture
            .staging
            .failed_offset
            .store(component.offset + component.svn_offset, Ordering::SeqCst);
        assert_eq!(fixture.check(component), Err(ErrorCode::NoMem));
        assert!(fixture.otp.reads.borrow().is_empty());
        fixture
            .staging
            .failed_offset
            .store(usize::MAX, Ordering::SeqCst);
        for index in 0..SVN_FUSE_WORD_COUNT as u32 {
            fixture
                .otp
                .failed_word
                .set(Some((component.otp_reg, index)));
            assert_eq!(fixture.check(component), Err(ErrorCode::NoDevice));
        }
    }
}

#[test]
fn verification_rejects_each_artifact_before_authentication() {
    let _guard = PLDM_TEST_LOCK.lock().unwrap();
    for component in COMPONENTS {
        for candidate in [3, 4] {
            let mut fixture = if component.otp_reg == otp::reg::CALIPTRA_FW_SVN {
                Fixture::new(candidate, 6)
            } else {
                Fixture::new(6, candidate)
            };
            fixture.otp.set_floor(component.otp_reg, 5);
            assert!(matches!(fixture.verify(), Err(ErrorCode::Fail)));
            let expected = if component.otp_reg == otp::reg::CALIPTRA_FW_SVN {
                std::vec![]
            } else {
                std::vec![CommandId::FIRMWARE_VERIFY.0]
            };
            assert_eq!(*fixture.mailbox.commands.borrow(), expected);
        }
    }
}

#[test]
fn verification_preserves_authentication_when_floors_pass_or_are_disabled() {
    let _guard = PLDM_TEST_LOCK.lock().unwrap();
    for (candidate, disable_word) in [(5, 0), (6, 0), (0, 1)] {
        let mut fixture = Fixture::new(candidate, candidate);
        fixture.otp.disable.set(Ok(disable_word));
        for component in COMPONENTS {
            fixture.otp.set_floor(component.otp_reg, 5);
        }
        fixture.verify().unwrap();
        assert_eq!(
            *fixture.mailbox.commands.borrow(),
            [
                CommandId::FIRMWARE_VERIFY.0,
                CommandId::VERIFY_AUTH_MANIFEST.0
            ]
        );
    }
}

#[test]
fn verification_still_rejects_failed_cryptographic_verification() {
    let _guard = PLDM_TEST_LOCK.lock().unwrap();
    let mut fixture = Fixture::new(6, 6);
    fixture
        .mailbox
        .responses
        .borrow_mut()
        .front_mut()
        .unwrap()
        .1 = FirmwareVerifyResp {
        verify_result: u32::MAX,
        ..Default::default()
    }
    .as_bytes()
    .to_vec();
    assert!(matches!(fixture.verify(), Err(ErrorCode::Fail)));
    assert_eq!(
        *fixture.mailbox.commands.borrow(),
        [CommandId::FIRMWARE_VERIFY.0]
    );
}

#[test]
fn activation_rechecks_each_physical_floor_after_verification() {
    let _guard = PLDM_TEST_LOCK.lock().unwrap();
    for component in COMPONENTS {
        let mut fixture = Fixture::new(4, 4);
        let header = fixture.verify().unwrap();
        fixture.otp.set_floor(component.otp_reg, 5);
        fixture.otp.reads.borrow_mut().clear();
        assert_eq!(fixture.activate(component, &header), Err(ErrorCode::Fail));
        assert_eq!(
            *fixture.mailbox.commands.borrow(),
            [
                CommandId::FIRMWARE_VERIFY.0,
                CommandId::VERIFY_AUTH_MANIFEST.0
            ]
        );
        assert_eq!(
            *fixture.otp.reads.borrow(),
            (0..SVN_FUSE_WORD_COUNT as u32)
                .map(|index| (component.otp_reg, index))
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn activation_allows_candidates_at_or_above_each_physical_floor() {
    let _guard = PLDM_TEST_LOCK.lock().unwrap();
    for component in COMPONENTS {
        for candidate in [5, 6] {
            let mut fixture = Fixture::new(candidate, candidate);
            for other in COMPONENTS {
                fixture.otp.set_floor(other.otp_reg, 5);
            }
            let header = fixture.verify().unwrap();
            assert_eq!(fixture.activate(component, &header), Ok(()));
            let mut expected = std::vec![
                CommandId::FIRMWARE_VERIFY.0,
                CommandId::VERIFY_AUTH_MANIFEST.0,
            ];
            if component.otp_reg == otp::reg::CALIPTRA_FW_SVN {
                expected.extend([CommandId::FIRMWARE_LOAD.0, CommandId::FW_INFO.0]);
            } else {
                expected.push(CommandId::SET_AUTH_MANIFEST.0);
            }
            assert_eq!(*fixture.mailbox.commands.borrow(), expected);
        }
    }
}

#[test]
fn bundle_rejects_stale_manifest_before_loading_any_firmware() {
    let _guard = PLDM_TEST_LOCK.lock().unwrap();
    let mut fixture = Fixture::new(4, 4);
    let header = fixture.verify().unwrap();
    let hooks = fixture.prepare_bundle_activation();
    fixture.otp.set_floor(otp::reg::SOC_MANIFEST_SVN, 5);

    assert_eq!(
        run_with_upcalls(fixture.updater.activate_bundle(&header)),
        Err(ErrorCode::Fail)
    );
    assert_eq!(
        *fixture.mailbox.commands.borrow(),
        [
            CommandId::FIRMWARE_VERIFY.0,
            CommandId::VERIFY_AUTH_MANIFEST.0
        ]
    );
    assert_eq!(*hooks.calls.lock().unwrap(), ["caliptra"]);
    assert!(otp::SVN_UPDATE_LOCK.try_lock().is_ok());
}

#[test]
fn bundle_preflight_read_errors_release_the_guard_without_loading_firmware() {
    let _guard = PLDM_TEST_LOCK.lock().unwrap();
    for staging_error in [false, true] {
        let mut fixture = Fixture::new(4, 4);
        let header = fixture.verify().unwrap();
        fixture.prepare_bundle_activation();
        let manifest = COMPONENTS[1];
        let error = if staging_error {
            fixture
                .staging
                .failed_offset
                .store(manifest.offset + manifest.svn_offset, Ordering::SeqCst);
            ErrorCode::NoMem
        } else {
            fixture.otp.failed_word.set(Some((manifest.otp_reg, 2)));
            ErrorCode::NoDevice
        };
        assert_eq!(
            run_with_upcalls(fixture.updater.activate_bundle(&header)),
            Err(error)
        );
        assert_eq!(
            *fixture.mailbox.commands.borrow(),
            [
                CommandId::FIRMWARE_VERIFY.0,
                CommandId::VERIFY_AUTH_MANIFEST.0
            ]
        );
        assert!(otp::SVN_UPDATE_LOCK.try_lock().is_ok());
    }
}

#[test]
fn activation_waits_for_a_floor_writer_paused_in_fw_info() {
    let _guard = PLDM_TEST_LOCK.lock().unwrap();
    let mut fixture = Fixture::new(4, 4);
    let header = fixture.verify().unwrap();
    let mut info = FwInfoResp {
        fw_svn: 6,
        ..FwInfoResp::new_zeroed()
    };
    info.hdr.chksum = caliptra_api::calc_checksum(0, &info.as_bytes()[4..]);
    fixture.mailbox.respond(CommandId::FW_INFO, info.as_bytes());
    fixture.prepare_bundle_activation();
    fixture.otp.reads.borrow_mut().clear();

    let mut writer = core::pin::pin!(async {
        let _svn_guard = otp::SVN_UPDATE_LOCK.lock().await;
        let info = crate::fw_info(&TestAlloc).await.unwrap();
        assert!(info.fw_svn >= 5);
        burn_floor(otp::reg::CALIPTRA_FW_SVN, 5);
    });
    let mut context = Context::from_waker(Waker::noop());
    assert!(writer.as_mut().poll(&mut context).is_pending());
    let mut activation = core::pin::pin!(fixture.updater.activate_bundle(&header));
    assert!(activation.as_mut().poll(&mut context).is_pending());
    let deferred_reads = fixture.otp.reads.borrow().is_empty();

    run_with_upcalls(writer.as_mut());
    let result = run_with_upcalls(activation.as_mut());
    assert!(deferred_reads);
    assert_eq!(result, Err(ErrorCode::Fail));
    assert_eq!(fixture.otp.firmware_words.get(), encode_linear_or_svn(5));
    assert_eq!(
        *fixture.mailbox.commands.borrow(),
        [
            CommandId::FIRMWARE_VERIFY.0,
            CommandId::VERIFY_AUTH_MANIFEST.0,
            CommandId::FW_INFO.0
        ]
    );
    assert!(otp::SVN_UPDATE_LOCK.try_lock().is_ok());
}

#[test]
fn activation_blocks_both_floor_writers_across_async_staging() {
    let _guard = PLDM_TEST_LOCK.lock().unwrap();
    for component in COMPONENTS {
        let mut fixture = Fixture::new(4, 4);
        let header = fixture.verify().unwrap();
        let hooks = fixture.prepare_bundle_activation();
        fixture
            .staging
            .paused_offset
            .store(COMPONENTS[0].offset, Ordering::SeqCst);
        let mut activation = core::pin::pin!(fixture.updater.activate_bundle(&header));
        let mut context = Context::from_waker(Waker::noop());
        assert!(activation.as_mut().poll(&mut context).is_pending());

        let mut writer = core::pin::pin!(async {
            let _svn_guard = otp::SVN_UPDATE_LOCK.lock().await;
            burn_floor(component.otp_reg, 5);
        });
        assert!(writer.as_mut().poll(&mut context).is_pending());
        assert!(fixture.otp.writes.borrow().is_empty());
        assert_eq!(
            fixture.otp.words(component.otp_reg).get(),
            encode_linear_or_svn(3)
        );

        fixture
            .staging
            .paused_offset
            .store(usize::MAX, Ordering::SeqCst);
        assert_eq!(run_with_upcalls(activation.as_mut()), Err(ErrorCode::NoMem));
        assert_eq!(
            *hooks.calls.lock().unwrap(),
            ["caliptra", "manifest", "mcu"]
        );
        run_with_upcalls(writer.as_mut());
        assert_eq!(
            fixture.otp.words(component.otp_reg).get(),
            encode_linear_or_svn(5)
        );
        assert_eq!(
            *fixture.mailbox.commands.borrow(),
            [
                CommandId::FIRMWARE_VERIFY.0,
                CommandId::VERIFY_AUTH_MANIFEST.0,
                CommandId::FIRMWARE_LOAD.0,
                CommandId::FW_INFO.0,
                CommandId::SET_AUTH_MANIFEST.0
            ]
        );
        assert!(otp::SVN_UPDATE_LOCK.try_lock().is_ok());
    }
}

#[test]
fn manifest_only_activation_waits_for_the_same_transaction_guard() {
    let _guard = PLDM_TEST_LOCK.lock().unwrap();
    let mut fixture = Fixture::new(4, 4);
    let header = fixture.verify().unwrap();
    fixture.otp.set_floor(otp::reg::SOC_MANIFEST_SVN, 5);
    fixture.otp.reads.borrow_mut().clear();
    fixture.expect_rom_version();
    let svn_guard = run_ready(otp::SVN_UPDATE_LOCK.lock());
    let mut activation = core::pin::pin!(fixture.updater.update_mcu_with_auth_manifest(&header));
    let mut context = Context::from_waker(Waker::noop());
    assert!(activation.as_mut().poll(&mut context).is_pending());
    assert!(fixture.otp.reads.borrow().is_empty());
    drop(svn_guard);
    assert_eq!(run_with_upcalls(activation.as_mut()), Err(ErrorCode::Fail));
    assert_eq!(
        *fixture.mailbox.commands.borrow(),
        [
            CommandId::FIRMWARE_VERIFY.0,
            CommandId::VERIFY_AUTH_MANIFEST.0
        ]
    );
    assert!(otp::SVN_UPDATE_LOCK.try_lock().is_ok());
}
