// Licensed under the Apache-2.0 license

//! Integration test: full recovery flow exercising process_command()
//! end-to-end with a mock USB device driver and slice-backed CMS regions.

mod common;

extern crate alloc;

use alloc::vec::Vec;
use core::cell::RefCell;

use common::{take_last_response, test_config, MockUsbDeviceDriver};
use ocp::cms::slice_indirect::SliceIndirectRegion;
use ocp::interface::{ActivationResult, RecoveryAction, RecoveryStateMachine};
use ocp::protocol::device_status::{DeviceStatusValue, RecoveryReasonCode};
use ocp::protocol::indirect_status::CmsRegionType;
use ocp::protocol::prot_cap::{self, RecoveryProtocolCapabilities};
use ocp::protocol::recovery_status::DeviceRecoveryStatus;
use ocp::protocol::RecoveryCommand;
use ocp::vendor::NoopVendorHandler;

#[test]
fn full_recovery_sequence() {
    let sent = RefCell::new(Vec::new());
    let mut cms_buf = [0u8; 64];
    let mut region = SliceIndirectRegion::new(&mut cms_buf, CmsRegionType::CodeSpace).unwrap();
    let mut regions: [(u8, &mut dyn ocp::cms::IndirectCmsRegion); 1] = [(0, &mut region)];

    let mut transport = MockUsbDeviceDriver::new(&sent);

    // Pre-queue the entire command sequence.
    transport.enqueue_read(RecoveryCommand::ProtCap);
    transport.enqueue_read(RecoveryCommand::DeviceStatus);
    transport.enqueue_read(RecoveryCommand::DeviceStatus);
    transport.enqueue_write(
        RecoveryCommand::IndirectCtrl,
        &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    );
    transport.enqueue_write(RecoveryCommand::IndirectData, &[0xDE, 0xAD, 0xBE, 0xEF]);
    transport.enqueue_write(RecoveryCommand::RecoveryCtrl, &[0x00, 0x01, 0x0F]);
    transport.enqueue_read(RecoveryCommand::RecoveryStatus);

    let mut sm = RecoveryStateMachine::new(
        test_config(),
        &mut transport,
        &mut regions,
        &mut [],
        NoopVendorHandler,
    )
    .unwrap();

    // Step 1: Read PROT_CAP — verify capabilities.
    let action = sm.process_command().unwrap();
    assert_eq!(action, RecoveryAction::None);

    let resp = take_last_response(&sent);
    assert_eq!(resp.len(), prot_cap::RESPONSE_LEN);
    assert_eq!(&resp[0..8], prot_cap::MAGIC);
    assert_eq!(resp[8], 1); // major
    assert_eq!(resp[9], 1); // minor
    let caps = RecoveryProtocolCapabilities(u16::from_le_bytes([resp[10], resp[11]]));
    assert!(caps.identification());
    assert!(caps.device_status());
    assert!(caps.push_c_image_support());
    assert!(caps.recovery_memory_access());
    assert_eq!(resp[12], 1); // 1 CMS region

    // Step 2: Read DEVICE_STATUS — verify StatusPending.
    let action = sm.process_command().unwrap();
    assert_eq!(action, RecoveryAction::None);

    let resp = take_last_response(&sent);
    assert_eq!(resp[0], DeviceStatusValue::StatusPending as u8);

    // Step 3: Transition to RecoveryMode (integrator-driven).
    sm.enter_recovery(RecoveryReasonCode::CorruptedMissingCriticalData);

    // Step 4: Read DEVICE_STATUS — verify RecoveryMode + reason code.
    let action = sm.process_command().unwrap();
    assert_eq!(action, RecoveryAction::None);

    let resp = take_last_response(&sent);
    assert_eq!(resp[0], DeviceStatusValue::RecoveryMode as u8);
    assert_eq!(
        u16::from_le_bytes([resp[2], resp[3]]),
        RecoveryReasonCode::CorruptedMissingCriticalData.to_u16()
    );

    // Step 5: Write INDIRECT_CTRL — select CMS 0, IMO 0.
    let action = sm.process_command().unwrap();
    assert_eq!(action, RecoveryAction::None);

    // Step 6: Write INDIRECT_DATA — push recovery image bytes.
    let action = sm.process_command().unwrap();
    assert_eq!(action, RecoveryAction::None);

    // Step 7 & 8: Write RECOVERY_CTRL — activate, expect ActivateRecoveryImage.
    let action = sm.process_command().unwrap();
    assert_eq!(action, RecoveryAction::ActivateRecoveryImage);

    // Step 9: Integrator completes activation successfully.
    sm.complete_activation(ActivationResult::Complete).unwrap();

    // Step 10: Read RECOVERY_STATUS — verify RecoverySuccessful.
    let action = sm.process_command().unwrap();
    assert_eq!(action, RecoveryAction::None);

    let resp = take_last_response(&sent);
    assert_eq!(resp.len(), 2);
    assert_eq!(resp[0] & 0x0F, DeviceRecoveryStatus::Success as u8);
}
