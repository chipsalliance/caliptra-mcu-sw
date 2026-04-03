// Licensed under the Apache-2.0 license

//! Integration test: activation flow exercising process_command()
//! end-to-end with a mock USB device driver and slice-backed CMS regions.

mod common;

extern crate alloc;

use alloc::vec::Vec;
use core::cell::RefCell;

use common::{
    take_last_response, test_config, test_config_with_local_c_image, MockUsbDeviceDriver,
};
use ocp::cms::slice_indirect::SliceIndirectRegion;
use ocp::interface::{ActivationResult, RecoveryAction, RecoveryStateMachine};
use ocp::protocol::device_status::{DeviceStatusValue, RecoveryReasonCode};
use ocp::protocol::indirect_status::CmsRegionType;
use ocp::protocol::recovery_status::DeviceRecoveryStatus;
use ocp::protocol::RecoveryCommand;
use ocp::vendor::NoopVendorHandler;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Multi-stage activation: stage 1 succeeds, push more data, stage 2 completes.
#[test]
fn multi_stage_activation_sequence() {
    let sent = RefCell::new(Vec::new());
    let mut cms_buf = [0u8; 64];
    let mut region = SliceIndirectRegion::new(&mut cms_buf, CmsRegionType::CodeSpace).unwrap();
    let mut regions: [(u8, &mut dyn ocp::cms::IndirectCmsRegion); 1] = [(0, &mut region)];
    let mut transport = MockUsbDeviceDriver::new(&sent);

    // Stage 1 commands: select CMS, push data, activate
    transport.enqueue_write(
        RecoveryCommand::IndirectCtrl,
        &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    );
    transport.enqueue_write(RecoveryCommand::IndirectData, &[0xAA, 0xBB]);
    transport.enqueue_write(RecoveryCommand::RecoveryCtrl, &[0x00, 0x01, 0x0F]);
    // Read RECOVERY_STATUS after stage 1 completion
    transport.enqueue_read(RecoveryCommand::RecoveryStatus);

    // Stage 2 commands: push more data, activate again
    transport.enqueue_write(RecoveryCommand::IndirectData, &[0xCC, 0xDD]);
    transport.enqueue_write(RecoveryCommand::RecoveryCtrl, &[0x00, 0x01, 0x0F]);
    // Read RECOVERY_STATUS after final completion
    transport.enqueue_read(RecoveryCommand::RecoveryStatus);

    let mut sm = RecoveryStateMachine::new(
        test_config(),
        &mut transport,
        &mut regions,
        &mut [],
        NoopVendorHandler,
    )
    .unwrap();

    sm.enter_recovery(RecoveryReasonCode::CorruptedMissingCriticalData);

    // -- Stage 1 --
    // Select CMS 0
    let action = sm.process_command().unwrap();
    assert_eq!(action, RecoveryAction::IndirectCtrlChanged);
    // Push data
    let action = sm.process_command().unwrap();
    assert_eq!(action, RecoveryAction::None);
    // Activate
    let action = sm.process_command().unwrap();
    assert_eq!(action, RecoveryAction::ActivateRecoveryImage);

    // Integrator: stage 1 succeeded, more stages needed
    sm.complete_activation(ActivationResult::StageSuccess)
        .unwrap();

    // Read RECOVERY_STATUS: expect AwaitingImage with image_index = 1
    let action = sm.process_command().unwrap();
    assert_eq!(action, RecoveryAction::None);
    let resp = take_last_response(&sent);
    assert_eq!(resp[0] & 0x0F, DeviceRecoveryStatus::AwaitingImage as u8);
    assert_eq!((resp[0] >> 4) & 0x0F, 1); // image_index incremented to 1

    // -- Stage 2 --
    // Push more data
    let action = sm.process_command().unwrap();
    assert_eq!(action, RecoveryAction::None);
    // Activate
    let action = sm.process_command().unwrap();
    assert_eq!(action, RecoveryAction::ActivateRecoveryImage);

    // Integrator: final stage complete
    sm.complete_activation(ActivationResult::Complete).unwrap();

    // Read RECOVERY_STATUS: expect Success
    let action = sm.process_command().unwrap();
    assert_eq!(action, RecoveryAction::None);
    let resp = take_last_response(&sent);
    assert_eq!(resp[0] & 0x0F, DeviceRecoveryStatus::Success as u8);
}

/// Activation failure followed by retry: first activation fails, then the
/// host pushes new data and activates again successfully.
#[test]
fn activation_failure_and_retry() {
    let sent = RefCell::new(Vec::new());
    let mut cms_buf = [0u8; 64];
    let mut region = SliceIndirectRegion::new(&mut cms_buf, CmsRegionType::CodeSpace).unwrap();
    let mut regions: [(u8, &mut dyn ocp::cms::IndirectCmsRegion); 1] = [(0, &mut region)];
    let mut transport = MockUsbDeviceDriver::new(&sent);

    // Attempt 1: select CMS, push data, activate (will fail)
    transport.enqueue_write(
        RecoveryCommand::IndirectCtrl,
        &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    );
    transport.enqueue_write(RecoveryCommand::IndirectData, &[0x01, 0x02]);
    transport.enqueue_write(RecoveryCommand::RecoveryCtrl, &[0x00, 0x01, 0x0F]);
    // Read RECOVERY_STATUS after failure
    transport.enqueue_read(RecoveryCommand::RecoveryStatus);
    // Read DEVICE_STATUS after failure
    transport.enqueue_read(RecoveryCommand::DeviceStatus);

    // Attempt 2: push new data, activate (will succeed)
    transport.enqueue_write(RecoveryCommand::IndirectData, &[0x03, 0x04]);
    transport.enqueue_write(RecoveryCommand::RecoveryCtrl, &[0x00, 0x01, 0x0F]);
    // Read RECOVERY_STATUS after success
    transport.enqueue_read(RecoveryCommand::RecoveryStatus);
    // Read DEVICE_STATUS after success
    transport.enqueue_read(RecoveryCommand::DeviceStatus);

    let mut sm = RecoveryStateMachine::new(
        test_config(),
        &mut transport,
        &mut regions,
        &mut [],
        NoopVendorHandler,
    )
    .unwrap();

    sm.enter_recovery(RecoveryReasonCode::CorruptedMissingCriticalData);

    // -- Attempt 1 --
    sm.process_command().unwrap(); // INDIRECT_CTRL
    sm.process_command().unwrap(); // INDIRECT_DATA

    let action = sm.process_command().unwrap(); // RECOVERY_CTRL
    assert_eq!(action, RecoveryAction::ActivateRecoveryImage);

    // Integrator: activation failed
    sm.complete_activation(ActivationResult::Failed).unwrap();

    // Verify RECOVERY_STATUS shows Failed
    sm.process_command().unwrap();
    let resp = take_last_response(&sent);
    assert_eq!(resp[0] & 0x0F, DeviceRecoveryStatus::Failed as u8);

    // Verify DEVICE_STATUS shows BootFailure after failed activation
    sm.process_command().unwrap();
    let resp = take_last_response(&sent);
    assert_eq!(resp[0], DeviceStatusValue::BootFailure as u8);

    // -- Attempt 2 (retry) --
    sm.process_command().unwrap(); // INDIRECT_DATA (new image)

    let action = sm.process_command().unwrap(); // RECOVERY_CTRL
    assert_eq!(action, RecoveryAction::ActivateRecoveryImage);

    // Integrator: activation succeeded
    sm.complete_activation(ActivationResult::Complete).unwrap();

    // Verify RECOVERY_STATUS shows Success
    sm.process_command().unwrap();
    let resp = take_last_response(&sent);
    assert_eq!(resp[0] & 0x0F, DeviceRecoveryStatus::Success as u8);

    // Verify DEVICE_STATUS shows RunningRecoveryImage
    sm.process_command().unwrap();
    let resp = take_last_response(&sent);
    assert_eq!(resp[0], DeviceStatusValue::RunningRecoveryImage as u8);
}

/// Authentication error during activation: verify status and device state.
#[test]
fn activation_authentication_error_and_retry() {
    let sent = RefCell::new(Vec::new());
    let mut cms_buf = [0u8; 64];
    let mut region = SliceIndirectRegion::new(&mut cms_buf, CmsRegionType::CodeSpace).unwrap();
    let mut regions: [(u8, &mut dyn ocp::cms::IndirectCmsRegion); 1] = [(0, &mut region)];
    let mut transport = MockUsbDeviceDriver::new(&sent);

    // Auth error attempt
    transport.enqueue_write(
        RecoveryCommand::IndirectCtrl,
        &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    );
    transport.enqueue_write(RecoveryCommand::IndirectData, &[0xBA, 0xD0]);
    transport.enqueue_write(RecoveryCommand::RecoveryCtrl, &[0x00, 0x01, 0x0F]);
    transport.enqueue_read(RecoveryCommand::RecoveryStatus);
    transport.enqueue_read(RecoveryCommand::DeviceStatus);

    // Retry with good image
    transport.enqueue_write(RecoveryCommand::IndirectData, &[0x60, 0x0D]);
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

    sm.enter_recovery(RecoveryReasonCode::CorruptedMissingCriticalData);

    sm.process_command().unwrap(); // INDIRECT_CTRL
    sm.process_command().unwrap(); // INDIRECT_DATA
    let action = sm.process_command().unwrap(); // RECOVERY_CTRL
    assert_eq!(action, RecoveryAction::ActivateRecoveryImage);

    sm.complete_activation(ActivationResult::AuthenticationError)
        .unwrap();

    // RECOVERY_STATUS: AuthenticationError
    sm.process_command().unwrap();
    let resp = take_last_response(&sent);
    assert_eq!(
        resp[0] & 0x0F,
        DeviceRecoveryStatus::AuthenticationError as u8
    );

    // DEVICE_STATUS: BootFailure after auth error
    sm.process_command().unwrap();
    let resp = take_last_response(&sent);
    assert_eq!(resp[0], DeviceStatusValue::BootFailure as u8);

    // Retry: push good data and activate
    sm.process_command().unwrap(); // INDIRECT_DATA
    let action = sm.process_command().unwrap(); // RECOVERY_CTRL
    assert_eq!(action, RecoveryAction::ActivateRecoveryImage);

    sm.complete_activation(ActivationResult::Complete).unwrap();

    sm.process_command().unwrap();
    let resp = take_last_response(&sent);
    assert_eq!(resp[0] & 0x0F, DeviceRecoveryStatus::Success as u8);
}

/// Combined image selection + activation in a single RECOVERY_CTRL write:
/// CMS 0, MemoryWindow, Activate — all in one command.
#[test]
fn combined_image_selection_and_activation() {
    let sent = RefCell::new(Vec::new());
    let mut cms_buf = [0u8; 64];
    let mut region = SliceIndirectRegion::new(&mut cms_buf, CmsRegionType::CodeSpace).unwrap();
    let mut regions: [(u8, &mut dyn ocp::cms::IndirectCmsRegion); 1] = [(0, &mut region)];
    let mut transport = MockUsbDeviceDriver::new(&sent);

    // Select CMS, push data, then single combined RECOVERY_CTRL
    transport.enqueue_write(
        RecoveryCommand::IndirectCtrl,
        &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    );
    transport.enqueue_write(RecoveryCommand::IndirectData, &[0xCA, 0xFE]);
    // CMS=0, ImageSelection=MemoryWindow(0x01), Activate(0x0F)
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

    sm.enter_recovery(RecoveryReasonCode::CorruptedMissingCriticalData);

    sm.process_command().unwrap(); // INDIRECT_CTRL
    sm.process_command().unwrap(); // INDIRECT_DATA

    // Single RECOVERY_CTRL that selects CMS + activates
    let action = sm.process_command().unwrap();
    assert_eq!(action, RecoveryAction::ActivateRecoveryImage);

    sm.complete_activation(ActivationResult::Complete).unwrap();

    sm.process_command().unwrap();
    let resp = take_last_response(&sent);
    assert_eq!(resp[0] & 0x0F, DeviceRecoveryStatus::Success as u8);
}

/// Local c-image selection and activation: the device activates from a
/// locally stored image without needing CMS data push.
#[test]
fn local_c_image_activation() {
    let sent = RefCell::new(Vec::new());
    let mut cms_buf = [0u8; 64];
    let mut region = SliceIndirectRegion::new(&mut cms_buf, CmsRegionType::CodeSpace).unwrap();
    let mut regions: [(u8, &mut dyn ocp::cms::IndirectCmsRegion); 1] = [(0, &mut region)];
    let mut transport = MockUsbDeviceDriver::new(&sent);

    // CMS=0, ImageSelection=LocalCImage(0x02), Activate(0x0F)
    transport.enqueue_write(RecoveryCommand::RecoveryCtrl, &[0x00, 0x02, 0x0F]);
    transport.enqueue_read(RecoveryCommand::RecoveryStatus);
    transport.enqueue_read(RecoveryCommand::DeviceStatus);

    let mut sm = RecoveryStateMachine::new(
        test_config_with_local_c_image(),
        &mut transport,
        &mut regions,
        &mut [],
        NoopVendorHandler,
    )
    .unwrap();

    sm.enter_recovery(RecoveryReasonCode::CorruptedMissingCriticalData);

    // RECOVERY_CTRL: local c-image + activate
    let action = sm.process_command().unwrap();
    assert_eq!(action, RecoveryAction::ActivateRecoveryImage);

    sm.complete_activation(ActivationResult::Complete).unwrap();

    // RECOVERY_STATUS: Success
    sm.process_command().unwrap();
    let resp = take_last_response(&sent);
    assert_eq!(resp[0] & 0x0F, DeviceRecoveryStatus::Success as u8);

    // DEVICE_STATUS: RunningRecoveryImage
    sm.process_command().unwrap();
    let resp = take_last_response(&sent);
    assert_eq!(resp[0], DeviceStatusValue::RunningRecoveryImage as u8);
}
