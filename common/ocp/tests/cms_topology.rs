// Licensed under the Apache-2.0 license

//! Integration test: CMS topology exercising process_command()
//! end-to-end with mixed indirect + FIFO regions.

mod common;

extern crate alloc;

use alloc::vec::Vec;
use core::cell::RefCell;

use common::{take_last_response, test_config, MockUsbDeviceDriver};
use ocp::cms::slice_fifo::SliceFifoRegion;
use ocp::cms::slice_indirect::SliceIndirectRegion;
use ocp::interface::{RecoveryAction, RecoveryStateMachine};
use ocp::protocol::device_status::RecoveryReasonCode;
use ocp::protocol::indirect_fifo_status::{self, FifoCmsRegionType};
use ocp::protocol::indirect_status::{self, CmsRegionType};
use ocp::protocol::RecoveryCommand;
use ocp::vendor::NoopVendorHandler;

/// Accessing a FIFO CMS region (index 1) via INDIRECT_CTRL + INDIRECT_STATUS
/// should report CmsRegionType::Unsupported.
#[test]
fn fifo_cms_via_indirect_ctrl_returns_unsupported() {
    let sent = RefCell::new(Vec::new());
    let mut ind_buf = [0u8; 64];
    let mut ind_region = SliceIndirectRegion::new(&mut ind_buf, CmsRegionType::CodeSpace).unwrap();
    let mut fifo_buf = [0u8; 64];
    let mut fifo_region =
        SliceFifoRegion::new(&mut fifo_buf, FifoCmsRegionType::CodeSpace, 16).unwrap();

    let mut ind_regions: [(u8, &mut dyn ocp::cms::IndirectCmsRegion); 1] = [(0, &mut ind_region)];
    let mut fifo_regions: [(u8, &mut dyn ocp::cms::FifoCmsRegion); 1] = [(1, &mut fifo_region)];

    let mut transport = MockUsbDeviceDriver::new(&sent);

    // Select FIFO index (1) via INDIRECT_CTRL
    transport.enqueue_write(
        RecoveryCommand::IndirectCtrl,
        &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00],
    );
    // Read INDIRECT_STATUS — should report Unsupported
    transport.enqueue_read(RecoveryCommand::IndirectStatus);

    let mut sm = RecoveryStateMachine::new(
        test_config(),
        &mut transport,
        &mut ind_regions,
        &mut fifo_regions,
        NoopVendorHandler,
    )
    .unwrap();

    sm.enter_recovery(RecoveryReasonCode::CorruptedMissingCriticalData);

    // INDIRECT_CTRL write: select CMS 1 (FIFO)
    let action = sm.process_command().unwrap();
    assert_eq!(action, RecoveryAction::IndirectCtrlChanged);

    // INDIRECT_STATUS read
    let action = sm.process_command().unwrap();
    assert_eq!(action, RecoveryAction::None);

    let resp = take_last_response(&sent);
    assert_eq!(resp.len(), indirect_status::MESSAGE_LEN);
    assert_eq!(resp[1] & 0x07, CmsRegionType::Unsupported as u8);
}

/// Accessing an indirect CMS region (index 0) via INDIRECT_FIFO_CTRL +
/// INDIRECT_FIFO_STATUS should report FifoCmsRegionType::Unsupported.
#[test]
fn indirect_cms_via_fifo_ctrl_returns_unsupported() {
    let sent = RefCell::new(Vec::new());
    let mut ind_buf = [0u8; 64];
    let mut ind_region = SliceIndirectRegion::new(&mut ind_buf, CmsRegionType::CodeSpace).unwrap();
    let mut fifo_buf = [0u8; 64];
    let mut fifo_region =
        SliceFifoRegion::new(&mut fifo_buf, FifoCmsRegionType::CodeSpace, 16).unwrap();

    let mut ind_regions: [(u8, &mut dyn ocp::cms::IndirectCmsRegion); 1] = [(0, &mut ind_region)];
    let mut fifo_regions: [(u8, &mut dyn ocp::cms::FifoCmsRegion); 1] = [(1, &mut fifo_region)];

    let mut transport = MockUsbDeviceDriver::new(&sent);

    // Select indirect index (0) via INDIRECT_FIFO_CTRL
    transport.enqueue_write(
        RecoveryCommand::IndirectFifoCtrl,
        &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    );
    // Read INDIRECT_FIFO_STATUS — should report Unsupported
    transport.enqueue_read(RecoveryCommand::IndirectFifoStatus);

    let mut sm = RecoveryStateMachine::new(
        test_config(),
        &mut transport,
        &mut ind_regions,
        &mut fifo_regions,
        NoopVendorHandler,
    )
    .unwrap();

    sm.enter_recovery(RecoveryReasonCode::CorruptedMissingCriticalData);

    // INDIRECT_FIFO_CTRL write: select CMS 0 (indirect)
    let action = sm.process_command().unwrap();
    assert_eq!(action, RecoveryAction::IndirectFifoCtrlChanged);

    // INDIRECT_FIFO_STATUS read
    let action = sm.process_command().unwrap();
    assert_eq!(action, RecoveryAction::None);

    let resp = take_last_response(&sent);
    assert_eq!(resp.len(), indirect_fifo_status::MESSAGE_LEN);
    assert_eq!(resp[1], FifoCmsRegionType::Unsupported as u8);
}

/// Invalid CMS index (no region exists) returns Unsupported for both
/// INDIRECT_STATUS and INDIRECT_FIFO_STATUS.
#[test]
fn invalid_cms_index_returns_unsupported() {
    let sent = RefCell::new(Vec::new());
    let mut ind_buf = [0u8; 64];
    let mut ind_region = SliceIndirectRegion::new(&mut ind_buf, CmsRegionType::CodeSpace).unwrap();
    let mut fifo_buf = [0u8; 64];
    let mut fifo_region =
        SliceFifoRegion::new(&mut fifo_buf, FifoCmsRegionType::CodeSpace, 16).unwrap();

    let mut ind_regions: [(u8, &mut dyn ocp::cms::IndirectCmsRegion); 1] = [(0, &mut ind_region)];
    let mut fifo_regions: [(u8, &mut dyn ocp::cms::FifoCmsRegion); 1] = [(1, &mut fifo_region)];

    let mut transport = MockUsbDeviceDriver::new(&sent);

    // Select nonexistent CMS index 99 via INDIRECT_CTRL
    transport.enqueue_write(
        RecoveryCommand::IndirectCtrl,
        &[99, 0x00, 0x00, 0x00, 0x00, 0x00],
    );
    transport.enqueue_read(RecoveryCommand::IndirectStatus);

    // Select nonexistent CMS index 99 via INDIRECT_FIFO_CTRL
    transport.enqueue_write(
        RecoveryCommand::IndirectFifoCtrl,
        &[99, 0x00, 0x00, 0x00, 0x00, 0x00],
    );
    transport.enqueue_read(RecoveryCommand::IndirectFifoStatus);

    let mut sm = RecoveryStateMachine::new(
        test_config(),
        &mut transport,
        &mut ind_regions,
        &mut fifo_regions,
        NoopVendorHandler,
    )
    .unwrap();

    sm.enter_recovery(RecoveryReasonCode::CorruptedMissingCriticalData);

    // INDIRECT_CTRL write: select CMS 99
    sm.process_command().unwrap();

    // INDIRECT_STATUS read: Unsupported
    sm.process_command().unwrap();
    let resp = take_last_response(&sent);
    assert_eq!(resp[1] & 0x07, CmsRegionType::Unsupported as u8);

    // INDIRECT_FIFO_CTRL write: select CMS 99
    sm.process_command().unwrap();

    // INDIRECT_FIFO_STATUS read: Unsupported
    sm.process_command().unwrap();
    let resp = take_last_response(&sent);
    assert_eq!(resp[1], FifoCmsRegionType::Unsupported as u8);
}

/// Multiple code regions across different CMS indices: write data to
/// indirect CMS 0, write data to indirect CMS 2, and verify each region
/// holds its own data independently.
#[test]
fn multiple_code_regions_across_indices() {
    let sent = RefCell::new(Vec::new());
    let mut buf0 = [0u8; 64];
    let mut region0 = SliceIndirectRegion::new(&mut buf0, CmsRegionType::CodeSpace).unwrap();
    let mut buf2 = [0u8; 64];
    let mut region2 = SliceIndirectRegion::new(&mut buf2, CmsRegionType::CodeSpace).unwrap();

    let mut ind_regions: [(u8, &mut dyn ocp::cms::IndirectCmsRegion); 2] =
        [(0, &mut region0), (2, &mut region2)];

    let mut transport = MockUsbDeviceDriver::new(&sent);

    // Select CMS 0, write data
    transport.enqueue_write(
        RecoveryCommand::IndirectCtrl,
        &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    );
    transport.enqueue_write(RecoveryCommand::IndirectData, &[0xAA, 0xBB, 0xCC, 0xDD]);
    // Read INDIRECT_STATUS for CMS 0 (should be CodeSpace)
    transport.enqueue_read(RecoveryCommand::IndirectStatus);

    // Select CMS 2, write different data
    transport.enqueue_write(
        RecoveryCommand::IndirectCtrl,
        &[0x02, 0x00, 0x00, 0x00, 0x00, 0x00],
    );
    transport.enqueue_write(RecoveryCommand::IndirectData, &[0x11, 0x22, 0x33, 0x44]);
    // Read INDIRECT_STATUS for CMS 2 (should be CodeSpace)
    transport.enqueue_read(RecoveryCommand::IndirectStatus);

    // Switch back to CMS 0, read data back
    transport.enqueue_write(
        RecoveryCommand::IndirectCtrl,
        &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    );
    transport.enqueue_read(RecoveryCommand::IndirectData);

    // Switch to CMS 2, read data back
    transport.enqueue_write(
        RecoveryCommand::IndirectCtrl,
        &[0x02, 0x00, 0x00, 0x00, 0x00, 0x00],
    );
    transport.enqueue_read(RecoveryCommand::IndirectData);

    let mut sm = RecoveryStateMachine::new(
        test_config(),
        &mut transport,
        &mut ind_regions,
        &mut [],
        NoopVendorHandler,
    )
    .unwrap();

    sm.enter_recovery(RecoveryReasonCode::CorruptedMissingCriticalData);

    // -- Write to CMS 0 --
    sm.process_command().unwrap(); // INDIRECT_CTRL: select CMS 0
    sm.process_command().unwrap(); // INDIRECT_DATA: write 0xAA..

    // INDIRECT_STATUS for CMS 0: CodeSpace
    sm.process_command().unwrap();
    let resp = take_last_response(&sent);
    assert_eq!(resp[1] & 0x07, CmsRegionType::CodeSpace as u8);

    // -- Write to CMS 2 --
    sm.process_command().unwrap(); // INDIRECT_CTRL: select CMS 2
    sm.process_command().unwrap(); // INDIRECT_DATA: write 0x11..

    // INDIRECT_STATUS for CMS 2: CodeSpace
    sm.process_command().unwrap();
    let resp = take_last_response(&sent);
    assert_eq!(resp[1] & 0x07, CmsRegionType::CodeSpace as u8);

    // -- Read back CMS 0 --
    sm.process_command().unwrap(); // INDIRECT_CTRL: select CMS 0
    sm.process_command().unwrap(); // INDIRECT_DATA: read
    let resp = take_last_response(&sent);
    assert_eq!(&resp[..4], &[0xAA, 0xBB, 0xCC, 0xDD]);

    // -- Read back CMS 2 --
    sm.process_command().unwrap(); // INDIRECT_CTRL: select CMS 2
    sm.process_command().unwrap(); // INDIRECT_DATA: read
    let resp = take_last_response(&sent);
    assert_eq!(&resp[..4], &[0x11, 0x22, 0x33, 0x44]);
}

/// Mixed topology: verify that INDIRECT_STATUS for the indirect region
/// reports CodeSpace and INDIRECT_FIFO_STATUS for the FIFO region reports
/// CodeSpace, confirming both types coexist correctly.
#[test]
fn mixed_topology_both_types_report_correctly() {
    let sent = RefCell::new(Vec::new());
    let mut ind_buf = [0u8; 64];
    let mut ind_region = SliceIndirectRegion::new(&mut ind_buf, CmsRegionType::CodeSpace).unwrap();
    let mut fifo_buf = [0u8; 64];
    let mut fifo_region =
        SliceFifoRegion::new(&mut fifo_buf, FifoCmsRegionType::CodeSpace, 16).unwrap();

    let mut ind_regions: [(u8, &mut dyn ocp::cms::IndirectCmsRegion); 1] = [(0, &mut ind_region)];
    let mut fifo_regions: [(u8, &mut dyn ocp::cms::FifoCmsRegion); 1] = [(1, &mut fifo_region)];

    let mut transport = MockUsbDeviceDriver::new(&sent);

    // Select CMS 0 via INDIRECT_CTRL, read INDIRECT_STATUS
    transport.enqueue_write(
        RecoveryCommand::IndirectCtrl,
        &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    );
    transport.enqueue_read(RecoveryCommand::IndirectStatus);

    // Select CMS 1 via INDIRECT_FIFO_CTRL, read INDIRECT_FIFO_STATUS
    transport.enqueue_write(
        RecoveryCommand::IndirectFifoCtrl,
        &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00],
    );
    transport.enqueue_read(RecoveryCommand::IndirectFifoStatus);

    let mut sm = RecoveryStateMachine::new(
        test_config(),
        &mut transport,
        &mut ind_regions,
        &mut fifo_regions,
        NoopVendorHandler,
    )
    .unwrap();

    sm.enter_recovery(RecoveryReasonCode::CorruptedMissingCriticalData);

    // INDIRECT_CTRL: select CMS 0
    sm.process_command().unwrap();
    // INDIRECT_STATUS: should be CodeSpace
    sm.process_command().unwrap();
    let resp = take_last_response(&sent);
    assert_eq!(resp.len(), indirect_status::MESSAGE_LEN);
    assert_eq!(resp[1] & 0x07, CmsRegionType::CodeSpace as u8);

    // INDIRECT_FIFO_CTRL: select CMS 1
    sm.process_command().unwrap();
    // INDIRECT_FIFO_STATUS: should be CodeSpace
    sm.process_command().unwrap();
    let resp = take_last_response(&sent);
    assert_eq!(resp.len(), indirect_fifo_status::MESSAGE_LEN);
    assert_eq!(resp[1], FifoCmsRegionType::CodeSpace as u8);
}
