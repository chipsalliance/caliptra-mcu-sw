// Licensed under the Apache-2.0 license

// NOTE: Do not call `caliptra_mcu_romtime::println!` from this test. On the
// emulator the printer is wired to a UART MMIO register at 0x1000_1041; on
// the FPGA that address is unmapped and forbidden by user-mode PMP, so any
// `println!` here would fault the test process on real hardware.

use caliptra_mcu_libsyscall_caliptra::dpe_handle_store::{
    DpeHandleRecord, DpeHandleRecordFlags, DpeHandleStore, DPE_HANDLE_STORE_DRIVER_NUM,
};
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;

#[allow(unused)]
pub(crate) fn test_dpe_handle_store() {
    let store = DpeHandleStore::<DefaultSyscalls>::new(DPE_HANDLE_STORE_DRIVER_NUM);

    // Verify the driver exists.
    store.exists().unwrap();

    // Start with a clean slate.
    store.clear_records().unwrap();

    // Reading the leaf or attestation target from an empty store must fail.
    let mut out = DpeHandleRecord::default();
    assert!(store.read_leaf_record(&mut out).is_err());
    assert!(store.read_attestation_target(&mut out).is_err());

    // Write a root record (fw_id 0x0001, no parent).
    let root = DpeHandleRecord {
        fw_id: 0x0001,
        parent_fw_id: None,
        context_handle: [0xAA; 16],
        tci_tag: 0xDEAD_0001,
        flags: DpeHandleRecordFlags {
            valid: true,
            attestation_target: false,
        },
    };
    store.write_record(root.fw_id, &root).unwrap();

    // Leaf should now be the root record.
    store.read_leaf_record(&mut out).unwrap();
    assert_eq!(out, root);

    // Write a child record (fw_id 0x0002, parent 0x0001).
    let child = DpeHandleRecord {
        fw_id: 0x0002,
        parent_fw_id: Some(0x0001),
        context_handle: [0xBB; 16],
        tci_tag: 0xDEAD_0002,
        flags: DpeHandleRecordFlags {
            valid: true,
            attestation_target: false,
        },
    };
    store.write_record(child.fw_id, &child).unwrap();

    // Leaf is now the child (last valid record).
    store.read_leaf_record(&mut out).unwrap();
    assert_eq!(out, child);

    // Read the root back by fw_id.
    store.read_record(root.fw_id, &mut out).unwrap();
    assert_eq!(out, root);

    // Overwrite the child with an updated context handle.
    let child_v2 = DpeHandleRecord {
        context_handle: [0xCC; 16],
        ..child
    };
    store.write_record(child_v2.fw_id, &child_v2).unwrap();

    store.read_record(child_v2.fw_id, &mut out).unwrap();
    assert_eq!(out.context_handle, [0xCC; 16]);

    // Looking up a fw_id that does not exist should fail.
    assert!(store.read_record(0xDEAD_BEEF, &mut out).is_err());

    // Mark the child as the attestation target.
    store.mark_attestation_target(child_v2.fw_id).unwrap();

    // Marking a non-existent fw_id as attestation target must fail.
    assert!(store.mark_attestation_target(0xDEAD_BEEF).is_err());

    // Read the attestation target — should match the updated child.
    store.read_attestation_target(&mut out).unwrap();
    assert_eq!(out.fw_id, child_v2.fw_id);
    assert_eq!(out.context_handle, [0xCC; 16]);

    // clear_records resets everything: leaf and attestation target are gone.
    store.clear_records().unwrap();
    assert!(store.read_leaf_record(&mut out).is_err());
    assert!(store.read_attestation_target(&mut out).is_err());
    assert!(store.read_record(root.fw_id, &mut out).is_err());
}
