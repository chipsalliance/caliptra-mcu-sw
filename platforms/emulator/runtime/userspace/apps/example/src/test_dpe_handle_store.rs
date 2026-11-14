// Licensed under the Apache-2.0 license

// NOTE: Do not call `caliptra_mcu_romtime::println!` from this test.

use caliptra_mcu_libsyscall_caliptra::dpe_handle_store::{
    DpeHandleRecord, DpeHandleStore, DPE_HANDLE_STORE_DRIVER_NUM, EXPORTED_CDI_ANY_FW_ID,
    EXPORTED_CDI_SIZE, POLICY_DIGEST_SIZE,
};
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;

#[allow(unused)]
pub(crate) fn test_dpe_handle_store() {
    let store = DpeHandleStore::<DefaultSyscalls>::new(DPE_HANDLE_STORE_DRIVER_NUM);

    store.exists().unwrap();

    // Cold-boot initialization with a known policy digest.
    let policy_digest = [0x42u8; POLICY_DIGEST_SIZE];
    store.initialize_store(&policy_digest).unwrap();

    // Validate immediately after initialization (same digest must match).
    store.validate_store(&policy_digest).unwrap();
    // Wrong digest must fail.
    assert!(store.validate_store(&[0xFFu8; POLICY_DIGEST_SIZE]).is_err());

    // Empty store: leaf, attestation target, and exported CDI must fail.
    let mut out = DpeHandleRecord::default();
    assert!(store.read_leaf_record(&mut out).is_err());
    assert!(store.read_attestation_target(&mut out).is_err());
    let mut cdi_out = [0xFFu8; EXPORTED_CDI_SIZE];
    assert!(store.read_exported_cdi(0x0001, &mut cdi_out).is_err());
    assert!(store
        .read_exported_cdi(EXPORTED_CDI_ANY_FW_ID, &mut cdi_out)
        .is_err());

    // Write a root record (fw_id 0x0001, no parent).
    let root = DpeHandleRecord {
        fw_id: 0x0001,
        parent_fw_id: None,
        context_handle: [0xAAu8; 16],
        tci_tag: 0xDEAD_0001,
        flags: 0,
    };
    store.write_record(root.fw_id, &root).unwrap();

    // Leaf is now the root.
    store.read_leaf_record(&mut out).unwrap();
    assert_eq!(out, root);

    // Write a child record (fw_id 0x0002, parent 0x0001).
    let child = DpeHandleRecord {
        fw_id: 0x0002,
        parent_fw_id: Some(0x0001),
        context_handle: [0xBBu8; 16],
        tci_tag: 0xDEAD_0002,
        flags: 0,
    };
    store.write_record(child.fw_id, &child).unwrap();

    // Leaf is now the child (last appended).
    store.read_leaf_record(&mut out).unwrap();
    assert_eq!(out, child);

    // Read root back by fw_id.
    store.read_record(root.fw_id, &mut out).unwrap();
    assert_eq!(out, root);

    // Upsert: overwrite child with updated context_handle.
    let child_v2 = DpeHandleRecord {
        context_handle: [0xCCu8; 16],
        ..child
    };
    store.write_record(child_v2.fw_id, &child_v2).unwrap();
    store.read_record(child_v2.fw_id, &mut out).unwrap();
    assert_eq!(out.context_handle, [0xCCu8; 16]);

    // Non-existent fw_id must fail.
    assert!(store.read_record(0xDEAD_BEEF, &mut out).is_err());

    // Mark child as attestation target.
    store.mark_attestation_target(child_v2.fw_id).unwrap();
    // Non-existent target must fail.
    assert!(store.mark_attestation_target(0xDEAD_BEEF).is_err());

    // Read attestation target.
    store.read_attestation_target(&mut out).unwrap();
    assert_eq!(out.fw_id, child_v2.fw_id);
    assert_eq!(out.context_handle, [0xCCu8; 16]);

    // validate_store still succeeds (state is consistent).
    store.validate_store(&policy_digest).unwrap();

    // Exported CDI validation: all-zero handle and unknown fw_id must fail.
    assert!(store
        .write_exported_cdi(child_v2.fw_id, &[0u8; EXPORTED_CDI_SIZE])
        .is_err());
    let test_cdi = [0x55u8; EXPORTED_CDI_SIZE];
    assert!(store.write_exported_cdi(0xDEAD_BEEF, &test_cdi).is_err());

    // Write and read exported CDI for child_v2.
    store.write_exported_cdi(child_v2.fw_id, &test_cdi).unwrap();
    store
        .read_exported_cdi(child_v2.fw_id, &mut cdi_out)
        .unwrap();
    assert_eq!(cdi_out, test_cdi);
    cdi_out = [0u8; EXPORTED_CDI_SIZE];
    store
        .read_exported_cdi(EXPORTED_CDI_ANY_FW_ID, &mut cdi_out)
        .unwrap();
    assert_eq!(cdi_out, test_cdi);
    assert!(store.read_exported_cdi(root.fw_id, &mut cdi_out).is_err());

    // Updating the same fw_id in place must succeed.
    let updated_cdi = [0x66u8; EXPORTED_CDI_SIZE];
    store
        .write_exported_cdi(child_v2.fw_id, &updated_cdi)
        .unwrap();
    store
        .read_exported_cdi(child_v2.fw_id, &mut cdi_out)
        .unwrap();
    assert_eq!(cdi_out, updated_cdi);

    // Writing a second distinct fw_id when exported_cdi_capacity == 1 must fail.
    assert!(store.write_exported_cdi(root.fw_id, &test_cdi).is_err());

    // validate_store succeeds with active exported CDI slot.
    store.validate_store(&policy_digest).unwrap();

    // Clearing the slot frees capacity for another fw_id.
    assert!(store.clear_exported_cdi(root.fw_id).is_err());
    store.clear_exported_cdi(child_v2.fw_id).unwrap();
    assert!(store
        .read_exported_cdi(child_v2.fw_id, &mut cdi_out)
        .is_err());
    store.write_exported_cdi(root.fw_id, &test_cdi).unwrap();
    store.read_exported_cdi(root.fw_id, &mut cdi_out).unwrap();
    assert_eq!(cdi_out, test_cdi);

    // Re-initialize clears everything.
    let new_digest = [0x11u8; POLICY_DIGEST_SIZE];
    store.initialize_store(&new_digest).unwrap();
    assert!(store.read_leaf_record(&mut out).is_err());
    assert!(store.read_attestation_target(&mut out).is_err());
    assert!(store.read_record(root.fw_id, &mut out).is_err());
    // Old digest no longer matches.
    assert!(store.validate_store(&policy_digest).is_err());
    store.validate_store(&new_digest).unwrap();

    // Exported CDI slots must be cleared after re-initialization.
    assert!(store.read_exported_cdi(root.fw_id, &mut cdi_out).is_err());
    assert!(store
        .read_exported_cdi(EXPORTED_CDI_ANY_FW_ID, &mut cdi_out)
        .is_err());
}
