// Licensed under the Apache-2.0 license

// NOTE: Do not call `caliptra_mcu_romtime::println!` from this test.

use caliptra_mcu_libsyscall_caliptra::dpe_handle_store::{
    DpeHandleRecord, DpeHandleStore, DPE_HANDLE_STORE_DRIVER_NUM, POLICY_DIGEST_SIZE,
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

    // Empty store: leaf and attestation target must fail.
    let mut out = DpeHandleRecord::default();
    assert!(store.read_leaf_record(&mut out).is_err());
    assert!(store.read_attestation_target(&mut out).is_err());

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

    // Re-initialize clears everything.
    let new_digest = [0x11u8; POLICY_DIGEST_SIZE];
    store.initialize_store(&new_digest).unwrap();
    assert!(store.read_leaf_record(&mut out).is_err());
    assert!(store.read_attestation_target(&mut out).is_err());
    assert!(store.read_record(root.fw_id, &mut out).is_err());
    // Old digest no longer matches.
    assert!(store.validate_store(&policy_digest).is_err());
    store.validate_store(&new_digest).unwrap();
}
