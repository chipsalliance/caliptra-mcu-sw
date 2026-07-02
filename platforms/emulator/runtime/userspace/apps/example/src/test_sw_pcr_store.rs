// Licensed under the Apache-2.0 license

// NOTE: Do not call `caliptra_mcu_romtime::println!` from this test. On the
// emulator the printer is wired to a UART MMIO register; on the FPGA that
// address is unmapped and forbidden by user-mode PMP, so any `println!` here
// would fault the test process on real hardware.

use caliptra_mcu_libsyscall_caliptra::soft_pcr_store::{
    MeasurementRecord, SoftwarePcrStore, SOFT_PCR_STORE_DRIVER_NUM,
};
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;

pub(crate) fn test_sw_pcr_store() {
    let store = SoftwarePcrStore::<DefaultSyscalls>::new(SOFT_PCR_STORE_DRIVER_NUM);

    // Capsule must be present.
    store.exists().unwrap();

    // Cold-boot initialization.
    store.initialize_store().unwrap();

    // VALIDATE_STORE must pass right after initialization.
    store.validate_store().unwrap();

    // Reading a non-existent fw_id must fail.
    let mut out = MeasurementRecord::default();
    assert!(store.read_measurement(0x1000, &mut out).is_err());

    // CREATE_MEASUREMENT for fw_id=0x1001.
    let rec1 = MeasurementRecord {
        fw_id: 0x1001,
        current_digest: [0x11u8; 48],
        journey_digest: [0x22u8; 48],
        svn: 1,
        version: 0x0100,
        reserved: [0u8; 4],
    };
    store.create_measurement(0x1001, &rec1).unwrap();

    // CREATE again for the same fw_id must fail (already exists).
    assert!(store.create_measurement(0x1001, &rec1).is_err());

    // READ back and verify.
    store.read_measurement(0x1001, &mut out).unwrap();
    assert_eq!(out.fw_id, 0x1001);
    assert_eq!(out.current_digest, rec1.current_digest);
    assert_eq!(out.journey_digest, rec1.journey_digest);
    assert_eq!(out.svn, 1);

    // UPDATE_MEASUREMENT for a non-existent fw_id must fail.
    assert!(store.update_measurement(0xDEAD, &rec1).is_err());

    // CREATE a second record for fw_id=0x1002.
    let rec2 = MeasurementRecord {
        fw_id: 0x1002,
        current_digest: [0xAAu8; 48],
        journey_digest: [0xBBu8; 48],
        svn: 2,
        version: 0x0200,
        reserved: [0u8; 4],
    };
    store.create_measurement(0x1002, &rec2).unwrap();

    // UPDATE fw_id=0x1001 with new digests.
    let rec1_v2 = MeasurementRecord {
        fw_id: 0x1001,
        current_digest: [0x33u8; 48],
        journey_digest: [0x44u8; 48],
        svn: 1,
        version: 0x0101,
        reserved: [0u8; 4],
    };
    store.update_measurement(0x1001, &rec1_v2).unwrap();

    // READ back updated record.
    store.read_measurement(0x1001, &mut out).unwrap();
    assert_eq!(out.current_digest, rec1_v2.current_digest);
    assert_eq!(out.journey_digest, rec1_v2.journey_digest);
    assert_eq!(out.version, 0x0101);

    // fw_id=0x1002 is unchanged.
    store.read_measurement(0x1002, &mut out).unwrap();
    assert_eq!(out.current_digest, rec2.current_digest);

    // VALIDATE_STORE still passes.
    store.validate_store().unwrap();

    // Re-initialize and validate again (simulates hitless-update cold-boot path).
    store.initialize_store().unwrap();
    store.validate_store().unwrap();

    // After re-initialization all records are gone.
    assert!(store.read_measurement(0x1001, &mut out).is_err());
    assert!(store.read_measurement(0x1002, &mut out).is_err());
}
