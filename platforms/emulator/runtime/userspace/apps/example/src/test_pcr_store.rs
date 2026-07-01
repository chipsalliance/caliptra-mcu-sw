// Licensed under the Apache-2.0 license

// NOTE: Do not call `caliptra_mcu_romtime::println!` from this test. On the
// emulator the printer is wired to a UART MMIO register at 0x1000_1041; on
// the FPGA that address is unmapped and forbidden by user-mode PMP, so any
// `println!` here would fault the test process on real hardware.

use caliptra_mcu_libsyscall_caliptra::pcr_store::{
    PcrStore, PCR_COUNT, PCR_MEASUREMENT_SIZE, PCR_STORE_DRIVER_NUM,
};
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;

pub(crate) async fn test_pcr_store() {
    let store = PcrStore::<DefaultSyscalls>::new(PCR_STORE_DRIVER_NUM);

    // Capsule must be present.
    store.exists().unwrap();

    // Start from a clean slate.
    store.clear_measurements().unwrap();

    // Reading any PCR from an empty store must fail.
    let mut out = [0u8; PCR_MEASUREMENT_SIZE];
    assert!(store.read_measurement(0, &mut out).is_err());
    assert!(store
        .read_measurement(PCR_COUNT as u32 - 1, &mut out)
        .is_err());

    // Out-of-range index must fail on read and write.
    assert!(store.read_measurement(PCR_COUNT as u32, &mut out).is_err());
    assert!(store
        .write_measurement(PCR_COUNT as u32, &[0u8; PCR_MEASUREMENT_SIZE])
        .is_err());

    // Write PCR 0 and read it back.
    let measurement_0 = [0x11u8; PCR_MEASUREMENT_SIZE];
    store.write_measurement(0, &measurement_0).unwrap();

    store.read_measurement(0, &mut out).unwrap();
    assert_eq!(out, measurement_0);

    // PCR 1 is still unset.
    assert!(store.read_measurement(1, &mut out).is_err());

    // Write PCR 1 and read it back.
    let measurement_1 = [0x22u8; PCR_MEASUREMENT_SIZE];
    store.write_measurement(1, &measurement_1).unwrap();

    store.read_measurement(1, &mut out).unwrap();
    assert_eq!(out, measurement_1);

    // PCR 0 should still hold its original value.
    store.read_measurement(0, &mut out).unwrap();
    assert_eq!(out, measurement_0);

    // Overwrite PCR 0 directly.
    let measurement_0_v2 = [0x33u8; PCR_MEASUREMENT_SIZE];
    store.write_measurement(0, &measurement_0_v2).unwrap();
    store.read_measurement(0, &mut out).unwrap();
    assert_eq!(out, measurement_0_v2);

    // Extend PCR 0: SHA-384(current_value || extend_data).
    // The resulting hash must differ from the pre-extend value.
    let extend_data = [0xABu8; 32];
    store.extend_measurement(0, &extend_data).await.unwrap();
    store.read_measurement(0, &mut out).unwrap();
    // After extension the value must have changed.
    assert_ne!(out, measurement_0_v2);
    // The result must be a valid non-zero 48-byte value.
    assert!(out.iter().any(|&b| b != 0));

    // Extending PCR 1 with empty data (SHA-384(current || "")) must succeed.
    store.extend_measurement(1, &[]).await.unwrap();
    store.read_measurement(1, &mut out).unwrap();
    assert_ne!(out, measurement_1);

    // Write PCR 31 (last valid index) and clear everything.
    let measurement_31 = [0xFFu8; PCR_MEASUREMENT_SIZE];
    store.write_measurement(31, &measurement_31).unwrap();
    store.read_measurement(31, &mut out).unwrap();
    assert_eq!(out, measurement_31);

    // clear_measurements zeros everything.
    store.clear_measurements().unwrap();
    assert!(store.read_measurement(0, &mut out).is_err());
    assert!(store.read_measurement(1, &mut out).is_err());
    assert!(store.read_measurement(31, &mut out).is_err());
}
