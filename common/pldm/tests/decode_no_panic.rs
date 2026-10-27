// Licensed under the Apache-2.0 license

//! Every hand-written decoder takes bytes from a peer, so it must return an
//! error on bad input instead of panicking. Each one is fed all-zero, all-0xFF
//! and pseudo-random buffers, plus zeros with one large byte at each offset so
//! that every length field gets a turn at being too big. The inputs are
//! deterministic, so a failure always reproduces.
//!
//! Types decoded through the zerocopy blanket impl cannot index past their
//! input and are not listed. Add any new hand-written decoder here.

use caliptra_mcu_pldm_common::codec::PldmCodec;
use caliptra_mcu_pldm_common::message::firmware_update::{
    get_fw_params, pass_component, query_devid, request_update, update_component,
};
use caliptra_mcu_pldm_common::protocol::firmware_update;

const LENGTHS: [usize; 18] = [
    0, 1, 2, 3, 4, 5, 8, 12, 16, 24, 32, 48, 64, 100, 128, 256, 600, 1200,
];

fn inputs() -> Vec<Vec<u8>> {
    let mut seed: u64 = 0x1234_5678;
    let mut next = move || {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (seed >> 33) as u8
    };

    let mut all = Vec::new();
    for len in LENGTHS {
        all.push(vec![0u8; len]);
        all.push(vec![0xFFu8; len]);
        for _ in 0..20 {
            all.push((0..len).map(|_| next()).collect());
        }
        for i in 0..len.min(96) {
            for byte in [0xFF, 0x80, 65, 33, 9] {
                let mut buf = vec![0u8; len];
                buf[i] = byte;
                all.push(buf);
            }
        }
    }
    all
}

fn check<T: PldmCodec>(name: &str) {
    for input in inputs() {
        let result = std::panic::catch_unwind(|| {
            let _ = T::decode(&input);
        });
        assert!(
            result.is_ok(),
            "{name}::decode panicked on {} bytes starting {:02x?}",
            input.len(),
            &input[..input.len().min(16)]
        );
    }
}

macro_rules! no_panic {
    ($test:ident, $ty:ty) => {
        #[test]
        fn $test() {
            check::<$ty>(stringify!($ty));
        }
    };
}

no_panic!(descriptor, firmware_update::Descriptor);
no_panic!(
    component_parameter_entry,
    firmware_update::ComponentParameterEntry
);
no_panic!(firmware_parameters, get_fw_params::FirmwareParameters);
no_panic!(
    get_fw_params_response,
    get_fw_params::GetFirmwareParametersResponse
);
no_panic!(
    pass_component_request,
    pass_component::PassComponentTableRequest
);
no_panic!(
    query_devid_response,
    query_devid::QueryDeviceIdentifiersResponse
);
no_panic!(request_update_request, request_update::RequestUpdateRequest);
no_panic!(
    request_update_response,
    request_update::RequestUpdateResponse
);
no_panic!(
    update_component_request,
    update_component::UpdateComponentRequest
);
no_panic!(
    update_component_response,
    update_component::UpdateComponentResponse
);
