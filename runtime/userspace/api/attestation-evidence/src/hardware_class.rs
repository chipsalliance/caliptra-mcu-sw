// Licensed under the Apache-2.0 license

//! Request-scoped hardware configuration metadata.

use core::future::Future;
use mcu_caliptra_api::FwInfo;
use mcu_error::McuResult;

include!(concat!(env!("OUT_DIR"), "/hardware_class_config.rs"));

struct FeStatusRawValue {
    schema_version: u8,
    available: bool,
    partition_status: [u8; 4],
}

impl FeStatusRawValue {
    fn into_bytes(self) -> [u8; FE_STATUS_RAW_VALUE_SIZE] {
        [
            self.schema_version,
            u8::from(self.available),
            self.partition_status[0],
            self.partition_status[1],
            self.partition_status[2],
            self.partition_status[3],
        ]
    }
}

pub(crate) async fn collect_hardware_config(
    enabled: bool,
    query: impl Future<Output = McuResult<FwInfo>>,
) -> Option<[u8; FE_STATUS_RAW_VALUE_SIZE]> {
    if !enabled {
        return None;
    }

    let mut value = FeStatusRawValue {
        schema_version: 1,
        available: false,
        partition_status: [0xff; 4],
    };
    if let Ok(info) = query.await {
        value.available = true;
        for (partition, status) in value.partition_status.iter_mut().enumerate() {
            *status = ((info.fe_status >> (partition * 2)) & 3) as u8;
        }
    }
    Some(value.into_bytes())
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::cell::Cell;
    use core::task::{Context, Poll, Waker};

    fn ready<T>(future: impl Future<Output = T>) -> T {
        let mut future = core::pin::pin!(future);
        match future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("test query did not complete"),
        }
    }

    #[test]
    fn disabled_hardware_class_does_not_poll_core_query() {
        let value = ready(collect_hardware_config(false, async {
            panic!("disabled hardware class queried Core");
        }));
        assert_eq!(value, None);
    }

    #[test]
    fn each_request_collects_one_fresh_snapshot_and_preserves_core_error_status() {
        let queries = Cell::new(0);
        for (status, expected) in [
            (0xffff_ffe4, [1, 1, 0, 1, 2, 3]),
            (0x55, [1, 1, 1, 1, 1, 1]),
        ] {
            let value = ready(collect_hardware_config(true, async {
                queries.set(queries.get() + 1);
                Ok(FwInfo {
                    fe_status: status,
                    ..Default::default()
                })
            }));
            assert_eq!(value, Some(expected));
        }
        assert_eq!(queries.get(), 2);
    }

    #[test]
    fn failed_metadata_query_is_unavailable_not_unprovisioned() {
        let value = ready(collect_hardware_config(
            true,
            core::future::ready(Err(mcu_error::codes::INVARIANT)),
        ));
        assert_eq!(value, Some([1, 0, 0xff, 0xff, 0xff, 0xff]));
        let blank = ready(collect_hardware_config(
            true,
            core::future::ready(Ok(FwInfo {
                fe_status: 0,
                ..Default::default()
            })),
        ));
        assert_eq!(blank, Some([1, 1, 0, 0, 0, 0]));
    }
}
