// Licensed under the Apache-2.0 license

//! Request-scoped FE configuration metadata for the HW evidence class.

use core::future::Future;
use mcu_caliptra_api::FwInfo;
use mcu_error::McuResult;

include!(concat!(env!("OUT_DIR"), "/hardware_class_config.rs"));

pub(crate) async fn collect_fe_status(
    enabled: bool,
    query: impl Future<Output = McuResult<FwInfo>>,
) -> Option<[u8; FE_STATUS_RAW_VALUE_SIZE]> {
    if !enabled {
        return None;
    }

    let mut value = [1, 0, 0xff, 0xff, 0xff, 0xff];
    if let Ok(info) = query.await {
        value[1] = 1;
        for partition in 0..4 {
            value[2 + partition] = ((info.fe_status >> (partition * 2)) & 3) as u8;
        }
    }
    Some(value)
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
    fn disabled_claim_does_not_poll_core_query() {
        let value = ready(collect_fe_status(false, async {
            panic!("disabled FE claim queried Core");
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
            let value = ready(collect_fe_status(true, async {
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
        let value = ready(collect_fe_status(
            true,
            core::future::ready(Err(mcu_error::codes::INVARIANT)),
        ));
        assert_eq!(value, Some([1, 0, 0xff, 0xff, 0xff, 0xff]));
        let blank = ready(collect_fe_status(
            true,
            core::future::ready(Ok(FwInfo {
                fe_status: 0,
                ..Default::default()
            })),
        ));
        assert_eq!(blank, Some([1, 1, 0, 0, 0, 0]));
    }
}
