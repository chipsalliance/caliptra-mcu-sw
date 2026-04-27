// Licensed under the Apache-2.0 license

use user_app_common::image_loader::NoExtraSteps;
use user_app_common::IDENTITY_DMA_MAPPING;

#[embassy_executor::task]
pub async fn image_loading_task() {
    let spawner = crate::EXECUTOR.get().spawner();
    user_app_common::image_loader::image_loading_task_body(
        &IDENTITY_DMA_MAPPING,
        spawner,
        NoExtraSteps,
    )
    .await;
}
