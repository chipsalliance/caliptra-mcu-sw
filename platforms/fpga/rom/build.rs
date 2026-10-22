// Licensed under the Apache-2.0 license

use chrono::{DateTime, SecondsFormat, Utc};
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
    // A missing path forces a rerun so the logged build time matches each ROM build.
    println!("cargo:rerun-if-changed=.always-rebuild-timestamp");

    let unix_seconds = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock is before the Unix epoch")
                .as_secs() as i64
        });
    let timestamp = DateTime::<Utc>::from_timestamp(unix_seconds, 0)
        .expect("build timestamp is outside chrono's supported range")
        .to_rfc3339_opts(SecondsFormat::Secs, true);

    println!("cargo:rustc-env=MCU_ROM_BUILD_TIMESTAMP={timestamp}");
}
