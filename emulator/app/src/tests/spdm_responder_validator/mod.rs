// Licensed under the Apache-2.0 license

mod common;
pub mod doe;
pub mod mctp;
mod transport;

pub enum SpdmTestType {
    SpdmResponderConformance,
    SpdmTeeIoValidator,
}
