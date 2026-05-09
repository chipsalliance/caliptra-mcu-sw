// Licensed under the Apache-2.0 license

// Component for System driver.

use core::mem::MaybeUninit;
use kernel::component::Component;

pub struct SystemComponent<E: romtime::Exit + 'static> {
    exiter: &'static mut E,
}

impl<E: romtime::Exit> SystemComponent<E> {
    pub fn new(exiter: &'static mut E) -> Self {
        Self { exiter }
    }
}

impl<E: romtime::Exit> Component for SystemComponent<E> {
    type StaticInput = &'static mut MaybeUninit<capsules_runtime::system::System<'static, E>>;
    type Output = &'static capsules_runtime::system::System<'static, E>;

    fn finalize(self, static_buffer: Self::StaticInput) -> Self::Output {
        let system: &capsules_runtime::system::System<'static, E> =
            static_buffer.write(capsules_runtime::system::System::new(self.exiter));
        system
    }
}
