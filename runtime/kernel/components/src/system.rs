// Licensed under the Apache-2.0 license

// Component for System driver.

use core::mem::MaybeUninit;
use kernel::component::Component;

pub struct SystemComponent<E: caliptra_mcu_romtime::Exit + 'static> {
    exiter: &'static mut E,
}

impl<E: caliptra_mcu_romtime::Exit> SystemComponent<E> {
    pub fn new(exiter: &'static mut E) -> Self {
        Self { exiter }
    }
}

impl<E: caliptra_mcu_romtime::Exit> Component for SystemComponent<E> {
    type StaticInput =
        &'static mut MaybeUninit<caliptra_mcu_capsules_runtime::system::System<'static, E>>;
    type Output = &'static caliptra_mcu_capsules_runtime::system::System<'static, E>;

    fn finalize(self, static_buffer: Self::StaticInput) -> Self::Output {
        let system: &caliptra_mcu_capsules_runtime::system::System<'static, E> = static_buffer
            .write(caliptra_mcu_capsules_runtime::system::System::new(
                self.exiter,
            ));
        system
    }
}
