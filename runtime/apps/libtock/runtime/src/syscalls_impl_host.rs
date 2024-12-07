use libtock_platform::{RawSyscalls, Register};

// These are fake syscalls just to make the compilation happy.
unsafe impl RawSyscalls for crate::TockSyscalls {
    #[cfg(not(any(target_feature = "d", target_feature = "f")))]
    unsafe fn yield1([Register(_r0)]: [Register; 1]) {}

    #[cfg(not(any(target_feature = "d", target_feature = "f")))]
    unsafe fn yield2([Register(_r0), Register(_r1)]: [Register; 2]) {}

    unsafe fn syscall1<const CLASS: usize>([Register(r0)]: [Register; 1]) -> [Register; 2] {
        [Register(r0), Register(r0)]
    }

    unsafe fn syscall2<const CLASS: usize>(
        [Register(r0), Register(r1)]: [Register; 2],
    ) -> [Register; 2] {
        [Register(r0), Register(r1)]
    }

    unsafe fn syscall4<const CLASS: usize>(
        [Register(r0), Register(r1), Register(r2), Register(r3)]: [Register; 4],
    ) -> [Register; 4] {
        [Register(r0), Register(r1), Register(r2), Register(r3)]
    }
}
