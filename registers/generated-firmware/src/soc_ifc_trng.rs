// Licensed under the Apache-2.0 license.
//
// generated by registers_generator with caliptra-rtl repo at 0e43b8e7011c1c8761e114bc949fcad6cf30538e
// , caliptra-ss repo at 9911c2b0e4bac9e4b48f6c2155c86cb116159734
// , and i3c-core repo at d5c715103f529ade0e5d375a53c5692daaa9c54b
//
pub mod bits {
    //! Types that represent individual registers (bitfields).
    use tock_registers::register_bitfields;
    register_bitfields! {
        u32,
            pub CptraTrngStatus [
                /// Indicates that there is a request for TRNG Data.
                /// [br]Caliptra Access: RW
                /// [br]SOC Access:      RO
                DataReq OFFSET(0) NUMBITS(1) [],
                /// Indicates that the requests TRNG Data is done and stored in the TRNG Data register.
                /// [br]Caliptra Access: RO
                /// [br]SOC Access:      RW
                /// [br]When DATA_REQ is 0 DATA_WR_DONE will also be 0
                DataWrDone OFFSET(1) NUMBITS(1) [],
            ],
    }
}
pub mod regs {
    //! Types that represent registers.
    use tock_registers::register_structs;
    register_structs! {
        pub SocIfcTrng {
            (0x0 => _reserved0),
            (0x78 => pub cptra_trng_data: [tock_registers::registers::ReadOnly<u32>; 12]),
            (0xa8 => _reserved1),
            (0xac => pub cptra_trng_status: tock_registers::registers::ReadOnly<u32, crate::soc_ifc_trng::bits::CptraTrngStatus::Register>),
            (0xb0 => @END),
        }
    }
}
