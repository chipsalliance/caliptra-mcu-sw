
set adbDir $ssrtlDir/third_party/caliptra-rtl/submodules/adams-bridge

if { [file exists $adbDir/src/abr_prim/rtl/abr_prim_flop_macros.sv] == 0 } {
    puts "ERROR: $adbDir/src/abr_prim/rtl/abr_prim_flop_macros.sv not found"
    puts "Adam's bridge submodule may not be initialized"
    puts "Try: git submodule update --init --recursive"
    exit
}

add_files $adbDir/src/abr_prim/rtl/abr_prim_flop_macros.sv

# Initial list from abr_top_tb.vf
add_files $adbDir/src/abr_top/rtl/abr_config_defines.svh
add_files $adbDir/src/abr_top/rtl/abr_params_pkg.sv
add_files $adbDir/src/abr_top/rtl/abr_reg_pkg.sv

add_files $adbDir/src/abr_libs/rtl/abr_sva.svh
add_files $adbDir/src/abr_libs/rtl/abr_macros.svh

add_files [ glob $adbDir/src/abr_libs/rtl/*.sv ]

add_files $adbDir/src/abr_sampler_top/rtl/abr_sampler_pkg.sv
add_files $adbDir/src/sample_in_ball/rtl/sample_in_ball_pkg.sv
add_files $adbDir/src/sample_in_ball/rtl/sib_mem.sv

add_files [ glob $adbDir/src/abr_prim/rtl/*.sv ]
add_files [ glob $adbDir/src/abr_prim/rtl/*.svh ]

add_files [ glob $adbDir/src/ntt_top/rtl/*.sv ]
add_files $adbDir/src/ntt_top/tb/ntt_ram_tdp_file.sv
add_files $adbDir/src/ntt_top/tb/ntt_wrapper.sv

add_files [ glob $adbDir/src/*/rtl/*.sv ]
add_files [ glob $adbDir/src/abr_top/rtl/*.sv ]
