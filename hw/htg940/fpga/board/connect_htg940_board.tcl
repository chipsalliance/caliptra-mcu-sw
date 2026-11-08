# Sourced while caliptra_htg940_bd is open, before validate_bd_design.
foreach {port pin} {
    board_core_clk htg940_clocks/clk_out1
    board_reset_n proc_sys_reset_0/peripheral_aresetn
    board_clock_locked htg940_clocks/locked
} {
    if {[llength [get_bd_ports -quiet $port]]} {error "Duplicate board port: $port"}
    set endpoint [get_bd_pins -quiet $pin]
    if {[llength $endpoint] != 1} {error "Missing board connection: $pin"}
    create_bd_port -dir O $port
    connect_bd_net [get_bd_ports $port] $endpoint
}
set boardTop [file join $fpgaDir board htg940_board_top.sv]
add_files -norecurse $boardTop
set_property file_type SystemVerilog [get_files $boardTop]

# HTG940_ENTROPY_CONTROL_V1
# HTG940_PACKAGING_FIX_V1
# Reset AND gate now lives in board RTL; typed BD input preserves polarity.
create_bd_port -dir I -type rst subsystem_reset_n
set_property CONFIG.POLARITY ACTIVE_LOW [get_bd_ports subsystem_reset_n]
set resetPin [get_bd_pins proc_sys_reset_0/ext_reset_in]
set resetNet [get_bd_nets -of_objects $resetPin]
if {[llength $resetNet] != 1} {error "Cannot resolve subsystem reset net"}
disconnect_bd_net $resetNet $resetPin
connect_bd_net [get_bd_ports subsystem_reset_n] $resetPin

create_bd_port -dir I -from 3 -to 0 host_entropy_data
create_bd_port -dir I host_entropy_valid
create_bd_port -dir O host_entropy_req
foreach {port pin} {
    host_entropy_data board_entropy_data
    host_entropy_valid board_entropy_valid
    host_entropy_req board_entropy_req
} {
    set ep [get_bd_pins -quiet caliptra_package_top_0/$pin]
    if {[llength $ep]!=1} {error "Missing packaged entropy port: $pin"}
    connect_bd_net [get_bd_ports $port] $ep
}
foreach filename {htg940_entropy_control.sv htg940_entropy_uart.sv} {
    add_files -norecurse [file join $fpgaDir board $filename]
}

# HTG940_UART_LOGS_V1
foreach port {board_mcu_log_valid board_core_log_valid} {
    create_bd_port -dir O $port
    connect_bd_net [get_bd_ports $port] [get_bd_pins caliptra_package_top_0/$port]
}
foreach port {board_mcu_log_byte board_core_log_byte} {
    create_bd_port -dir O -from 7 -to 0 $port
    connect_bd_net [get_bd_ports $port] [get_bd_pins caliptra_package_top_0/$port]
}
add_files -norecurse [file join $fpgaDir board htg940_log_bridge.sv]
