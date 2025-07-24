# Running with an FPGA

## UDS Provisioning

### Preliminaries

1. Build OpenOCD 0.12.0 with `--enable-sysfsgpio`.
2. Install gdb-multiarch
3. Run a ROM flow with a blank OTP memory to transition the lifecycle state to `TestUnlocked0`.
4. Run a ROM to burn lifecycle tokens for the other transitions.
5. Run a ROM flow to transition the lifecycle state to `Dev` (this maps to the Manufacturing device lifecycle for Caliptra).
6. Start a run with the bootfsm_break set to 1.
7. Start the OpenOCD server:

```
sudo openocd --file openocd_caliptra.txt
```

8. Connect to OpenOCD

```
telnet localhost 4444
```

9. Verify connectivity in telnet:

```
> riscv.cpu riscv dmi_read 0x74
0xcccccccc
```

10. Write the request
```
> riscv.cpu riscv dmi_write 0x70 4
> riscv.cpu riscv dmi_write 0x61 1
```
