
1. Solder a header to pins L05-L02 of J1 of the FMC-XM119-PMOD board packaged with the Versal FPGA.
2. Ensure the jumper for EN1/J3 is bridging the sense pin to GND.
3. Install the FMC card to FMCP1/J51. Labeled (20) in the VCK190 User Guide.
4. Install the I3C driver board on top of the FMC board. The connections are L05-L02 of J1, and 3.3V and GND of PMOD1.

Common issues:
- SCL pad voltage between 0 or 1.5V may indicate a misfunctioning level shifter.

