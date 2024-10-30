# Runtime Specification

The runtime (or "firmware") uses Tock as the kernel. Any RISC-V code that needs to run in M-mode, e.g., low-level drivers, should run in the Tock board or a capsule loaded by the board.

In Tock, the "board" is the code that runs that does all of the hardware initialization and starts the Tock kernel. The Tock board is essentially a custom a kernel for each SoC.

The applications are higher-level RISC-V code that only interact with the rest of the world through Tock system calls. For instance, an app might be responsible for running a PLDM flow and uses a Tock capsule to interact with the MCTP stack to communicate with the rest of the SoC.

The Tock kernel allows us to run multiple applications at the same time.
