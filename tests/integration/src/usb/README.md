# USB/IP Integration Test Architecture

This directory contains a minimal USB/IP device server and three integration tests. Together, the tests verify the USB/IP protocol directly, through the Linux USB stack, and end-to-end through the Caliptra hardware model and OCP Recovery firmware.

`TestDevice` remains useful for isolated transport tests. `HwModelUsbDevice` connects the same USB/IP server to the emulated Caliptra USB peripheral and MCU firmware.

## Components

```mermaid
flowchart LR
    subgraph RustTest["Rust integration test process"]
        direction TB
        UserspaceHost["Userspace test client\nTcpStream"]
        Server["UsbIpServer\nTCP listener"]
        Adapter["UsbIpDevice trait"]
        Device["TestDevice\nUSB endpoint 0"]
        ModelAdapter["HwModelUsbDevice"]
        Model["DefaultHwModel\nMCU USB + OCP firmware"]

        UserspaceHost -->|"USB/IP import and URBs"| Server
        Server -->|"UsbControlRequest"| Adapter
        Adapter --> Device
        Adapter --> ModelAdapter
        ModelAdapter --> Model
    end

    subgraph LinuxHost["Linux kernel test path"]
        UsbIpTool["usbip userspace utility"]
        VHCI["vhci_hcd\nvirtual host controller"]
        UsbCore["Linux USB core\nand enumeration"]
        Sysfs["/sys/bus/usb/devices"]
        Libusb["libusb recovery agent"]

        UsbIpTool -->|"attach / detach"| VHCI
        UsbCore <--> VHCI
        UsbCore --> Sysfs
        Libusb --> UsbCore
    end

    VHCI <-->|"USB/IP over TCP\n127.0.0.1:3240"| Server
```

### `UsbIpServer`

The server implements the device side of the USB/IP 1.1 protocol. It:

- accepts one TCP connection;
- validates an `OP_REQ_IMPORT` request and returns an `OP_REP_IMPORT` device description;
- handles `USBIP_CMD_SUBMIT` requests for endpoint zero;
- translates each control URB into a `UsbControlRequest`;
- returns `USBIP_RET_SUBMIT` with response data or a stall status;
- handles `USBIP_CMD_UNLINK`; and
- exits cleanly when the client disconnects.

USB/IP header integers use big-endian byte order. The embedded eight-byte USB SETUP packet retains USB little-endian fields.

### `TestDevice`

`TestDevice` implements `UsbIpDevice` and provides enough standard control requests for enumeration:

- `GET_DESCRIPTOR` for device, configuration, and string descriptors;
- `SET_ADDRESS`;
- `GET_STATUS`;
- `GET_CONFIGURATION`; and
- `SET_CONFIGURATION`.

Its test identity is vendor ID `0xca5e`, product ID `0x0001`, and bus ID `1-2`.

### `HwModelUsbDevice`

`HwModelUsbDevice` translates each complete USB/IP control URB into USB packet-level operations on `UsbHostController`. It performs the SETUP, data, and status stages, divides OUT data into 64-byte packets, combines IN packets, and retries temporary NAK responses while MCU firmware executes.

## Test 1: Pure Userspace Protocol Test

`usbip_host_controller_talks_to_emulated_device` validates the USB/IP wire protocol without kernel modules or elevated privileges.

```mermaid
sequenceDiagram
    participant Test as Rust test client
    participant TCP as TcpStream
    participant Server as UsbIpServer
    participant Device as TestDevice

    Test->>TCP: Connect to ephemeral loopback port
    TCP->>Server: OP_REQ_IMPORT for bus ID 1-2
    Server-->>TCP: OP_REP_IMPORT and device description

    TCP->>Server: CMD_SUBMIT GET_DESCRIPTOR
    Server->>Device: control(GET_DESCRIPTOR)
    Device-->>Server: 18-byte device descriptor
    Server-->>TCP: RET_SUBMIT and descriptor
    Test->>Test: Verify descriptor bytes

    TCP->>Server: CMD_SUBMIT SET_ADDRESS(7)
    Server->>Device: control(SET_ADDRESS)
    Device-->>Server: Success
    Server-->>TCP: RET_SUBMIT
    Test->>Test: Verify stored address is 7

    Test-xTCP: Close connection
    Server->>Server: Finish after two URBs
```

This test isolates protocol encoding, import handling, control request forwarding, and response decoding from Linux USB behavior.

## Test 2: Linux VHCI Enumeration Test

`usbip_linux_vhci_enumerates_emulated_device` exercises the real Linux USB/IP client, virtual host controller, USB core, and enumeration flow.

```mermaid
sequenceDiagram
    participant Test as Rust test
    participant Server as UsbIpServer
    participant Tool as usbip utility
    participant VHCI as vhci_hcd
    participant Core as Linux USB core
    participant Device as TestDevice
    participant Sysfs as USB sysfs

    Test->>Test: Check passwordless sudo and usbip
    Test->>Tool: sudo modprobe vhci_hcd
    Test->>Server: Start server on 127.0.0.1:3240
    Test->>Tool: sudo usbip attach -r 127.0.0.1 -b 1-2
    Tool->>VHCI: Attach remote device
    VHCI->>Server: OP_REQ_IMPORT
    Server-->>VHCI: Device description

    loop Linux USB enumeration
        Core->>VHCI: Submit endpoint-zero URB
        VHCI->>Server: USBIP_CMD_SUBMIT
        Server->>Device: UsbControlRequest
        Device-->>Server: Descriptor or status response
        Server-->>VHCI: USBIP_RET_SUBMIT
        VHCI-->>Core: Complete URB
    end

    Core->>Device: SET_CONFIGURATION(1)
    Core->>Sysfs: Publish ca5e:0001 device
    Test->>Sysfs: Poll and verify VID/PID
    Test->>Tool: sudo usbip detach -p 0
    Tool->>VHCI: Detach device
    VHCI-xServer: Close TCP connection
    Test->>Test: Verify configuration is 1
```

### Runtime prerequisites

The Linux test requires:

- Linux;
- the `usbip` userspace utility;
- the `vhci_hcd` kernel module; and
- passwordless non-interactive `sudo`.

The test checks these prerequisites at runtime and returns early with a `SKIP:` diagnostic when one is unavailable. Because this is implemented as an early return rather than the Rust test harness's ignored-test mechanism, inspect `--nocapture` output when confirming that the VHCI path actually ran.

## Test 3: libusb OCP Recovery Through the Hardware Model

`usbip_linux_libusb_reads_ocp_recovery_status_from_hwmodel` uses the production-style host path. It boots the hardware model with USB OCP Recovery firmware, imports that device through Linux VHCI, and sends OCP requests with libusb.

```mermaid
sequenceDiagram
    participant Agent as libusb recovery agent
    participant Core as Linux USB core + VHCI
    participant Server as UsbIpServer
    participant Adapter as HwModelUsbDevice
    participant USB as UsbHostController + UsbDevPeriph
    participant FW as MCU USB/OCP firmware

    Core->>Server: Import device and enumerate
    Server->>Adapter: Standard control URBs
    Adapter->>USB: SETUP / IN / OUT packets
    USB->>FW: USB MMIO events
    FW-->>USB: Descriptors and status stages
    USB-->>Adapter: Packet responses
    Adapter-->>Server: Complete control URBs
    Server-->>Core: USB/IP responses

    Agent->>Core: libusb PROT_CAP control read
    Core->>Server: OCP control URB
    Server->>Adapter: UsbControlRequest
    Adapter->>USB: EP0 control transfer
    USB->>FW: OCP PROT_CAP request
    FW-->>Agent: Recovery capabilities

    Agent->>Core: libusb DEVICE_STATUS control read
    Core->>Server: OCP control URB
    Server->>Adapter: UsbControlRequest
    Adapter->>USB: EP0 control transfer
    USB->>FW: OCP DEVICE_STATUS request
    FW-->>Agent: RecoveryMode
```

This test is equivalent in intent to the direct hardware-model `PROT_CAP` and `DEVICE_STATUS` test, but the host requests traverse libusb, the Linux USB core, VHCI, and USB/IP before reaching the model.

## Running the Tests

From the repository root, run the integration-test package with the `usbip` test-name filter and `--nocapture` to show prerequisite diagnostics.

After a failed or interrupted run, detach any remaining imported device with `sudo usbip detach -p 0`. The normal test path performs this detach before joining the server thread.

## Current Boundary and Future Integration

```mermaid
flowchart LR
    Current["USB/IP server"] --> Synthetic["Synthetic TestDevice"]
    Current --> Bridge["HwModelUsbDevice"]
    Bridge --> Host["UsbHostController"]
    Host --> Model["Caliptra DefaultHwModel"]
    Model --> Recovery["USB peripheral and\nOCP Recovery firmware"]

    style Current fill:#d5f5e3,stroke:#1e8449
    style Synthetic fill:#d5f5e3,stroke:#1e8449
    style Bridge fill:#d5f5e3,stroke:#1e8449
    style Host fill:#d5f5e3,stroke:#1e8449
    style Model fill:#d5f5e3,stroke:#1e8449
    style Recovery fill:#d5f5e3,stroke:#1e8449
```

The current end-to-end path covers enumeration and OCP control reads. Future tests can use the same libusb path for OCP writes, image streaming, activation, malformed requests, and recovery behavior. The host recovery-agent code remains unchanged when USB/IP is replaced by a physical Caliptra device.
