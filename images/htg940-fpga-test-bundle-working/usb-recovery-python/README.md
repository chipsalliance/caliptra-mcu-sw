# USB Recovery Agent for Python

This application performs OCP Secure Firmware Recovery over USB using PyUSB.
It is the Python equivalent of the Rust `caliptra-mcu-usb-recovery` application:
it claims USB interface 0, follows the device's requested image order, and
streams each image through the indirect FIFO CMS in control transfers of at
most 64 bytes.

The recovery images are Caliptra FMC/runtime (index 0), the SoC manifest
(index 1), and MCU runtime (index 2).

## Windows prerequisites

1. Install 64-bit Python 3.10 or newer from
   [python.org](https://www.python.org/downloads/windows/). Enable **Add Python
   to PATH** during installation.
2. Download [Zadig](https://zadig.akeo.ie/) and run it as Administrator.
3. In Zadig, select **Options > List All Devices**.
4. Select the recovery interface. It may appear as **OCP Secure Firmware
  Recovery**, an unknown USB device, or its USB ID `0424:0007`.
5. Confirm that the selected device has vendor ID `0424` and product ID `0007`,
   select **WinUSB**, and choose **Install Driver** or **Replace Driver**.

Be careful to select the recovery device before replacing a driver. Choosing a
keyboard, mouse, or another system device in Zadig can make that device
temporarily unusable.

The application uses `libusb-package`, installed from `requirements.txt`, to
provide the native libusb DLL required by PyUSB. WSL and `usbipd` are not
required.

## Setup

Open PowerShell in this directory, then create a local virtual environment and
install the dependencies:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If PowerShell blocks the activation script, allow it for the current PowerShell
process and activate again:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

After plugging in the device, confirm that PyUSB can find it:

```powershell
python -c "import libusb_package; print([f'{d.idVendor:04x}:{d.idProduct:04x}' for d in libusb_package.find(find_all=True)])"
```

The output should include `0424:0007`.

## Probe OCP registers

Read the OCP protocol capability and status registers without starting recovery
or writing any device state:

```powershell
python .\usb_recovery.py --probe
```

A working FPGA OCP register aperture reports the `OCP RECV` capability magic,
protocol version, capability bitmap, device status, and recovery status.

## Run

### GUI

The GUI starts the HTG-940 console on `COM8`, separates MCU and Caliptra logs,
and automatically starts USB recovery when the MCU requests firmware:

```powershell
python .\usb_recovery_gui.py
```

Use the serial-port field to select another COM port. The console and recovery
processes use the same Python interpreter that starts the GUI, so install all
packages from `requirements.txt` into that environment.

### Command line

```powershell
python .\usb_recovery.py `
  --caliptra-fmc-rt "C:\path\to\caliptra-fmc-rt.bin" `
  --soc-manifest "C:\path\to\soc-manifest.bin" `
  --mcu-runtime "C:\path\to\mcu-runtime.bin"
```

The default USB ID is `0424:0007`. Override it when needed:

```powershell
python .\usb_recovery.py `
  --vendor-id 0x0424 `
  --product-id 0x0007 `
  --caliptra-fmc-rt "C:\path\to\caliptra-fmc-rt.bin" `
  --soc-manifest "C:\path\to\soc-manifest.bin" `
  --mcu-runtime "C:\path\to\mcu-runtime.bin"
```

If the application reports that the device was not found, verify its hardware
ID in Device Manager and rerun the PyUSB discovery command above. If claiming
the interface fails, use Zadig to confirm that **WinUSB** is bound to the
`0424:0007` recovery interface.

## Test

The unit tests use a mock USB transport and do not require hardware:

```powershell
python -m unittest -v
```
