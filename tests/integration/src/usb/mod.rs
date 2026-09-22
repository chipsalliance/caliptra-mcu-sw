// Licensed under the Apache-2.0 license

//! USB/IP integration tests.
//!
//! The tests cover the USB/IP wire protocol directly and through Linux
//! `vhci_hcd`. The hardware-model test also drives OCP Recovery through
//! `libusb`, using the same host API intended for physical hardware.

mod hwmodel;
mod usbip;

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use super::hwmodel::HwModelUsbDevice;
    use super::usbip::{UsbControlRequest, UsbIpDevice, UsbIpServer, UsbIpServerConfig};
    #[cfg(target_os = "linux")]
    use crate::test::{build_test_binaries, start_runtime_hw_model, TestParams, TEST_LOCK};
    #[cfg(target_os = "linux")]
    use caliptra_mcu_hw_model::McuHwModel;
    #[cfg(target_os = "linux")]
    use caliptra_mcu_ocp::protocol::device_status::DeviceStatusValue;
    #[cfg(target_os = "linux")]
    use caliptra_mcu_ocp::protocol::prot_cap::{self, RecoveryProtocolCapabilities};
    #[cfg(target_os = "linux")]
    use caliptra_mcu_ocp::protocol::RecoveryCommand;
    #[cfg(target_os = "linux")]
    use caliptra_mcu_romtime::McuBootMilestones;
    #[cfg(target_os = "linux")]
    use caliptra_mcu_xtask::network::tap;
    #[cfg(target_os = "linux")]
    use random_port::PortPicker;
    #[cfg(target_os = "linux")]
    use rusb::UsbContext;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    #[cfg(target_os = "linux")]
    use std::path::PathBuf;
    #[cfg(target_os = "linux")]
    use std::process::Command;
    #[cfg(target_os = "linux")]
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, LazyLock, Mutex};
    use std::time::Duration;

    const OP_REQ_IMPORT: u16 = 0x8003;
    const OP_REP_IMPORT: u16 = 0x0003;
    const USBIP_CMD_SUBMIT: u32 = 0x0000_0001;
    const USBIP_RET_SUBMIT: u32 = 0x0000_0003;
    const USBIP_DIR_OUT: u32 = 0;
    const USBIP_DIR_IN: u32 = 1;
    const DEVID: u32 = 0x0001_0002;

    #[cfg(target_os = "linux")]
    static USBIP_TEST_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    const DEVICE_DESCRIPTOR: [u8; 18] = [
        18, 1, 0x00, 0x02, 0, 0, 0, 64, 0x5e, 0xca, 0x01, 0x00, 0x00, 0x01, 1, 2, 3, 1,
    ];
    const CONFIG_DESCRIPTOR: [u8; 18] = [
        9, 2, 18, 0, 1, 1, 0, 0x80, 50, // configuration
        9, 4, 0, 0, 0, 0xff, 0, 0, 0, // vendor-specific interface
    ];

    #[derive(Clone)]
    struct TestDevice {
        address: Arc<Mutex<u8>>,
        configured: Arc<Mutex<u8>>,
    }

    impl UsbIpDevice for TestDevice {
        fn control(&mut self, request: UsbControlRequest<'_>) -> std::io::Result<Vec<u8>> {
            if !request.data.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "this test device expects no control OUT data",
                ));
            }
            match (request.setup[0], request.setup[1]) {
                // GET_DESCRIPTOR
                (0x80, 6) => {
                    let requested =
                        u16::from_le_bytes([request.setup[6], request.setup[7]]) as usize;
                    let mut descriptor = match request.setup[3] {
                        1 => DEVICE_DESCRIPTOR.to_vec(),
                        2 => CONFIG_DESCRIPTOR.to_vec(),
                        3 => string_descriptor(request.setup[2]),
                        _ => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::Unsupported,
                                "unsupported descriptor",
                            ))
                        }
                    };
                    descriptor.truncate(requested);
                    Ok(descriptor)
                }
                // SET_ADDRESS
                (0x00, 5) => {
                    *self.address.lock().unwrap() = request.setup[2] & 0x7f;
                    Ok(Vec::new())
                }
                // GET_STATUS
                (0x80, 0) => Ok(vec![0, 0]),
                // GET_CONFIGURATION
                (0x80, 8) => Ok(vec![*self.configured.lock().unwrap()]),
                // SET_CONFIGURATION
                (0x00, 9) => {
                    *self.configured.lock().unwrap() = request.setup[2];
                    Ok(Vec::new())
                }
                _ => Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "unsupported control request",
                )),
            }
        }
    }

    #[test]
    fn usbip_host_controller_talks_to_emulated_device() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let server_address = listener.local_addr().unwrap();
        let address = Arc::new(Mutex::new(0));
        let configured = Arc::new(Mutex::new(0));
        let device = TestDevice {
            address: address.clone(),
            configured,
        };
        let config = UsbIpServerConfig::new("1-2", 1, 2, 0xca5e, 0x0001);

        let server = std::thread::spawn(move || {
            UsbIpServer::new(listener, config, device)
                .serve_one_connection(2)
                .unwrap();
        });

        let mut host = TcpStream::connect(server_address).unwrap();
        host.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        host.set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        import_device(&mut host, "1-2");

        let descriptor = submit_control(
            &mut host,
            1,
            USBIP_DIR_IN,
            [0x80, 6, 0, 1, 0, 0, 18, 0],
            &[],
            18,
        );
        assert_eq!(descriptor, DEVICE_DESCRIPTOR);

        let response = submit_control(
            &mut host,
            2,
            USBIP_DIR_OUT,
            [0x00, 5, 7, 0, 0, 0, 0, 0],
            &[],
            0,
        );
        assert!(response.is_empty());
        assert_eq!(*address.lock().unwrap(), 7);

        drop(host);
        server.join().unwrap();
    }

    #[cfg(all(target_os = "linux", not(feature = "fpga_realtime")))]
    #[test]
    fn usbip_lpcip_routes_enumeration_and_recovery_fifo() {
        let lock = TEST_LOCK.lock().unwrap();

        let mut hw = start_runtime_hw_model(TestParams {
            rom_feature: Some("test-lpcip-usb-ocp-recovery"),
            i3c_port: Some(PortPicker::new().pick().unwrap()),
            flash_boot: true,
            rom_only: true,
            ..Default::default()
        });
        let lpcip_host = hw.lpcip_usb_host_controller.clone();
        let recovery_host = Some(hw.usb_recovery_host.clone());

        for _ in 0..50_000_000 {
            hw.step();
            if lpcip_host.device_enabled() {
                break;
            }
        }
        assert!(
            lpcip_host.device_enabled(),
            "firmware did not enable LPCIP USB device"
        );
        lpcip_host.bus_reset();

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let server_address = listener.local_addr().unwrap();
        let config = UsbIpServerConfig::new("1-2", 1, 2, 0x1209, 0x0001);
        let server_thread = std::thread::spawn(move || {
            let result = UsbIpServer::new(
                listener,
                config,
                HwModelUsbDevice::new_lpcip(lpcip_host, recovery_host),
            )
            .serve_one_connection(8);
            if let Err(error) = &result {
                eprintln!("LPCIP USB/IP server failed: {error}");
            }
            result
        });

        let agent_thread = std::thread::spawn(move || {
            let mut host = TcpStream::connect(server_address).unwrap();
            host.set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            host.set_write_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            import_device(&mut host, "1-2");

            let device_descriptor = submit_control(
                &mut host,
                1,
                USBIP_DIR_IN,
                [0x80, 6, 0, 1, 0, 0, 18, 0],
                &[],
                18,
            );
            assert_eq!(&device_descriptor[8..12], &[0x09, 0x12, 0x01, 0x00]);
            submit_control(
                &mut host,
                2,
                USBIP_DIR_OUT,
                [0x00, 5, 7, 0, 0, 0, 0, 0],
                &[],
                0,
            );
            let configuration = submit_control(
                &mut host,
                3,
                USBIP_DIR_IN,
                [0x80, 6, 0, 2, 0, 0, 64, 0],
                &[],
                64,
            );
            assert_eq!(&configuration[..2], &[9, 2]);
            submit_control(
                &mut host,
                4,
                USBIP_DIR_OUT,
                [0x00, 9, 1, 0, 0, 0, 0, 0],
                &[],
                0,
            );

            let prot_cap = submit_control(
                &mut host,
                5,
                USBIP_DIR_IN,
                [0xa1, 0, RecoveryCommand::ProtCap as u8, 0, 0, 0, 15, 0],
                &[],
                15,
            );
            assert_eq!(prot_cap.len(), 15);

            submit_control(
                &mut host,
                6,
                USBIP_DIR_OUT,
                [
                    0x21,
                    0,
                    RecoveryCommand::IndirectFifoCtrl as u8,
                    0,
                    0,
                    0,
                    6,
                    0,
                ],
                &[0, 0, 2, 0, 0, 0],
                0,
            );
            submit_control(
                &mut host,
                7,
                USBIP_DIR_OUT,
                [
                    0x21,
                    0,
                    RecoveryCommand::IndirectFifoData as u8,
                    0,
                    0,
                    0,
                    8,
                    0,
                ],
                &[0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4],
                0,
            );
            let fifo_status = submit_control(
                &mut host,
                8,
                USBIP_DIR_IN,
                [
                    0xa1,
                    0,
                    RecoveryCommand::IndirectFifoStatus as u8,
                    0,
                    0,
                    0,
                    20,
                    0,
                ],
                &[],
                20,
            );
            assert_eq!(fifo_status.len(), 20);
            assert_eq!(u32::from_le_bytes(fifo_status[4..8].try_into().unwrap()), 2);
            assert_eq!(
                u32::from_le_bytes(fifo_status[12..16].try_into().unwrap()),
                64
            );
            assert_eq!(
                u32::from_le_bytes(fifo_status[16..20].try_into().unwrap()),
                64
            );
        });

        for step in 0..50_000_000 {
            if agent_thread.is_finished() {
                break;
            }
            hw.step();
            if step % 1_000 == 0 {
                std::thread::yield_now();
            }
        }
        assert!(
            agent_thread.is_finished(),
            "USB/IP recovery agent timed out"
        );
        agent_thread.join().unwrap();
        server_thread.join().unwrap().unwrap();
        lock.fetch_add(1, Ordering::Relaxed);
    }

    /// End-to-end test through Linux's virtual USB host controller.
    ///
    /// The test skips itself when `usbip`, `vhci_hcd`, or passwordless sudo is
    /// unavailable, matching the network integration-test convention.
    #[cfg(target_os = "linux")]
    #[test]
    fn usbip_linux_vhci_enumerates_emulated_device() {
        let _usbip_lock = USBIP_TEST_LOCK.lock().unwrap();
        if !tap::has_sudo_access() {
            eprintln!("SKIP: No passwordless sudo access");
            return;
        }
        let Some(usbip) = find_usbip() else {
            eprintln!("SKIP: usbip userspace utility is not installed");
            return;
        };
        let modprobe = Command::new("sudo")
            .args(["-n", "modprobe", "vhci_hcd"])
            .output()
            .expect("failed to execute modprobe");
        if !modprobe.status.success() {
            eprintln!(
                "SKIP: vhci_hcd is unavailable: {}",
                String::from_utf8_lossy(&modprobe.stderr)
            );
            return;
        }

        let listener =
            TcpListener::bind(("127.0.0.1", 3240)).expect("USB/IP TCP port 3240 must be available");
        let configured = Arc::new(Mutex::new(0));
        let device = TestDevice {
            address: Arc::new(Mutex::new(0)),
            configured: configured.clone(),
        };
        let config = UsbIpServerConfig::new("1-2", 1, 2, 0xca5e, 0x0001);
        let server = std::thread::spawn(move || {
            UsbIpServer::new(listener, config, device)
                .serve_until_disconnect()
                .unwrap();
        });

        let attach = Command::new("sudo")
            .arg("-n")
            .arg(&usbip)
            .args(["attach", "-r", "127.0.0.1", "-b", "1-2"])
            .output()
            .expect("failed to execute usbip attach");
        assert!(
            attach.status.success(),
            "usbip attach failed: {}",
            String::from_utf8_lossy(&attach.stderr)
        );

        let mut enumerated = false;
        for _ in 0..100 {
            enumerated = linux_usb_device_present(0xca5e, 0x0001);
            if enumerated {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }

        let detach = Command::new("sudo")
            .arg("-n")
            .arg(&usbip)
            .args(["detach", "-p", "0"])
            .output()
            .expect("failed to execute usbip detach");
        assert!(
            detach.status.success(),
            "usbip detach failed: {}",
            String::from_utf8_lossy(&detach.stderr)
        );
        server.join().unwrap();

        assert!(enumerated, "Linux did not enumerate the USB/IP device");
        assert_eq!(*configured.lock().unwrap(), 1);
    }

    /// Exercise the real MCU USB driver and OCP Recovery state machine from a
    /// host recovery agent using libusb over Linux USB/IP and VHCI.
    #[cfg(target_os = "linux")]
    #[test]
    fn usbip_linux_libusb_reads_ocp_recovery_status_from_hwmodel() {
        let lock = TEST_LOCK.lock().unwrap();
        let _usbip_lock = USBIP_TEST_LOCK.lock().unwrap();

        if !linux_usbip_prerequisites_available() {
            return;
        }

        let mut hw = start_runtime_hw_model(TestParams {
            rom_feature: Some("test-usb-ocp-recovery"),
            i3c_port: Some(PortPicker::new().pick().unwrap()),
            flash_boot: true,
            rom_only: true,
            ..Default::default()
        });
        let host = hw.usb_host_controller.clone();
        #[cfg(not(feature = "fpga_realtime"))]
        let recovery_host = Some(hw.usb_recovery_host.clone());
        #[cfg(feature = "fpga_realtime")]
        let recovery_host = None;

        for _ in 0..50_000_000 {
            hw.step();
            if host.device_enabled() {
                break;
            }
        }
        assert!(host.device_enabled(), "firmware did not enable USB device");
        host.bus_reset();

        let listener =
            TcpListener::bind(("127.0.0.1", 3240)).expect("USB/IP TCP port 3240 must be available");
        let config = UsbIpServerConfig::new("1-2", 1, 2, 0x1209, 0x0001);
        let server_thread = std::thread::spawn(move || {
            UsbIpServer::new(listener, config, HwModelUsbDevice::new(host, recovery_host))
                .serve_until_disconnect()
        });

        let agent_thread = std::thread::spawn(|| {
            let attach = Command::new("sudo")
                .args(["-n", "usbip", "attach", "-r", "127.0.0.1", "-b", "1-2"])
                .output()
                .map_err(|error| format!("failed to execute usbip attach: {error}"))?;
            if !attach.status.success() {
                return Err(format!(
                    "usbip attach failed: {}",
                    String::from_utf8_lossy(&attach.stderr)
                ));
            }

            let test_result = run_libusb_ocp_recovery_agent();
            let detach = Command::new("sudo")
                .args(["-n", "usbip", "detach", "-p", "0"])
                .output()
                .map_err(|error| format!("failed to execute usbip detach: {error}"))?;
            if !detach.status.success() {
                return Err(format!(
                    "usbip detach failed: {}",
                    String::from_utf8_lossy(&detach.stderr)
                ));
            }
            test_result
        });

        let mut steps = 0_u64;
        while !agent_thread.is_finished() {
            hw.step();
            steps += 1;
            if steps % 1_000 == 0 {
                std::thread::yield_now();
            }
        }

        let test_result = agent_thread.join().unwrap();
        let server_result = server_thread.join().unwrap();

        test_result.unwrap_or_else(|error| panic!("libusb recovery agent failed: {error}"));
        server_result.unwrap();
        lock.fetch_add(1, Ordering::Relaxed);
    }

    /// Enumerate the LPCIP controller through MCU ROM, then route OCP class
    /// requests to the dedicated recovery hardware over Linux USB/IP.
    #[cfg(all(target_os = "linux", not(feature = "fpga_realtime")))]
    #[test]
    fn usbip_linux_libusb_reads_ocp_recovery_status_from_lpcip() {
        let lock = TEST_LOCK.lock().unwrap();
        let _usbip_lock = USBIP_TEST_LOCK.lock().unwrap();

        if !linux_usbip_prerequisites_available() {
            return;
        }

        let mut hw = start_runtime_hw_model(TestParams {
            rom_feature: Some("test-lpcip-usb-ocp-recovery"),
            i3c_port: Some(PortPicker::new().pick().unwrap()),
            flash_boot: true,
            rom_only: true,
            ..Default::default()
        });
        let host = hw.lpcip_usb_host_controller.clone();
        let recovery_host = Some(hw.usb_recovery_host.clone());

        for _ in 0..50_000_000 {
            hw.step();
            if host.device_enabled() {
                break;
            }
        }
        assert!(
            host.device_enabled(),
            "firmware did not enable LPCIP USB device"
        );
        host.bus_reset();

        let listener =
            TcpListener::bind(("127.0.0.1", 3240)).expect("USB/IP TCP port 3240 must be available");
        let config = UsbIpServerConfig::new("1-2", 1, 2, 0x1209, 0x0001);
        let server_thread = std::thread::spawn(move || {
            UsbIpServer::new(
                listener,
                config,
                HwModelUsbDevice::new_lpcip(host, recovery_host),
            )
            .serve_until_disconnect()
        });

        let agent_thread = std::thread::spawn(|| {
            let attach = Command::new("sudo")
                .args(["-n", "usbip", "attach", "-r", "127.0.0.1", "-b", "1-2"])
                .output()
                .map_err(|error| format!("failed to execute usbip attach: {error}"))?;
            if !attach.status.success() {
                return Err(format!(
                    "usbip attach failed: {}",
                    String::from_utf8_lossy(&attach.stderr)
                ));
            }

            let test_result = run_libusb_ocp_recovery_agent();
            let detach = Command::new("sudo")
                .args(["-n", "usbip", "detach", "-p", "0"])
                .output()
                .map_err(|error| format!("failed to execute usbip detach: {error}"))?;
            if !detach.status.success() {
                return Err(format!(
                    "usbip detach failed: {}",
                    String::from_utf8_lossy(&detach.stderr)
                ));
            }
            test_result
        });

        let mut steps = 0_u64;
        while !agent_thread.is_finished() {
            hw.step();
            steps += 1;
            if steps % 1_000 == 0 {
                std::thread::yield_now();
            }
        }

        let test_result = agent_thread.join().unwrap();
        let server_result = server_thread.join().unwrap();

        test_result.unwrap_or_else(|error| panic!("libusb recovery agent failed: {error}"));
        server_result.unwrap();
        lock.fetch_add(1, Ordering::Relaxed);
    }

    /// Run the Linux recovery-agent application against LPCIP over USB/IP and
    /// boot Caliptra and the MCU from the three streamed recovery artifacts.
    #[cfg(all(target_os = "linux", not(feature = "fpga_realtime")))]
    #[test]
    fn usbip_linux_libusb_lpcip_completes_recovery_boot() {
        let lock = TEST_LOCK.lock().unwrap();
        let _usbip_lock = USBIP_TEST_LOCK.lock().unwrap();

        if !linux_usbip_prerequisites_available() {
            return;
        }

        let params = TestParams {
            rom_feature: Some("test-lpcip-usb-ocp-recovery"),
            i3c_port: Some(PortPicker::new().pick().unwrap()),
            flash_boot: true,
            usb_recovery: true,
            rom_only: true,
            ..Default::default()
        };
        let bins = build_test_binaries(&params);
        let image_dir = tempfile::tempdir().expect("failed to create recovery image directory");
        let caliptra_fmc_rt = image_dir.path().join("caliptra-fmc-rt.bin");
        let soc_manifest = image_dir.path().join("soc-manifest.bin");
        let mcu_runtime = image_dir.path().join("mcu-runtime.bin");
        std::fs::write(&caliptra_fmc_rt, &bins.caliptra_fw)
            .expect("failed to write Caliptra recovery image");
        std::fs::write(&soc_manifest, &bins.soc_manifest)
            .expect("failed to write SoC manifest recovery image");
        std::fs::write(&mcu_runtime, &bins.mcu_runtime)
            .expect("failed to write MCU runtime recovery image");
        let recovery_agent = build_usb_recovery_agent();
        let mut hw = start_runtime_hw_model(TestParams {
            custom_mcu_rom: Some(bins.mcu_rom),
            ..params
        });
        let host = hw.lpcip_usb_host_controller.clone();
        let recovery_host = Some(hw.usb_recovery_host.clone());

        for _ in 0..50_000_000 {
            hw.step();
            if host.device_enabled() {
                break;
            }
        }
        assert!(
            host.device_enabled(),
            "firmware did not enable LPCIP USB device"
        );
        host.bus_reset();

        let listener =
            TcpListener::bind(("127.0.0.1", 3240)).expect("USB/IP TCP port 3240 must be available");
        let config = UsbIpServerConfig::new("1-2", 1, 2, 0x1209, 0x0001);
        let server_thread = std::thread::spawn(move || {
            UsbIpServer::new(
                listener,
                config,
                HwModelUsbDevice::new_lpcip(host, recovery_host),
            )
            .serve_until_disconnect()
        });

        let agent_thread = std::thread::spawn(move || {
            let _image_dir = image_dir;
            attach_usbip_device()?;
            (|| -> Result<(), String> {
                grant_libusb_access(0x1209, 0x0001).map_err(|error| error.to_string())?;
                let output = Command::new(recovery_agent)
                    .arg("--caliptra-fmc-rt")
                    .arg(caliptra_fmc_rt)
                    .arg("--soc-manifest")
                    .arg(soc_manifest)
                    .arg("--mcu-runtime")
                    .arg(mcu_runtime)
                    .output()
                    .map_err(|error| format!("failed to launch USB recovery agent: {error}"))?;
                if !output.status.success() {
                    return Err(format!(
                        "USB recovery agent exited with {}\nstdout:\n{}\nstderr:\n{}",
                        output.status,
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    ));
                }
                Ok(())
            })()
        });

        for step in 0..250_000_000 {
            if agent_thread.is_finished() {
                break;
            }
            hw.step();
            if step % 1_000 == 0 {
                std::thread::yield_now();
            }
        }
        assert!(
            agent_thread.is_finished(),
            "USB recovery agent did not finish within the emulation cycle budget"
        );

        let agent_result = agent_thread.join().unwrap();
        if let Err(error) = agent_result {
            let _ = detach_usbip_device();
            let _ = server_thread.join();
            panic!("USB recovery agent failed: {error}");
        }
        hw.step_until(|model| {
            model
                .mci_boot_milestones()
                .contains(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE)
        });
        detach_usbip_device().unwrap();
        server_thread.join().unwrap().unwrap();
        lock.fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(target_os = "linux")]
    fn build_usb_recovery_agent() -> PathBuf {
        let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let output = Command::new(env!("CARGO"))
            .current_dir(workspace)
            .args(["build", "-p", "caliptra-mcu-usb-recovery"])
            .output()
            .expect("failed to execute cargo build for USB recovery agent");
        assert!(
            output.status.success(),
            "failed to build USB recovery agent:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );

        let test_executable = std::env::current_exe().expect("failed to locate test executable");
        let profile_dir = test_executable
            .parent()
            .and_then(|deps| deps.parent())
            .expect("test executable is not under a Cargo profile directory");
        profile_dir.join("caliptra-mcu-usb-recovery")
    }

    #[cfg(target_os = "linux")]
    fn linux_usbip_prerequisites_available() -> bool {
        if !tap::has_sudo_access() {
            eprintln!("SKIP: No passwordless sudo access");
            return false;
        }
        if find_usbip().is_none() {
            eprintln!("SKIP: usbip userspace utility is not installed");
            return false;
        }
        let modprobe = Command::new("sudo")
            .args(["-n", "modprobe", "vhci_hcd"])
            .output()
            .expect("failed to execute modprobe");
        if !modprobe.status.success() {
            eprintln!(
                "SKIP: vhci_hcd is unavailable: {}",
                String::from_utf8_lossy(&modprobe.stderr)
            );
            return false;
        }
        true
    }

    #[cfg(target_os = "linux")]
    fn find_usbip() -> Option<PathBuf> {
        let mut candidates = std::env::var_os("USBIP")
            .map(PathBuf::from)
            .into_iter()
            .chain([PathBuf::from("usbip")])
            .collect::<Vec<_>>();
        if let Ok(entries) = std::fs::read_dir("/usr/lib/linux-tools") {
            candidates.extend(
                entries
                    .flatten()
                    .map(|entry| entry.path().join("usbip"))
                    .filter(|path| path.is_file()),
            );
        }
        candidates.into_iter().find(|candidate| {
            Command::new(candidate)
                .arg("version")
                .output()
                .is_ok_and(|output| output.status.success())
        })
    }

    #[cfg(target_os = "linux")]
    fn attach_usbip_device() -> Result<(), String> {
        let usbip = find_usbip().ok_or_else(|| "usbip is unavailable".to_owned())?;
        let attach = Command::new("sudo")
            .arg("-n")
            .arg(usbip)
            .args(["attach", "-r", "127.0.0.1", "-b", "1-2"])
            .output()
            .map_err(|error| format!("failed to execute usbip attach: {error}"))?;
        if !attach.status.success() {
            return Err(format!(
                "usbip attach failed: {}",
                String::from_utf8_lossy(&attach.stderr)
            ));
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn detach_usbip_device() -> Result<(), String> {
        let usbip = find_usbip().ok_or_else(|| "usbip is unavailable".to_owned())?;
        let detach = Command::new("sudo")
            .arg("-n")
            .arg(usbip)
            .args(["detach", "-p", "0"])
            .output()
            .map_err(|error| format!("failed to execute usbip detach: {error}"))?;
        if !detach.status.success() {
            return Err(format!(
                "usbip detach failed: {}",
                String::from_utf8_lossy(&detach.stderr)
            ));
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn grant_libusb_access(vendor: u16, product: u16) -> anyhow::Result<()> {
        let context = rusb::Context::new()?;
        let device = (0..100)
            .find_map(|_| {
                let devices = context.devices().ok()?;
                let device = devices.iter().find(|device| {
                    device.device_descriptor().is_ok_and(|descriptor| {
                        descriptor.vendor_id() == vendor && descriptor.product_id() == product
                    })
                });
                if device.is_none() {
                    std::thread::sleep(Duration::from_millis(20));
                }
                device
            })
            .ok_or_else(|| anyhow::anyhow!("Linux did not enumerate the USB recovery device"))?;
        let device_node = format!(
            "/dev/bus/usb/{:03}/{:03}",
            device.bus_number(),
            device.address()
        );
        let chmod = Command::new("sudo")
            .args(["-n", "chmod", "0666", &device_node])
            .output()?;
        anyhow::ensure!(
            chmod.status.success(),
            "could not grant access to {device_node}: {}",
            String::from_utf8_lossy(&chmod.stderr)
        );
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn run_libusb_ocp_recovery_agent() -> Result<(), String> {
        let context = rusb::Context::new().map_err(|error| error.to_string())?;
        let (device, descriptor) = (0..100)
            .find_map(|_| {
                let devices = context.devices().ok()?;
                let result = devices.iter().find_map(|device| {
                    let descriptor = device.device_descriptor().ok()?;
                    (descriptor.vendor_id() == 0x1209 && descriptor.product_id() == 0x0001)
                        .then_some((device, descriptor))
                });
                if result.is_none() {
                    std::thread::sleep(Duration::from_millis(20));
                }
                result
            })
            .ok_or_else(|| "Linux did not enumerate the Caliptra USB/IP device".to_owned())?;

        let device_node = format!(
            "/dev/bus/usb/{:03}/{:03}",
            device.bus_number(),
            device.address()
        );
        let chmod = Command::new("sudo")
            .args(["-n", "chmod", "0666", &device_node])
            .output()
            .map_err(|error| format!("failed to execute chmod: {error}"))?;
        if !chmod.status.success() {
            return Err(format!(
                "could not grant access to {device_node}: {}",
                String::from_utf8_lossy(&chmod.stderr)
            ));
        }

        if descriptor.num_configurations() != 1 {
            return Err("Caliptra device did not advertise one configuration".to_owned());
        }
        let handle = device
            .open()
            .map_err(|error| format!("could not open Caliptra USB device: {error}"))?;
        handle
            .claim_interface(0)
            .map_err(|error| format!("could not claim OCP Recovery interface: {error}"))?;

        let timeout = Duration::from_secs(2);
        let mut prot_cap = vec![0; prot_cap::RESPONSE_LEN];
        let length = handle
            .read_control(
                0xA1,
                0,
                RecoveryCommand::ProtCap as u16,
                0,
                &mut prot_cap,
                timeout,
            )
            .map_err(|error| format!("PROT_CAP read failed: {error}"))?;
        prot_cap.truncate(length);
        if prot_cap.len() != prot_cap::RESPONSE_LEN {
            return Err(format!("unexpected PROT_CAP length: {}", prot_cap.len()));
        }

        let mut expected_caps = RecoveryProtocolCapabilities(0);
        expected_caps.set_identification(true);
        expected_caps.set_device_status(true);
        expected_caps.set_push_c_image_support(true);
        expected_caps.set_recovery_memory_access(true);
        expected_caps.set_fifo_cms_support(true);
        let expected_low = (expected_caps.0 & 0xff) as u8;
        if prot_cap[10] != expected_low {
            return Err(format!(
                "PROT_CAP capabilities mismatch: expected {expected_low:#04x}, got {:#04x}",
                prot_cap[10]
            ));
        }

        let mut status = [0; 7];
        let length = handle
            .read_control(
                0xA1,
                0,
                RecoveryCommand::DeviceStatus as u16,
                0,
                &mut status,
                timeout,
            )
            .map_err(|error| format!("DEVICE_STATUS read failed: {error}"))?;
        if length != status.len() || status[0] != DeviceStatusValue::RecoveryMode as u8 {
            return Err(format!(
                "unexpected DEVICE_STATUS: length={length}, status={:#04x}",
                status[0]
            ));
        }

        Ok(())
    }

    fn string_descriptor(index: u8) -> Vec<u8> {
        if index == 0 {
            return vec![4, 3, 0x09, 0x04];
        }
        let value = match index {
            1 => "Caliptra",
            2 => "USB/IP Test Device",
            3 => "0001",
            _ => return Vec::new(),
        };
        let utf16: Vec<u16> = value.encode_utf16().collect();
        let mut descriptor = Vec::with_capacity(2 + utf16.len() * 2);
        descriptor.extend_from_slice(&[(2 + utf16.len() * 2) as u8, 3]);
        for character in utf16 {
            descriptor.extend_from_slice(&character.to_le_bytes());
        }
        descriptor
    }

    #[cfg(target_os = "linux")]
    fn linux_usb_device_present(vendor: u16, product: u16) -> bool {
        let Ok(entries) = std::fs::read_dir("/sys/bus/usb/devices") else {
            return false;
        };
        entries.flatten().any(|entry| {
            let path = entry.path();
            let vendor_id = std::fs::read_to_string(path.join("idVendor"));
            let product_id = std::fs::read_to_string(path.join("idProduct"));
            match (vendor_id, product_id) {
                (Ok(vendor_id), Ok(product_id)) => {
                    vendor_id.trim() == format!("{vendor:04x}")
                        && product_id.trim() == format!("{product:04x}")
                }
                _ => false,
            }
        })
    }

    fn import_device(stream: &mut TcpStream, busid: &str) {
        let mut request = Vec::with_capacity(40);
        request.extend_from_slice(&0x0111_u16.to_be_bytes());
        request.extend_from_slice(&OP_REQ_IMPORT.to_be_bytes());
        request.extend_from_slice(&0_u32.to_be_bytes());
        let mut encoded_busid = [0_u8; 32];
        encoded_busid[..busid.len()].copy_from_slice(busid.as_bytes());
        request.extend_from_slice(&encoded_busid);
        stream.write_all(&request).unwrap();

        let mut reply = [0_u8; 320];
        stream.read_exact(&mut reply).unwrap();
        assert_eq!(u16::from_be_bytes(reply[0..2].try_into().unwrap()), 0x0111);
        assert_eq!(
            u16::from_be_bytes(reply[2..4].try_into().unwrap()),
            OP_REP_IMPORT
        );
        assert_eq!(u32::from_be_bytes(reply[4..8].try_into().unwrap()), 0);
    }

    fn submit_control(
        stream: &mut TcpStream,
        seqnum: u32,
        direction: u32,
        setup: [u8; 8],
        out_data: &[u8],
        expected_length: u32,
    ) -> Vec<u8> {
        let transfer_length = if direction == USBIP_DIR_IN {
            expected_length
        } else {
            out_data.len() as u32
        };

        let mut command = Vec::with_capacity(48 + out_data.len());
        for value in [USBIP_CMD_SUBMIT, seqnum, DEVID, direction, 0] {
            command.extend_from_slice(&value.to_be_bytes());
        }
        command.extend_from_slice(&0_u32.to_be_bytes()); // transfer flags
        command.extend_from_slice(&transfer_length.to_be_bytes());
        command.extend_from_slice(&0_u32.to_be_bytes()); // start frame
        command.extend_from_slice(&0_u32.to_be_bytes()); // packet count
        command.extend_from_slice(&0_u32.to_be_bytes()); // interval
        command.extend_from_slice(&setup);
        command.extend_from_slice(out_data);
        stream.write_all(&command).unwrap();

        let mut reply = [0_u8; 48];
        stream
            .read_exact(&mut reply)
            .unwrap_or_else(|error| panic!("USB/IP submit {seqnum} reply failed: {error}"));
        assert_eq!(
            u32::from_be_bytes(reply[0..4].try_into().unwrap()),
            USBIP_RET_SUBMIT
        );
        assert_eq!(u32::from_be_bytes(reply[4..8].try_into().unwrap()), seqnum);
        assert_eq!(i32::from_be_bytes(reply[20..24].try_into().unwrap()), 0);
        let actual_length = u32::from_be_bytes(reply[24..28].try_into().unwrap()) as usize;

        let mut data = vec![0; actual_length];
        stream.read_exact(&mut data).unwrap();
        data
    }
}
