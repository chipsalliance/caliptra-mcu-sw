// Licensed under the Apache-2.0 license

#[cfg(test)]
mod test {
    use std::io::Write;
    use std::process::ExitStatus;
    use std::sync::atomic::AtomicU32;
    use std::sync::Mutex;
    use std::{
        path::{Path, PathBuf},
        process::Command,
        sync::LazyLock,
    };

    const TARGET: &str = "riscv32imc-unknown-none-elf";

    static PROJECT_ROOT: LazyLock<PathBuf> = LazyLock::new(|| {
        Path::new(&env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf()
    });

    fn target_binary(name: &str) -> PathBuf {
        PROJECT_ROOT
            .join("target")
            .join(TARGET)
            .join("release")
            .join(name)
    }

    // only build the ROM once
    static ROM: LazyLock<PathBuf> = LazyLock::new(compile_rom);

    static BUILD_LOCK: LazyLock<Mutex<AtomicU32>> = LazyLock::new(|| Mutex::new(AtomicU32::new(0)));

    fn compile_rom() -> PathBuf {
        let output = target_binary("rom.bin");
        let mut cmd = Command::new("cargo");
        let cmd = cmd.args(["xtask", "rom-build"]).current_dir(&*PROJECT_ROOT);
        let cmd_output = cmd.output().unwrap();
        if !cmd.status().unwrap().success() {
            std::io::stdout().write_all(&cmd_output.stdout).unwrap();
            std::io::stderr().write_all(&cmd_output.stderr).unwrap();
            panic!("failed to compile ROM");
        }
        assert!(output.exists());
        output
    }

    fn compile_runtime(feature: &str) -> PathBuf {
        let lock = BUILD_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let output = target_binary(&format!("runtime-{}.bin", feature));
        let mut cmd = Command::new("cargo");
        let cmd = cmd
            .args([
                "xtask",
                "runtime-build",
                "--features",
                feature,
                "--output",
                &format!("{}", output.display()),
            ])
            .current_dir(&*PROJECT_ROOT);
        let cmd_output = cmd.output().unwrap();
        if !cmd.status().unwrap().success() {
            std::io::stdout().write_all(&cmd_output.stdout).unwrap();
            std::io::stderr().write_all(&cmd_output.stderr).unwrap();
            panic!("failed to compile runtime");
        }
        assert!(output.exists());
        // force the compiler to keep the lock
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        output
    }

    fn run_runtime(
        feature: &str,
        rom_path: PathBuf,
        runtime_path: PathBuf,
        i3c_port: String,
    ) -> ExitStatus {
        let cargo_run_args = vec![
            "run",
            "-p",
            "emulator",
            "--release",
            "--features",
            feature,
            "--",
            "--rom",
            rom_path.to_str().unwrap(),
            "--firmware",
            runtime_path.to_str().unwrap(),
            "--i3c-port",
            i3c_port.as_str(),
        ];
        println!("Running test firmware {}", feature.replace("_", "-"));
        let mut cmd = Command::new("cargo");
        let cmd = cmd.args(&cargo_run_args).current_dir(&*PROJECT_ROOT);
        cmd.status().unwrap()
    }

    #[macro_export]
    macro_rules! run_test {
        ($test:ident) => {
            #[test]
            fn $test() {
                println!("Compiling test firmware {}", stringify!($test));
                let feature = stringify!($test).replace("_", "-");
                let test_runtime = compile_runtime(&feature);
                let i3c_port = "65534".to_string();
                let test = run_runtime(&feature, ROM.to_path_buf(), test_runtime, i3c_port);
                assert_eq!(0, test.code().unwrap_or_default());
            }
        };
    }

    // To add a test:
    // * add the test name here
    // * add the feature to the emulator and use it to implement any behavior needed
    // * add the feature to the runtime and use it in board.rs at the end of the main function to call your test
    // These use underscores but will be converted to dashes in the feature flags
    run_test!(test_i3c_simple);
    run_test!(test_i3c_constant_writes);

    run_test!(test_flash_ctrl_init);
    run_test!(test_flash_ctrl_read_write_page);
    run_test!(test_flash_ctrl_erase_page);
    run_test!(test_mctp_ctrl_cmds);
    run_test!(test_mctp_send_loopback);
}
