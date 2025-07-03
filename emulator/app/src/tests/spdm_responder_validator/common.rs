// Licensed under the Apache-2.0 license

use std::fs::File;
use std::io::{self, ErrorKind};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub enum SpdmTransport {
    Mctp,
    PciDoe,
}

impl SpdmTransport {
    fn as_str(&self) -> &'static str {
        match self {
            SpdmTransport::Mctp => "MCTP",
            SpdmTransport::PciDoe => "PCI_DOE",
        }
    }

    /// Create transport from string (useful for configuration)
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "MCTP" => Some(SpdmTransport::Mctp),
            "PCI_DOE" => Some(SpdmTransport::PciDoe),
            _ => None,
        }
    }
}

pub fn execute_spdm_validator(running: Arc<AtomicBool>, transport: &'static str) {
    std::thread::spawn(move || match start_spdm_device_validator(transport) {
        Ok(mut child) => {
            while running.load(Ordering::Relaxed) {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        println!(
                            "spdm_device_validator_sample exited with status: {:?}",
                            status
                        );
                        break;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        println!("Error: {:?}", e);
                        break;
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            let _ = child.kill();
        }
        Err(e) => {
            println!(
                "Error: {:?} Failed to spawn spdm_device_validator_sample!!",
                e
            );
        }
    });
}

pub fn start_spdm_device_validator(transport: &'static str) -> io::Result<Child> {
    let spdm_validator_dir = std::env::var("SPDM_VALIDATOR_DIR");
    let dir_path = match spdm_validator_dir {
        Ok(dir) => {
            println!("SPDM_VALIDATOR_DIR: {}", dir);
            Path::new(&dir).to_path_buf()
        }
        Err(_e) => {
            println!(
                "SPDM_VALIDATOR_DIR is not set. The spdm_device_validator_sample can't be found"
            );
            return Err(ErrorKind::NotFound.into());
        }
    };

    let utility_path = dir_path.join("spdm_device_validator_sample");
    if !utility_path.exists() {
        println!("spdm_device_validator_sample not found in the path");
        return Err(ErrorKind::NotFound.into());
    }

    let log_file_path = dir_path.join("spdm_device_validator_output.txt");

    let output_file = File::create(log_file_path)?;
    let output_file_clone = output_file.try_clone()?;

    println!(
        "Starting spdm_device_validator_sample process with {} transport",
        transport
    );

    Command::new(utility_path)
        .args(["--trans", transport])
        .stdout(Stdio::from(output_file))
        .stderr(Stdio::from(output_file_clone))
        .spawn()
}
