// Licensed under the Apache-2.0 license

use anyhow::{anyhow, bail, Result};
use caliptra_builder::{firmware, ImageOptions};
use caliptra_image_types::FwVerificationPqcKeyType;

fn main() -> Result<()> {
    caliptra_mcu_builder::caliptra_source_revision()?;
    let mut args = std::env::args().skip(1);
    let action = args.next().ok_or_else(|| anyhow!("missing build action"))?;
    let output = args.next().ok_or_else(|| anyhow!("missing output path"))?;
    let bytes = match action.as_str() {
        "rom" => {
            let index: usize = args
                .next()
                .ok_or_else(|| anyhow!("missing firmware ID index"))?
                .parse()?;
            let id = firmware::REGISTERED_FW
                .get(index)
                .ok_or_else(|| anyhow!("unregistered firmware ID index {index}"))?;
            caliptra_builder::build_firmware_rom(id)?
        }
        "firmware" => {
            let mut next = || {
                args.next()
                    .ok_or_else(|| anyhow!("missing firmware option"))
            };
            let fpga: bool = next()?.parse()?;
            let ocp_lock: bool = next()?.parse()?;
            let svn: u32 = next()?.parse()?;
            let pqc = match next()?.as_str() {
                "lms" => FwVerificationPqcKeyType::LMS,
                "mldsa" => FwVerificationPqcKeyType::MLDSA,
                value => bail!("unsupported PQC key type {value}"),
            };
            let second_key: bool = next()?.parse()?;
            let fmc = if fpga {
                &firmware::FMC_FPGA_WITH_UART
            } else {
                &firmware::FMC_WITH_UART
            };
            let app = match (fpga, ocp_lock) {
                (true, true) => &firmware::APP_WITH_UART_OCP_LOCK_FPGA,
                (true, false) => &firmware::APP_WITH_UART_FPGA,
                (false, true) => &firmware::APP_WITH_UART_OCP_LOCK,
                (false, false) => &firmware::APP_WITH_UART,
            };
            caliptra_builder::build_and_sign_image(
                fmc,
                app,
                ImageOptions {
                    pqc_key_type: pqc,
                    fw_svn: svn,
                    vendor_config: if second_key {
                        caliptra_image_fake_keys::VENDOR_CONFIG_KEY_1
                    } else {
                        caliptra_image_fake_keys::VENDOR_CONFIG_KEY_0
                    },
                    ..Default::default()
                },
            )?
            .to_bytes()?
        }
        value => bail!("unsupported core build action {value}"),
    };
    if args.next().is_some() {
        bail!("unexpected trailing core build options");
    }
    std::fs::write(output, bytes)?;
    Ok(())
}
