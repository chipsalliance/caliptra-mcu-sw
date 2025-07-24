// Licensed under the Apache-2.0 license

use anyhow::{bail, Result};
use std::{io::Write, path::Path};

/// Build Caliptra ROM and firmware bundle, MCU ROM and runtime, and SoC manifest, and package them all together in a ZIP file.
pub fn all_build(
    output: Option<&str>,
    platform: Option<&str>,
    use_dccm_for_stack: bool,
    dccm_offset: Option<u32>,
    dccm_size: Option<u32>,
) -> Result<()> {
    // TODO: use temp files
    let platform = platform.unwrap_or("emulator");
    let mcu_rom = crate::rom_build(Some(platform), "")?;
    let memory_map = match platform {
        "emulator" => &mcu_config_emulator::EMULATOR_MEMORY_MAP,
        "fpga" => &mcu_config_fpga::FPGA_MEMORY_MAP,
        _ => bail!("Unknown platform: {:?}", platform),
    };
    let mcu_runtime = &crate::runtime_build_with_apps_cached(
        &[],
        None,
        false,
        Some(platform),
        Some(memory_map),
        use_dccm_for_stack,
        dccm_offset,
        dccm_size,
        None,
    )?;

    let fpga = platform == "fpga";
    let mut caliptra_builder =
        crate::CaliptraBuilder::new(fpga, None, None, None, None, Some(mcu_runtime.into()), None);
    let caliptra_rom = caliptra_builder.get_caliptra_rom()?;
    let caliptra_fw = caliptra_builder.get_caliptra_fw()?;
    let vendor_pk_hash = caliptra_builder.get_vendor_pk_hash()?;
    println!("Vendor PK hash: {:x?}", vendor_pk_hash);
    let soc_manifest = caliptra_builder.get_soc_manifest()?;

    let default_path = crate::target_dir().join("all-fw.zip");
    let path = output.map(Path::new).unwrap_or(&default_path);
    println!("Creating ZIP file: {}", path.display());
    let file = std::fs::File::create(path)?;
    let mut zip = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o644)
        .last_modified_time(zip::DateTime::try_from(chrono::Local::now().naive_local())?);

    let data = std::fs::read(caliptra_rom)?;
    println!(
        "Adding Caliptra ROM (caliptra_rom.bin): {} bytes",
        data.len()
    );
    zip.start_file("caliptra_rom.bin", options)?;
    zip.write_all(&data)?;

    let data = std::fs::read(caliptra_fw)?;
    println!(
        "Adding Caliptra FW bundle (caliptra_fw.bin): {} bytes",
        data.len()
    );
    zip.start_file("caliptra_fw.bin", options)?;
    zip.write_all(&data)?;

    let data = std::fs::read(mcu_rom)?;
    println!("Adding MCU ROM (mcu_rom.bin): {} bytes", data.len());
    zip.start_file("mcu_rom.bin", options)?;
    zip.write_all(&data)?;

    let data = std::fs::read(mcu_runtime)?;
    println!("Adding MCU runtime (mcu_runtime.bin): {} bytes", data.len());
    zip.start_file("mcu_runtime.bin", options)?;
    zip.write_all(&data)?;

    let data = std::fs::read(soc_manifest)?;
    println!(
        "Adding SoC manifest (soc_manifest.bin): {} bytes",
        data.len()
    );
    zip.start_file("soc_manifest.bin", options)?;
    zip.write_all(&data)?;
    zip.finish()?;

    Ok(())
}
