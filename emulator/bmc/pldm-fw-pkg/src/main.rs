/*++

Licensed under the Apache-2.0 license.

--*/
use clap::{Arg, Command};
/// PLDM Firmware Tool
///
/// This tool is designed to work with PLDM (Platform Level Data Model) firmware packages.
/// It supports encoding a firmware manifest (in TOML format) into a binary firmware package and
/// decoding a firmware package back into a manifest.
///
/// An sample manifest file can be found in the `examples` directory.
/// This CLI tool provides the following subcommands:
/// - `encode`: Convert a manifest TOML file into a firmware package.
/// - `decode`: Convert a firmware package back into a manifest TOML file and its firmware components.
///
/// # Examples
///
/// Encode a manifest file:
/// ```bash
/// pldm_fw_pkg encode --manifest manifest.toml --file firmware.bin
/// ```
///
/// Decode a firmware package:
/// ```bash
/// pldm_fw_pkg decode --file firmware.bin --directory output
/// ```
///
use pldm_fw_pkg::FirmwareManifest;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = Command::new("PLDM Firmware Tool")
        .version("1.0")
        .about("Encodes/decodes PLDM firmware packages")
        .subcommand(
            Command::new("encode")
                .about("Encodes a manifest TOML file to a firmware package")
                .arg(
                    Arg::new("manifest")
                        .short('m')
                        .long("manifest")
                        .value_name("MANIFEST")
                        .help("Path to the manifest TOML file")
                        .required(true),
                )
                .arg(
                    Arg::new("file")
                        .short('f')
                        .long("file")
                        .value_name("FILE")
                        .help("Output file for the firmware package")
                        .required(true),
                ),
        )
        .subcommand(
            Command::new("decode")
                .about("Decodes a firmware package to a manifest and components")
                .arg(
                    Arg::new("package")
                        .short('p')
                        .long("package")
                        .value_name("PACKAGE")
                        .help("Path to the firmware package file")
                        .required(true),
                )
                .arg(
                    Arg::new("dir")
                        .short('d')
                        .long("directory")
                        .value_name("DIRECTORY")
                        .help("Output directory for manifest and components")
                        .required(true),
                ),
        )
        .get_matches();

    // Match on the subcommand and handle the arguments
    match matches.subcommand() {
        Some(("encode", sub_matches)) => {
            let manifest_path = sub_matches.get_one::<String>("manifest").unwrap();
            let output_path = sub_matches.get_one::<String>("file").unwrap();
            let firmware_manifest: FirmwareManifest =
                FirmwareManifest::parse_manifest_file(manifest_path)
                    .expect("Failed to parse the manifest file");
            firmware_manifest.generate_firmware_package(output_path)?;
            println!("Encoded FirmwarePackage to binary file: {}", output_path);
        }
        Some(("decode", sub_matches)) => {
            let package_path = sub_matches.get_one::<String>("package").unwrap();
            let output_dir = sub_matches.get_one::<String>("dir").unwrap();
            FirmwareManifest::decode_firmware_package(package_path, Some(output_dir))
                .expect("Failed to decode the firmware package");
            println!("Decoded FirmwarePackage to directory: {}", output_dir);
        }
        _ => {
            println!("Use either 'encode' or 'decode' subcommands.");
            std::process::exit(1);
        }
    }

    Ok(())
}
