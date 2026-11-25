// Licensed under the Apache-2.0 license

use anyhow::{anyhow, bail, Result};
use caliptra_mcu_config_emulator::flash::{
    PartitionTable, StandAloneChecksumCalculator, IMAGE_A_PARTITION, IMAGE_B_PARTITION,
};
use caliptra_mcu_flash_image::{
    FlashHeader, FlashImageVersion, ImageHeader, ImageHeaderV1V2, ImageHeaderV3,
    CALIPTRA_FMC_RT_IDENTIFIER, HEADER_VERSION, MAX_FILENAME_LEN, MCU_RT_IDENTIFIER,
    OWNER_AUTH_MANIFEST_IDENTIFIER, OWNER_MEASUREMENT_POLICY_IDENTIFIER,
    SOC_IMAGES_BASE_IDENTIFIER, SOC_MANIFEST_IDENTIFIER,
};
use std::fs::{File, OpenOptions};
use std::io::{self, Error, ErrorKind, Read, Seek, Write};
use std::mem::offset_of;
use zerocopy::{FromBytes, Immutable, IntoBytes};

mod v1;
mod v2;
mod v3;

pub use v1::FlashImageV1;
pub use v2::FlashImageV2;
pub use v3::{generate_image_info, FlashImageV3};

pub enum FlashImage<'a> {
    V1(FlashImageV1<'a>),
    V2(FlashImageV2<'a>),
    V3(FlashImageV3<'a>),
}

#[derive(Clone)]
pub struct FirmwareImage<'a> {
    pub identifier: u32,
    pub data: &'a [u8],
    pub filename: [u8; MAX_FILENAME_LEN],
}

impl<'a> FirmwareImage<'a> {
    pub fn new(identifier: u32, content: &'a [u8], filename: Option<&[u8]>) -> io::Result<Self> {
        let mut fname = [0u8; MAX_FILENAME_LEN];
        if let Some(name) = filename {
            if name.len() > MAX_FILENAME_LEN {
                return Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    format!("network filename exceeds {MAX_FILENAME_LEN} bytes"),
                ));
            }
            fname[..name.len()].copy_from_slice(name);
        }
        Ok(Self {
            identifier,
            data: content,
            filename: fname,
        })
    }
}

fn encode_toc(
    header: &(impl IntoBytes + Immutable),
    entries: &[impl IntoBytes + Immutable],
) -> Vec<u8> {
    let mut bytes = header.as_bytes().to_vec();
    for entry in entries {
        bytes.extend_from_slice(entry.as_bytes());
    }
    bytes
}

impl<'a> FlashImage<'a> {
    pub fn new(images: &'a [FirmwareImage<'a>], image_info: &[ImageHeaderV3]) -> Self {
        Self::V3(FlashImageV3::new(images, image_info))
    }

    pub fn with_version(images: &'a [FirmwareImage<'a>], version: FlashImageVersion) -> Self {
        match version {
            FlashImageVersion::V1 => Self::V1(FlashImageV1::new(images)),
            FlashImageVersion::V2 => Self::V2(FlashImageV2::new(images)),
            FlashImageVersion::V3 => Self::new(images, &generate_image_info(images.to_vec())),
        }
    }

    /// Convert the flash image to a byte vector
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.to_toc_bytes();
        let images = match self {
            Self::V1(image) => image.images(),
            Self::V2(image) => image.images(),
            Self::V3(image) => image.images(),
        };
        for image in images {
            bytes.extend_from_slice(image.data);
        }
        bytes
    }

    /// Convert just the flash header and image headers to a byte vector.
    pub fn to_toc_bytes(&self) -> Vec<u8> {
        match self {
            Self::V1(image) => image.to_toc_bytes(),
            Self::V2(image) => image.to_toc_bytes(),
            Self::V3(image) => image.to_toc_bytes(),
        }
    }

    pub fn write_to_file(&self, offset: usize, filename: &str) -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(filename)
            .map_err(|e| anyhow!(format!("Unable to open file {}: {}", filename, e)))?;

        // Seek to the specified offset before writing
        file.seek(std::io::SeekFrom::Start(offset as u64))
            .map_err(|e| {
                anyhow!(format!(
                    "Unable to seek to offset {} in file {}: {}",
                    offset, filename, e
                ))
            })?;
        file.write_all(&self.to_bytes())?;

        Ok(())
    }

    pub fn verify_flash_partition_table(image: &[u8]) -> Result<PartitionTable> {
        if image.len() < std::mem::size_of::<PartitionTable>() {
            bail!("Image too small to contain the partition table.");
        }
        let partition_table =
            PartitionTable::read_from_bytes(&image[..std::mem::size_of::<PartitionTable>()])
                .map_err(|_| anyhow!("Partition table not detected"))?;
        if !partition_table.verify_checksum(&StandAloneChecksumCalculator {}) {
            return Err(anyhow!("Partition table not detected"));
        }
        Ok(partition_table)
    }

    pub fn verify_flash_image(image: &[u8]) -> Result<()> {
        // Parse and verify header
        let header =
            FlashHeader::parse(image).map_err(|e| anyhow!("Invalid flash header: {e:?}"))?;
        let version = header.format().map_err(|e| anyhow!("{e:?}"))?;
        let table_end = header
            .table_end()
            .ok_or_else(|| anyhow!("Image table overflow"))?;
        if table_end > image.len() {
            bail!("Truncated image table");
        }

        // Parse and verify image info and data
        for i in 0..header.image_count as usize {
            let offset = header
                .image_header_offset(i)
                .ok_or_else(|| anyhow!("Image table overflow"))?;
            let info = ImageHeader::parse(&image[offset..], version)
                .map_err(|e| anyhow!("Invalid image entry: {e:?}"))?;
            let end = (info.offset as usize)
                .checked_add(info.size as usize)
                .ok_or_else(|| anyhow!("Image payload overflow"))?;
            if (info.offset as usize) < table_end || end > image.len() {
                bail!("Image payload outside valid range");
            }
            let image_checksum = calculate_checksum(&image[info.offset as usize..end]);
            if image_checksum != info.image_checksum {
                bail!(
                    "Image checksum mismatch for image with identifier: {}",
                    info.identifier
                );
            }
            println!("{:?}", info);
        }

        println!("Image is valid!");
        Ok(())
    }
}

pub use caliptra_mcu_flash_image::calculate_checksum;

fn load_file(filename: &str) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();

    // Open the file, map errors to a custom error message
    let mut file = File::open(filename)
        .map_err(|e| anyhow!(format!("Cannot open file '{}': {}", filename, e)))?;

    // Read the file into the buffer, map errors similarly
    file.read_to_end(&mut buffer)
        .map_err(|e| anyhow!(format!("Cannot read file '{}': {}", filename, e)))?;

    let padding = buffer.len().next_multiple_of(4) - buffer.len(); // Calculate padding size
    buffer.extend(vec![0; padding]); // Append padding bytes

    Ok(buffer)
}

use crate::CaliptraBuildArgs;

pub fn flash_image_create(args: &CaliptraBuildArgs) -> Result<()> {
    let version = FlashImageVersion::try_from(args.flash_image_version.unwrap_or(HEADER_VERSION))
        .map_err(|e| anyhow!("Invalid flash image format: {e:?}"))?;
    let caliptra_fw_path = &args.caliptra_firmware;
    let soc_manifest_path = &args.soc_manifest;
    let mcu_runtime_path = &args.mcu_firmware;
    let owner_auth_manifest_path = &args.owner_auth_manifest;
    let soc_image_paths = &args.soc_image_paths;
    let offset = args.offset;
    let output_path = args
        .output_path
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("output_path is required for flash_image_create"))?;

    let mut images: Vec<FirmwareImage> = Vec::new();

    let content;
    if let Some(caliptra_fw_path) = caliptra_fw_path {
        content = load_file(&caliptra_fw_path.to_string_lossy())?;
        images.push(FirmwareImage::new(
            CALIPTRA_FMC_RT_IDENTIFIER,
            &content,
            args.caliptra_firmware_network_filename
                .as_deref()
                .map(str::as_bytes),
        )?);
    }

    let content;
    if let Some(soc_manifest_path) = soc_manifest_path {
        content = load_file(&soc_manifest_path.to_string_lossy())?;
        images.push(FirmwareImage::new(
            SOC_MANIFEST_IDENTIFIER,
            &content,
            args.soc_manifest_network_filename
                .as_deref()
                .map(str::as_bytes),
        )?);
    }

    let content;
    if let Some(mcu_runtime_path) = mcu_runtime_path {
        content = load_file(&mcu_runtime_path.to_string_lossy())?;
        let filename = args
            .mcu_image_cfg
            .as_ref()
            .and_then(|config| config.network_filename.as_deref())
            .map(str::as_bytes);
        images.push(FirmwareImage::new(MCU_RT_IDENTIFIER, &content, filename)?);
    }

    let content;
    if let Some(owner_auth_manifest_path) = owner_auth_manifest_path {
        content = load_file(&owner_auth_manifest_path.to_string_lossy())?;
        images.push(FirmwareImage::new(
            OWNER_AUTH_MANIFEST_IDENTIFIER,
            &content,
            Some(b"owner-auth-manifest.bin"),
        )?);
    }

    let content;
    if let Some(owner_measurement_policy_path) = &args.owner_measurement_policy {
        content = load_file(&owner_measurement_policy_path.to_string_lossy())?;
        images.push(FirmwareImage::new(
            OWNER_MEASUREMENT_POLICY_IDENTIFIER,
            &content,
            Some(b"owner-measurement-policy.bin"),
        )?);
    }

    // Load SOC images into a buffer
    let mut soc_img_buffers: Vec<Vec<u8>> = Vec::new();
    if let Some(soc_image_paths) = soc_image_paths {
        for soc_image_path in soc_image_paths {
            let soc_image_data = load_file(soc_image_path)?; // Store the buffer
            soc_img_buffers.push(soc_image_data);
        }
    }

    // SoC TOC entries use component_id, matching runtime image lookup.
    for (i, soc_img) in soc_img_buffers.iter().enumerate() {
        let identifier = if let Some(ref soc_images) = args.soc_images {
            soc_images[i].component_id
        } else {
            SOC_IMAGES_BASE_IDENTIFIER + i as u32
        };
        let filename = args
            .soc_images
            .as_ref()
            .and_then(|images| images.get(i))
            .and_then(|config| config.network_filename.as_deref())
            .map(str::as_bytes);
        images.push(FirmwareImage::new(identifier, soc_img, filename)?);
    }

    let owner_soc_images = args.owner_soc_images.as_deref().unwrap_or(&[]);
    let owner_img_buffers = owner_soc_images
        .iter()
        .map(|image| load_file(&image.path.to_string_lossy()))
        .collect::<Result<Vec<_>>>()?;
    for (image, owner_img) in owner_soc_images.iter().zip(owner_img_buffers.iter()) {
        images.push(FirmwareImage::new(
            image.component_id,
            owner_img,
            image.network_filename.as_deref().map(str::as_bytes),
        )?);
    }

    if images.is_empty() || images.len() > u16::MAX as usize {
        bail!("Flash image must contain between 1 and {} images", u16::MAX);
    }
    let flash_image = FlashImage::with_version(&images, version);
    flash_image.write_to_file(offset, output_path)?;

    Ok(())
}

fn generate_legacy_image_info(
    images: &[FirmwareImage],
    version: FlashImageVersion,
) -> Vec<ImageHeaderV1V2> {
    let mut info = Vec::new();
    let mut offset =
        version.header_size() as u32 + (version.image_header_size() * images.len()) as u32;
    for image in images.iter() {
        let mut header = ImageHeaderV1V2 {
            identifier: image.identifier,
            offset,
            size: image.data.len() as u32,
            image_checksum: calculate_checksum(image.data),
            image_header_checksum: 0,
        };
        header.image_header_checksum = calculate_checksum(
            &header.as_bytes()[..offset_of!(ImageHeaderV1V2, image_header_checksum)],
        );
        info.push(header);
        offset += image.data.len() as u32;
    }
    info
}

/// Build a flash image from raw firmware data and return it as bytes.
///
/// This is useful for loading firmware to flash in the hardware model
/// instead of using the recovery interface.
pub fn build_flash_image_bytes(
    caliptra_fw: Option<&[u8]>,
    soc_manifest: Option<&[u8]>,
    mcu_runtime: Option<&[u8]>,
    owner_auth_manifest: Option<&[u8]>,
) -> Vec<u8> {
    fn pad_to_256_bytes(data: &[u8]) -> Vec<u8> {
        let padding = data.len().next_multiple_of(256) - data.len();
        let mut padded = data.to_vec();
        padded.extend(vec![0; padding]);
        padded
    }

    // Build padded copies of the firmware images
    let caliptra_fw_padded = caliptra_fw.map(pad_to_256_bytes);
    let soc_manifest_padded = soc_manifest.map(pad_to_256_bytes);
    let mcu_runtime_padded = mcu_runtime.map(pad_to_256_bytes);
    let owner_auth_manifest_padded = owner_auth_manifest.map(pad_to_256_bytes);

    let mut images: Vec<FirmwareImage> = Vec::new();

    if let Some(ref data) = caliptra_fw_padded {
        images.push(FirmwareImage {
            identifier: CALIPTRA_FMC_RT_IDENTIFIER,
            data,
            filename: [0u8; MAX_FILENAME_LEN],
        });
    }

    if let Some(ref data) = soc_manifest_padded {
        images.push(FirmwareImage {
            identifier: SOC_MANIFEST_IDENTIFIER,
            data,
            filename: [0u8; MAX_FILENAME_LEN],
        });
    }

    if let Some(ref data) = mcu_runtime_padded {
        images.push(FirmwareImage {
            identifier: MCU_RT_IDENTIFIER,
            data,
            filename: [0u8; MAX_FILENAME_LEN],
        });
    }

    if let Some(ref data) = owner_auth_manifest_padded {
        images.push(FirmwareImage {
            identifier: OWNER_AUTH_MANIFEST_IDENTIFIER,
            data,
            filename: [0u8; MAX_FILENAME_LEN],
        });
    }

    if images.is_empty() {
        return Vec::new();
    }

    let image_info = generate_image_info(images.clone());
    let flash_image = FlashImage::new(&images, &image_info);
    flash_image.to_bytes()
}

pub fn flash_image_verify(image_file_path: &str, offset: u32) -> Result<()> {
    let mut file = File::open(image_file_path).map_err(|e| {
        Error::new(
            ErrorKind::NotFound,
            format!("Failed to open file '{}': {}", image_file_path, e),
        )
    })?;

    let mut data = Vec::new();
    file.read_to_end(&mut data).map_err(|e| {
        Error::new(
            ErrorKind::InvalidData,
            format!("Failed to read file '{}': {}", image_file_path, e),
        )
    })?;
    file.read_to_end(&mut data)?;
    // Check if flash image has partition table
    match FlashImage::verify_flash_partition_table(&data[offset as usize..]) {
        Ok(partition_table) => {
            println!("Partition table found: {:?}", partition_table);
            println!("Partition A (offset {}):", IMAGE_A_PARTITION.offset);
            FlashImage::verify_flash_image(&data[IMAGE_A_PARTITION.offset..])?;
            println!("Partition B (offset {}):", IMAGE_B_PARTITION.offset);
            FlashImage::verify_flash_image(&data[IMAGE_B_PARTITION.offset..])
        }
        Err(_) => FlashImage::verify_flash_image(&data[offset as usize..]),
    }
}

pub fn write_partition_table(
    partition_table: &PartitionTable,
    offset: usize,
    filename: &str,
) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(filename)
        .map_err(|e| anyhow!(format!("Unable to open file {}: {}", filename, e)))?;

    // Seek to the specified offset before writing
    file.seek(std::io::SeekFrom::Start(offset as u64))
        .map_err(|e| {
            anyhow!(format!(
                "Unable to seek to offset {} in file {}: {}",
                offset, filename, e
            ))
        })?;
    file.write_all(partition_table.as_bytes())?;

    Ok(())
}

#[cfg(test)]
mod tests;
