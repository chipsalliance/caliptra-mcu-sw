// Licensed under the Apache-2.0 license

use anyhow::{anyhow, bail, Result};
use flash_image::{
    FlashHeader, ImageHeader, CALIPTRA_FMC_RT_IDENTIFIER, FLASH_IMAGE_MAGIC_NUMBER, HEADER_VERSION,
    MCU_RT_IDENTIFIER, SOC_IMAGES_BASE_IDENTIFIER, SOC_MANIFEST_IDENTIFIER,
};
use mcu_config_emulator::flash::{
    PartitionTable, StandAloneChecksumCalculator, IMAGE_A_PARTITION, IMAGE_B_PARTITION,
};
use std::fs::{File, OpenOptions};
use std::io::{self, Error, ErrorKind, Read, Seek, Write};
use std::mem::offset_of;
use zerocopy::{FromBytes, IntoBytes};

const HEADER_SIZE: usize = std::mem::size_of::<FlashHeader>();
const IMAGE_INFO_SIZE: usize = std::mem::size_of::<ImageHeader>();

pub struct FlashImage<'a> {
    header: FlashHeader,
    payload: FlashImagePayload<'a>,
}

pub struct FlashImagePayload<'a> {
    image_info: &'a [ImageHeader],
    images: &'a [FirmwareImage<'a>],
}
#[derive(Clone)]
pub struct FirmwareImage<'a> {
    pub identifier: u32,
    pub data: &'a [u8],
}

impl<'a> FirmwareImage<'a> {
    pub fn new(identifier: u32, content: &'a [u8]) -> io::Result<Self> {
        Ok(Self {
            identifier,
            data: content,
        })
    }
}

impl<'a> FlashImage<'a> {
    pub fn new(images: &'a [FirmwareImage<'a>], image_info: &'a [ImageHeader]) -> Self {
        let mut header = FlashHeader {
            magic: FLASH_IMAGE_MAGIC_NUMBER.into(),
            version: HEADER_VERSION,
            image_count: image_info.len() as u16,
            image_headers_offset: core::mem::size_of::<FlashHeader>() as u32,
            header_checksum: 0,
        };

        let header_checksum = calculate_checksum(
            header.as_bytes()[..offset_of!(FlashHeader, header_checksum)].as_ref(),
        );
        header.header_checksum = header_checksum;
        let payload = FlashImagePayload::new(image_info, images);

        Self { header, payload }
    }

    /// Convert the flash image to a byte vector
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.header.as_bytes());
        for info in self.payload.image_info {
            bytes.extend_from_slice(info.as_bytes());
        }
        for image in self.payload.images {
            bytes.extend_from_slice(image.data);
        }
        bytes
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
        file.write_all(self.header.as_bytes())?;
        for info in self.payload.image_info {
            file.write_all(info.as_bytes())?;
        }
        for image in self.payload.images {
            file.write_all(image.data)?;
        }

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
        if image.len() < HEADER_SIZE {
            bail!("Image too small to contain the header.");
        }
        let header = FlashHeader::read_from_bytes(&image[..HEADER_SIZE])
            .map_err(|_| anyhow!("Failed to parse header: invalid format or size"))?;
        if header.magic != FLASH_IMAGE_MAGIC_NUMBER {
            bail!("Invalid header: incorrect magic number or header version.");
        }

        if header.version != HEADER_VERSION {
            bail!("Unsupported header version");
        }
        // Parse and verify checksums
        let calculated_header_checksum = calculate_checksum(
            header.as_bytes()[..offset_of!(FlashHeader, header_checksum)].as_ref(),
        );
        if calculated_header_checksum != header.header_checksum {
            bail!("Header checksum mismatch.");
        }

        // Parse and verify image info and data
        for i in 0..header.image_count as usize {
            let offset = header.image_headers_offset as usize + (IMAGE_INFO_SIZE * i);
            let info = ImageHeader::read_from_bytes(&image[offset..offset + IMAGE_INFO_SIZE])
                .map_err(|_| anyhow!("Failed to read image info"))?;
            let image_checksum = calculate_checksum(
                &image[info.offset as usize..info.offset as usize + info.size as usize],
            );
            if image_checksum != info.image_checksum {
                bail!(
                    "Image checksum mismatch for image with identifier: {}",
                    info.identifier
                );
            }
            let header_checksum = calculate_checksum(
                info.as_bytes()[..offset_of!(ImageHeader, image_header_checksum)].as_ref(),
            );
            if header_checksum != info.image_header_checksum {
                bail!(
                    "Image header checksum mismatch for image with identifier: {}",
                    info.identifier
                );
            }
            println!("{:?}", info);
        }

        println!("Image is valid!");
        Ok(())
    }
}

pub fn calculate_checksum(data: &[u8]) -> u32 {
    let sum = data
        .iter()
        .fold(0u32, |acc, &byte| acc.wrapping_add(byte as u32));
    0u32.wrapping_sub(sum)
}

impl<'a> FlashImagePayload<'a> {
    pub fn new(image_info: &'a [ImageHeader], images: &'a [FirmwareImage<'a>]) -> Self {
        Self { image_info, images }
    }
}

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

pub fn flash_image_create(
    caliptra_fw_path: &Option<String>,
    soc_manifest_path: &Option<String>,
    mcu_runtime_path: &Option<String>,
    soc_image_paths: &Option<Vec<String>>,
    offset: usize,
    output_path: &str,
) -> Result<()> {
    let mut images: Vec<FirmwareImage> = Vec::new();

    let content;
    if let Some(caliptra_fw_path) = caliptra_fw_path {
        content = load_file(caliptra_fw_path)?;
        images.push(FirmwareImage::new(CALIPTRA_FMC_RT_IDENTIFIER, &content)?);
    }

    let content;
    if let Some(soc_manifest_path) = soc_manifest_path {
        content = load_file(soc_manifest_path)?;
        images.push(FirmwareImage::new(SOC_MANIFEST_IDENTIFIER, &content)?);
    }

    let content;
    if let Some(mcu_runtime_path) = mcu_runtime_path {
        content = load_file(mcu_runtime_path)?;
        images.push(FirmwareImage::new(MCU_RT_IDENTIFIER, &content)?);
    }

    // Load SOC images into a buffer
    let mut soc_img_buffers: Vec<Vec<u8>> = Vec::new();
    if let Some(soc_image_paths) = soc_image_paths {
        for soc_image_path in soc_image_paths {
            let soc_image_data = load_file(soc_image_path)?; // Store the buffer
            soc_img_buffers.push(soc_image_data);
        }
    }

    // Generate FirmwareImage from soc image buffer
    let mut soc_image_identifer = SOC_IMAGES_BASE_IDENTIFIER;
    for soc_img in soc_img_buffers.iter() {
        images.push(FirmwareImage::new(soc_image_identifer, soc_img)?);
        soc_image_identifer += 1;
    }

    let image_info = generate_image_info(images.clone());

    let flash_image = FlashImage::new(&images, &image_info);
    flash_image.write_to_file(offset, output_path)?;

    Ok(())
}

pub fn generate_image_info(images: Vec<FirmwareImage>) -> Vec<ImageHeader> {
    let mut info = Vec::new();
    let mut offset = std::mem::size_of::<FlashHeader>() as u32
        + (std::mem::size_of::<ImageHeader>() * images.len()) as u32;
    for image in images.iter() {
        let mut header = ImageHeader {
            identifier: image.identifier,
            offset,
            size: image.data.len() as u32,
            image_checksum: calculate_checksum(image.data),
            image_header_checksum: 0,
        };
        header.image_header_checksum = calculate_checksum(
            header.as_bytes()[..offset_of!(ImageHeader, image_header_checksum)].as_ref(),
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

    let mut images: Vec<FirmwareImage> = Vec::new();

    if let Some(ref data) = caliptra_fw_padded {
        images.push(FirmwareImage {
            identifier: CALIPTRA_FMC_RT_IDENTIFIER,
            data,
        });
    }

    if let Some(ref data) = soc_manifest_padded {
        images.push(FirmwareImage {
            identifier: SOC_MANIFEST_IDENTIFIER,
            data,
        });
    }

    if let Some(ref data) = mcu_runtime_padded {
        images.push(FirmwareImage {
            identifier: MCU_RT_IDENTIFIER,
            data,
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
mod tests {
    use super::*;
    use crate::PROJECT_ROOT;
    use std::fs::{self, File};
    use std::io::Write;
    use tempfile::NamedTempFile;

    /// Helper function to create a temporary file with specific content
    fn create_temp_file(content: &[u8]) -> io::Result<NamedTempFile> {
        let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");

        temp_file
            .write_all(content)
            .expect("Failed to write to temp file");
        Ok(temp_file)
    }

    #[test]
    fn test_flash_image_build() {
        // Generate test contents for temporary files
        let caliptra_fw_content = b"Caliptra Firmware Data - ABCDEFGH";
        let soc_manifest_content = b"Soc Manifest Data - 123456789";
        let mcu_runtime_content = b"MCU Runtime Data - QWERTYUI";
        let soc_image1_content = b"Soc Image 1 Data - ZXCVBNMLKJ";
        let soc_image2_content = b"Soc Image 2 Data - POIUYTREWQ";

        // Create temporary files with the generated content
        let caliptra_fw =
            create_temp_file(caliptra_fw_content).expect("Failed to create caliptra_fw");
        let soc_manifest =
            create_temp_file(soc_manifest_content).expect("Failed to create soc_manifest");
        let mcu_runtime =
            create_temp_file(mcu_runtime_content).expect("Failed to create mcu_runtime");
        let soc_image1 = create_temp_file(soc_image1_content).expect("Failed to create soc_image1");
        let soc_image2 = create_temp_file(soc_image2_content).expect("Failed to create soc_image2");

        // Collect SoC image paths
        let soc_image_paths = Some(vec![
            soc_image1.path().to_str().unwrap().to_string(),
            soc_image2.path().to_str().unwrap().to_string(),
        ]);

        // Specify the output file path
        let output_file = NamedTempFile::new().expect("Failed to create temp file");
        let output_path = output_file.path().to_str().unwrap();

        // Build the flash image
        flash_image_create(
            &Some(caliptra_fw.path().to_str().unwrap().to_string()),
            &Some(soc_manifest.path().to_str().unwrap().to_string()),
            &Some(mcu_runtime.path().to_str().unwrap().to_string()),
            &soc_image_paths,
            0,
            output_path,
        )
        .expect("Failed to build flash image");

        // Read and verify the generated flash image
        let mut file = File::open(output_path).expect("Failed to open generated flash image");
        let mut data = Vec::new();

        file.read_to_end(&mut data)
            .expect("Failed to read flash image");

        // Verify header
        let header = FlashHeader::read_from_bytes(&data[..HEADER_SIZE])
            .expect("Failed to parse flash header");

        assert_eq!(header.magic, FLASH_IMAGE_MAGIC_NUMBER);
        assert_eq!(header.version, HEADER_VERSION);
        assert_eq!(header.image_count, 5); // 3 main images + 2 SoC images

        // Verify checksums
        let calculated_header_checksum =
            calculate_checksum(&data[0..offset_of!(FlashHeader, header_checksum)]);
        assert_eq!(header.header_checksum, calculated_header_checksum);

        let expected_images: Vec<(u32, &[u8])> = vec![
            (CALIPTRA_FMC_RT_IDENTIFIER, caliptra_fw_content),
            (SOC_MANIFEST_IDENTIFIER, soc_manifest_content),
            (MCU_RT_IDENTIFIER, mcu_runtime_content),
            (SOC_IMAGES_BASE_IDENTIFIER, soc_image1_content),
            (SOC_IMAGES_BASE_IDENTIFIER + 1, soc_image2_content),
        ];
        let mut image_headers = Vec::new();

        for (i, _item) in expected_images
            .iter()
            .enumerate()
            .take(header.image_count as usize)
        {
            let offset =
                header.image_headers_offset as usize + (std::mem::size_of::<ImageHeader>() * i);
            let image_header =
                ImageHeader::read_from_bytes(&data[offset..offset + IMAGE_INFO_SIZE])
                    .expect("Failed to read image header");

            // Verify identifier and size
            assert_eq!(image_header.identifier, expected_images[i].0);
            assert_eq!(
                image_header.size as usize,
                expected_images[i].1.len().next_multiple_of(4)
            );

            image_headers.push(image_header);
        }

        // Verify image data using offsets
        for (i, header) in image_headers.iter().enumerate() {
            let actual_data =
                &data[header.offset as usize..header.offset as usize + header.size as usize];
            assert_eq!(
                &actual_data[..expected_images[i].1.len()],
                expected_images[i].1
            );
        }
    }

    #[test]
    fn test_flash_image_verify_happy_path() {
        let tmp_dir = PROJECT_ROOT.join("target").join("tmp");
        fs::create_dir_all(&tmp_dir).expect("Failed to create tmp directory");
        let image_path = tmp_dir.join("flash_image_happy_path.bin");
        let image_path = image_path.to_str().unwrap();

        // Create a valid firmware image
        let expected_images = [
            FirmwareImage {
                identifier: CALIPTRA_FMC_RT_IDENTIFIER,
                data: b"Caliptra Firmware Data - ABCDEFGH",
            },
            FirmwareImage {
                identifier: SOC_MANIFEST_IDENTIFIER,
                data: b"Soc Manifest Data - 123456789",
            },
            FirmwareImage {
                identifier: MCU_RT_IDENTIFIER,
                data: b"MCU Runtime Data - QWERTYUI",
            },
            FirmwareImage {
                identifier: SOC_IMAGES_BASE_IDENTIFIER,
                data: b"Soc Image 1 Data - ZXCVBNMLKJ",
            },
            FirmwareImage {
                identifier: SOC_IMAGES_BASE_IDENTIFIER + 1,
                data: b"Soc Image 2 Data - POIUYTREWQ",
            },
        ];
        // Create a flash image from the mutable slice
        let image_info = generate_image_info(expected_images.to_vec());
        let flash_image = FlashImage::new(&expected_images, &image_info);
        flash_image
            .write_to_file(0, image_path)
            .expect("Failed to write flash image");

        // Verify the firmware image
        let result = flash_image_verify(image_path, 0);
        result.unwrap_or_else(|e| {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        });

        // Cleanup
        fs::remove_file(image_path).expect("Failed to clean up test file");
    }

    #[test]
    fn test_flash_image_verify_corrupted_case() {
        let tmp_dir = PROJECT_ROOT.join("target").join("tmp");
        fs::create_dir_all(&tmp_dir).expect("Failed to create tmp directory");
        let image_path = tmp_dir.join("flash_image_corrupted.bin");
        let image_path = image_path.to_str().unwrap();

        // Create a corrupted firmware image (tamper with the header or data)
        let images = [
            FirmwareImage {
                identifier: CALIPTRA_FMC_RT_IDENTIFIER,
                data: b"Valid Caliptra Firmware Data",
            },
            FirmwareImage {
                identifier: SOC_MANIFEST_IDENTIFIER,
                data: b"Valid SOC Manifest Data",
            },
        ];
        let image_info = generate_image_info(images.to_vec());
        let flash_image = FlashImage::new(&images, &image_info);
        flash_image
            .write_to_file(0, image_path)
            .expect("Failed to write flash image");

        // Corrupt the file by modifying the data
        let mut file = File::options()
            .write(true)
            .open(image_path)
            .expect("Failed to open firmware image for tampering");
        file.write_all(b"Corrupted Data")
            .expect("Failed to corrupt data");

        // Verify the corrupted firmware image
        let result = flash_image_verify(image_path, 0);
        assert!(
            result.is_err(),
            "Expected verification to fail for corrupted firmware image"
        );

        if let Err(e) = result {
            println!("Expected error: {}", e);
        }

        // Cleanup
        fs::remove_file(image_path).expect("Failed to clean up test file");
    }
}
