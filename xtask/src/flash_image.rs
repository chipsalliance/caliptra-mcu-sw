// Licensed under the Apache-2.0 license

use anyhow::{anyhow, bail, Result};
use crc32fast::Hasher;
use std::fs::File;
use std::io::{self, Error, ErrorKind, Read, Write};
use zerocopy::{byteorder::U32, FromBytes, IntoBytes};
use zerocopy::{Immutable, KnownLayout};

const FLASH_IMAGE_MAGIC_NUMBER: u32 = u32::from_be_bytes(*b"FLSH");
const HEADER_VERSION: u16 = 0x0001;
const HEADER_SIZE: usize = std::mem::size_of::<FlashImageHeader>();
const CHECKSUM_SIZE: usize = std::mem::size_of::<FlashImageChecksum>();
const IMAGE_INFO_SIZE: usize = std::mem::size_of::<FlashImageInfo>();
const CALIPTRA_FMC_RT_IDENTIFIER: u32 = 0x00000001;
const SOC_MANIFEST_IDENTIFIER: u32 = 0x00000002;
const MCU_RT_IDENTIFIER: u32 = 0x00000002;
const SOC_IMAGES_BASE_IDENTIFIER: u32 = 0x00001000;

pub struct FlashImage<'a> {
    header: FlashImageHeader,
    checksum: FlashImageChecksum,
    payload: FlashImagePayload<'a>,
}

#[repr(C, packed)]
#[derive(IntoBytes, FromBytes, Immutable, KnownLayout)]
pub struct FlashImageHeader {
    magic_number: U32<zerocopy::byteorder::BigEndian>,
    header_version: u16,
    image_count: u16,
}

#[repr(C, packed)]
#[derive(IntoBytes, FromBytes, Immutable, KnownLayout)]
pub struct FlashImageChecksum {
    header: u32,
    payload: u32,
}

pub struct FlashImagePayload<'a> {
    image_info: &'a [FlashImageInfo],
    images: &'a [FirmwareImage<'a>],
}

#[repr(C, packed)]
#[derive(IntoBytes, FromBytes, Immutable)]
pub struct FlashImageInfo {
    identifier: u32,
    image_offset: u32, // Location of the image in the flash as an offset from the header
    size: u32,         // Size of the image
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
    pub fn new(images: &'a [FirmwareImage<'a>], image_info: &'a [FlashImageInfo]) -> Self {
        let header = FlashImageHeader {
            magic_number: FLASH_IMAGE_MAGIC_NUMBER.into(),
            header_version: HEADER_VERSION,
            image_count: image_info.len() as u16,
        };

        let payload = FlashImagePayload { image_info, images };

        let checksum = FlashImageChecksum::new(&header, &payload);

        Self {
            header,
            checksum,
            payload,
        }
    }

    pub fn write_to_file(&self, filename: &str) -> Result<()> {
        let mut file = File::create(filename)
            .map_err(|e| anyhow!(format!("Unable to create file {}: {}", filename, e)))?;
        file.write_all(self.header.as_bytes())?;
        file.write_all(self.checksum.as_bytes())?;
        for info in self.payload.image_info {
            file.write_all(info.as_bytes())?;
        }
        for image in self.payload.images {
            file.write_all(image.data)?;
        }

        Ok(())
    }

    pub fn verify_flash_image(image: &[u8]) -> Result<()> {
        // Parse and verify header
        if image.len() < HEADER_SIZE {
            bail!("Image too small to contain the header.");
        }
        let header = FlashImageHeader::read_from_bytes(&image[..HEADER_SIZE])
            .map_err(|_| anyhow!("Failed to parse header: invalid format or size"))?;
        if header.magic_number != FLASH_IMAGE_MAGIC_NUMBER {
            bail!("Invalid header: incorrect magic number or header version.");
        }

        if header.header_version != HEADER_VERSION {
            bail!("Unsupported header version");
        }

        if header.image_count < 3 {
            bail!("Expected at least 3 images");
        }

        // Parse and verify checksums
        let checksum =
            FlashImageChecksum::read_from_bytes(&image[HEADER_SIZE..(HEADER_SIZE + CHECKSUM_SIZE)])
                .map_err(|_| anyhow!("Failed to parse checksum field"))?;
        let calculated_header_checksum = calculate_checksum(header.as_bytes());
        let calculated_payload_checksum = calculate_checksum(&image[16..]);

        if checksum.header != calculated_header_checksum {
            bail!("Header checksum mismatch.");
        }

        if checksum.payload != calculated_payload_checksum {
            bail!("Payload checksum mismatch.");
        }

        // Parse and verify image info and data
        for i in 0..header.image_count as usize {
            let offset = HEADER_SIZE + CHECKSUM_SIZE + (IMAGE_INFO_SIZE * i);
            let info = FlashImageInfo::read_from_bytes(&image[offset..offset + IMAGE_INFO_SIZE])
                .map_err(|_| anyhow!("Failed to read image info"))?;
            match i {
                0 => {
                    if info.identifier != CALIPTRA_FMC_RT_IDENTIFIER {
                        bail!("Image 0 is not Caliptra Identifier");
                    }
                }
                1 => {
                    if info.identifier != SOC_MANIFEST_IDENTIFIER {
                        bail!("Image 0 is not SOC Manifest Identifier");
                    }
                }
                2 => {
                    if info.identifier != MCU_RT_IDENTIFIER {
                        bail!("Image 0 is not MCU RT Identifier");
                    }
                }
                3..255 => {
                    if info.identifier != (SOC_IMAGES_BASE_IDENTIFIER + (i as u32) - 3) {
                        bail!("Invalid SOC image identifier");
                    }
                }
                _ => bail!("Invalid image identifier"),
            }
        }

        println!("Image is valid!");
        Ok(())
    }
}

pub fn calculate_checksum(data: &[u8]) -> u32 {
    let mut hasher = Hasher::new();
    hasher.update(data);
    hasher.finalize()
}

impl FlashImagePayload<'_> {
    pub fn calculate_checksum(&self) -> u32 {
        let mut hasher = Hasher::new();
        for info in self.image_info {
            hasher.update(info.as_bytes());
        }
        for image in self.images {
            hasher.update(image.data);
        }
        hasher.finalize()
    }
}

impl FlashImageChecksum {
    pub fn new(header: &FlashImageHeader, payload: &FlashImagePayload) -> Self {
        Self {
            header: calculate_checksum(header.as_bytes()),
            payload: payload.calculate_checksum(),
        }
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

pub(crate) fn flash_image_create(
    caliptra_fw_path: &str,
    soc_manifest_path: &str,
    mcu_runtime_path: &str,
    soc_image_paths: &Option<Vec<String>>,
    output_path: &str,
) -> Result<()> {
    let mut images: Vec<FirmwareImage> = Vec::new();

    let content = load_file(caliptra_fw_path)?;
    images.push(FirmwareImage::new(CALIPTRA_FMC_RT_IDENTIFIER, &content)?);

    let content = load_file(soc_manifest_path)?;
    images.push(FirmwareImage::new(SOC_MANIFEST_IDENTIFIER, &content)?);

    let content = load_file(mcu_runtime_path)?;
    images.push(FirmwareImage::new(MCU_RT_IDENTIFIER, &content)?);

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
    flash_image.write_to_file(output_path)?;

    Ok(())
}

pub fn generate_image_info(images: Vec<FirmwareImage>) -> Vec<FlashImageInfo> {
    let mut info = Vec::new();
    let mut offset = std::mem::size_of::<FlashImageHeader>() as u32
        + std::mem::size_of::<FlashImageChecksum>() as u32
        + (std::mem::size_of::<FlashImageInfo>() * images.len()) as u32;
    for image in images.iter() {
        info.push(FlashImageInfo {
            identifier: image.identifier,
            image_offset: offset,
            size: image.data.len() as u32,
        });
        offset += image.data.len() as u32;
    }
    info
}

pub(crate) fn flash_image_verify(image_file_path: &str) -> Result<()> {
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
    FlashImage::verify_flash_image(&data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcu_builder::PROJECT_ROOT;
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
        let output_path = PROJECT_ROOT
            .join("target")
            .join("tmp")
            .join("flash_image.bin");
        let output_path = output_path.to_str().unwrap();

        // Build the flash image
        flash_image_create(
            caliptra_fw.path().to_str().unwrap(),
            soc_manifest.path().to_str().unwrap(),
            mcu_runtime.path().to_str().unwrap(),
            &soc_image_paths,
            output_path,
        )
        .expect("Failed to build flash image");

        // Read and verify the generated flash image
        let mut file = File::open(output_path).expect("Failed to open generated flash image");
        let mut data = Vec::new();

        file.read_to_end(&mut data)
            .expect("Failed to read flash image");

        // Verify header
        let magic_number = u32::from_be_bytes(data[0..4].try_into().unwrap());
        let header_version = u16::from_le_bytes(data[4..6].try_into().unwrap());
        let image_count = u16::from_le_bytes(data[6..8].try_into().unwrap());

        assert_eq!(magic_number, FLASH_IMAGE_MAGIC_NUMBER);
        assert_eq!(header_version, HEADER_VERSION);
        assert_eq!(image_count, 5); // 3 main images + 2 SoC images

        // Verify checksums
        let header_checksum = u32::from_le_bytes(data[8..12].try_into().unwrap());
        let payload_checksum = u32::from_le_bytes(data[12..16].try_into().unwrap());
        let calculated_header_checksum = calculate_checksum(&data[0..8]);
        let calculated_payload_checksum = calculate_checksum(&data[16..]);
        assert_eq!(header_checksum, calculated_header_checksum);
        assert_eq!(payload_checksum, calculated_payload_checksum);

        let expected_images: Vec<(u32, &[u8])> = vec![
            (CALIPTRA_FMC_RT_IDENTIFIER, caliptra_fw_content),
            (SOC_MANIFEST_IDENTIFIER, soc_manifest_content),
            (MCU_RT_IDENTIFIER, mcu_runtime_content),
            (SOC_IMAGES_BASE_IDENTIFIER, soc_image1_content),
            (SOC_IMAGES_BASE_IDENTIFIER + 1, soc_image2_content),
        ];
        let mut image_offsets = Vec::new();

        for (i, _item) in expected_images
            .iter()
            .enumerate()
            .take(image_count as usize)
        {
            let offset = std::mem::size_of::<FlashImageHeader>()
                + std::mem::size_of::<FlashImageChecksum>()
                + (std::mem::size_of::<FlashImageInfo>() * i);
            let identifier = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
            let image_offset = u32::from_le_bytes(data[offset + 4..offset + 8].try_into().unwrap());
            let size = u32::from_le_bytes(data[offset + 8..offset + 12].try_into().unwrap());

            // Verify identifier and size
            assert_eq!(identifier, expected_images[i].0);
            assert_eq!(
                size as usize,
                expected_images[i].1.len().next_multiple_of(4)
            );

            image_offsets.push((image_offset as usize, size as usize));
        }

        // Verify image data using offsets
        for (i, (start_offset, _size)) in image_offsets.iter().enumerate() {
            let actual_data = &data[*start_offset..*start_offset + expected_images[i].1.len()];
            assert_eq!(actual_data, expected_images[i].1);
        }
    }

    #[test]
    fn test_flash_image_verify_happy_path() {
        let image_path = PROJECT_ROOT
            .join("target")
            .join("tmp")
            .join("flash_image_happy_path.bin");
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
            .write_to_file(image_path)
            .expect("Failed to write flash image");

        // Verify the firmware image
        let result = flash_image_verify(image_path);
        result.unwrap_or_else(|e| {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        });

        // Cleanup
        fs::remove_file(image_path).expect("Failed to clean up test file");
    }

    #[test]
    fn test_flash_image_verify_corrupted_case() {
        let image_path = PROJECT_ROOT
            .join("target")
            .join("tmp")
            .join("flash_image_corrupted.bin");
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
            .write_to_file(image_path)
            .expect("Failed to write flash image");

        // Corrupt the file by modifying the data
        let mut file = File::options()
            .write(true)
            .open(image_path)
            .expect("Failed to open firmware image for tampering");
        file.write_all(b"Corrupted Data")
            .expect("Failed to corrupt data");

        // Verify the corrupted firmware image
        let result = flash_image_verify(image_path);
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
