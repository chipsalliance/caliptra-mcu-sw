// Licensed under the Apache-2.0 license

use crate::DynError;
use crc32fast::Hasher;
use std::fs::File;
use std::io::{self, Read, Write};
use std::io::{Error, ErrorKind};

const FLASH_IMAGE_MAGIC_NUMBER: u32 = 0x464C5348;
const HEADER_VERSION: u16 = 0x0001;
const CALIPTRA_FMC_RT_IDENTIFIER: u32 = 0x00000001;
const SOC_MANIFEST_IDENTIFIER: u32 = 0x00000002;
const MCU_RT_IDENTIFIER: u32 = 0x00000002;
const SOC_IMAGES_BASE_IDENTIFIER: u32 = 0x00001000;

pub struct FlashImage {
    header: FlashImageHeader,
    checksum: FlashImageChecksum,
    payload: FlashImagePayload,
}

pub struct FlashImageHeader {
    magic_number: u32,
    header_version: u16,
    image_count: u16, // number of images
}

pub struct FlashImageChecksum {
    header: u32,  // checksum of the header
    payload: u32, // checksum of the payload
}

pub struct FlashImagePayload {
    image_info: Vec<FlashImageInfo>,
    images: Vec<FirmwareImage>,
}

// Per image header
pub struct FlashImageInfo {
    identifier: u32,
    image_offset: u32, // Location of the image in the flash as an offset from the header
    size: u32,         // Size of the image
}

#[derive(Clone)]
pub struct FirmwareImage {
    identifier: u32,
    data: Vec<u8>,
}

impl FirmwareImage {
    pub fn new(identifier: u32, filename: &str) -> io::Result<Self> {
        let mut file = File::open(filename)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;

        Ok(Self { identifier, data })
    }
}

impl FlashImage {
    pub fn new(images: &mut [FirmwareImage]) -> Self {
        let mut image_info = Vec::new();
        let mut offset = std::mem::size_of::<FlashImageHeader>() as u32
            + std::mem::size_of::<FlashImageChecksum>() as u32
            + (std::mem::size_of::<FlashImageInfo>() * images.len()) as u32;

        for image in images.iter_mut() {
            let image_size = image.data.len() as u32;
            Self::align_to_4_bytes(&mut image.data);
            let padded_size = image.data.len() as u32;
            image_info.push(FlashImageInfo {
                identifier: image.identifier,
                image_offset: offset,
                size: image_size,
            });
            offset += padded_size;
        }

        let header = FlashImageHeader {
            magic_number: FLASH_IMAGE_MAGIC_NUMBER,
            header_version: HEADER_VERSION,
            image_count: image_info.len() as u16,
        };

        let payload = FlashImagePayload {
            image_info,
            images: images.to_owned(),
        };

        let checksum = FlashImageChecksum::new(&header, &payload);

        Self {
            header,
            checksum,
            payload,
        }
    }

    fn align_to_4_bytes(data: &mut Vec<u8>) {
        let padding = data.len().next_multiple_of(4) - data.len();
        data.extend(vec![0; padding]);
    }

    pub fn write_to_file(&self, filename: &str) -> io::Result<()> {
        let mut file = File::create(filename)?;

        // Write header
        file.write_all(&self.header.magic_number.to_le_bytes())?;
        file.write_all(&self.header.header_version.to_le_bytes())?;
        file.write_all(&self.header.image_count.to_le_bytes())?;

        // Write checksums
        file.write_all(&self.checksum.header.to_le_bytes())?;
        file.write_all(&self.checksum.payload.to_le_bytes())?;

        // Write image info
        for info in &self.payload.image_info {
            file.write_all(&info.identifier.to_le_bytes())?;
            file.write_all(&info.image_offset.to_le_bytes())?;
            file.write_all(&info.size.to_le_bytes())?;
        }

        // Write images
        for image in &self.payload.images {
            file.write_all(&image.data)?;
        }

        Ok(())
    }

    pub fn verify_flash_image(image: &[u8]) -> Result<(), DynError> {
        // Parse and verify header
        let magic_number = u32::from_le_bytes(image[0..4].try_into().unwrap());
        let header_version = u16::from_le_bytes(image[4..6].try_into().unwrap());
        let image_count = u16::from_le_bytes(image[6..8].try_into().unwrap());

        if magic_number != FLASH_IMAGE_MAGIC_NUMBER {
            // Return error
            return Err("Invalid header: incorrect magic number or header version.")?;
        }

        if header_version != HEADER_VERSION {
            return Err("Unsupported header version")?;
        }

        if image_count < 3 {
            return Err("Expected at least 3 images")?;
        }

        // Parse and verify checksums
        let header_checksum = u32::from_le_bytes(image[8..12].try_into().unwrap());
        let payload_checksum = u32::from_le_bytes(image[12..16].try_into().unwrap());
        let calculated_header_checksum = FlashImageChecksum::calculate_checksum(&image[0..8]);
        let calculated_payload_checksum = FlashImageChecksum::calculate_checksum(&image[16..]);

        if header_checksum != calculated_header_checksum {
            return Err("Header checksum mismatch.")?;
        }

        if payload_checksum != calculated_payload_checksum {
            return Err("Payload checksum mismatch.")?;
        }

        // Parse and verify image info and data
        let mut offset = 16; // Start after header and checksums

        for i in 0..image_count as usize {
            let identifier = u32::from_le_bytes(image[offset..offset + 4].try_into().unwrap());
            match i {
                0 => {
                    if identifier != CALIPTRA_FMC_RT_IDENTIFIER {
                        return Err("Image 0 is not Caliptra Identifier")?;
                    }
                }
                1 => {
                    if identifier != SOC_MANIFEST_IDENTIFIER {
                        return Err("Image 0 is not SOC Manifest Identifier")?;
                    }
                }
                2 => {
                    if identifier != MCU_RT_IDENTIFIER {
                        return Err("Image 0 is not MCU RT Identifier")?;
                    }
                }
                3..255 => {
                    if identifier != (SOC_IMAGES_BASE_IDENTIFIER + (i as u32) - 3) {
                        return Err("Invalid SOC image identifier")?;
                    }
                }
                _ => return Err("Invalid image identifier")?,
            }

            offset += 12;
        }

        println!("Image is valid!");
        Ok(())
    }
}

impl FlashImageHeader {
    fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&self.magic_number.to_le_bytes());
        buffer.extend_from_slice(&self.header_version.to_le_bytes());
        buffer.extend_from_slice(&self.image_count.to_le_bytes());
        buffer
    }
}

impl FlashImagePayload {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        for info in &self.image_info {
            buffer.extend_from_slice(&info.identifier.to_le_bytes());
            buffer.extend_from_slice(&info.image_offset.to_le_bytes());
            buffer.extend_from_slice(&info.size.to_le_bytes());
        }
        for image in &self.images {
            buffer.extend_from_slice(&image.data);
        }
        buffer
    }
}

impl FlashImageChecksum {
    pub fn new(header: &FlashImageHeader, payload: &FlashImagePayload) -> Self {
        Self {
            header: Self::calculate_checksum(&header.serialize()),
            payload: Self::calculate_checksum(&payload.serialize()),
        }
    }
    pub fn calculate_checksum(data: &[u8]) -> u32 {
        let mut hasher = Hasher::new();
        hasher.update(data);
        hasher.finalize()
    }
}

pub(crate) fn flash_image_create(
    caliptra_fw_path: &str,
    soc_manifest_path: &str,
    mcu_runtime_path: &str,
    soc_image_paths: &Option<Vec<String>>,
    output_path: &str,
) -> Result<(), DynError> {
    let mut images: Vec<FirmwareImage> = Vec::new();
    images.push(FirmwareImage::new(
        CALIPTRA_FMC_RT_IDENTIFIER,
        caliptra_fw_path,
    )?);
    images.push(FirmwareImage::new(
        SOC_MANIFEST_IDENTIFIER,
        soc_manifest_path,
    )?);
    images.push(FirmwareImage::new(MCU_RT_IDENTIFIER, mcu_runtime_path)?);
    if let Some(soc_image_paths) = soc_image_paths {
        let mut soc_image_identifer = SOC_IMAGES_BASE_IDENTIFIER;
        for soc_image_path in soc_image_paths {
            images.push(FirmwareImage::new(soc_image_identifer, soc_image_path)?);
            soc_image_identifer += 1;
        }
    }

    let flash_image = FlashImage::new(&mut images);
    flash_image.write_to_file(output_path)?;

    Ok(())
}

pub(crate) fn flash_image_verify(image_file_path: &str) -> Result<(), DynError> {
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
    use crate::PROJECT_ROOT;
    use std::fs::{self, File};
    use std::io::Write;

    /// Helper function to create a temporary file with specific content
    fn create_temp_file(content: &[u8], file_name: &str) -> io::Result<String> {
        let tmp_directory = PROJECT_ROOT.join("target").join("tmp");
        fs::create_dir_all(tmp_directory.clone())?;
        let path = tmp_directory.join(file_name);
        let mut file = File::create(&path).expect("Failed to create temp file");
        file.write_all(content)
            .expect("Failed to write to temp file");
        Ok(String::from(path.to_str().unwrap()))
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
        let caliptra_fw_path = create_temp_file(caliptra_fw_content, "caliptra_fw.bin")
            .expect("Failed to create caliptra_fw.bin");
        let soc_manifest_path = create_temp_file(soc_manifest_content, "soc_manifest.bin")
            .expect("Failed to create soc_manifest.bin");
        let mcu_runtime_path = create_temp_file(mcu_runtime_content, "mcu_runtime.bin")
            .expect("Failed to create mcu_runtime.bin");
        let soc_image1_path = create_temp_file(soc_image1_content, "soc_image1.bin")
            .expect("Failed to create soc_image1.bin");
        let soc_image2_path = create_temp_file(soc_image2_content, "soc_image2.bin")
            .expect("Failed to create soc_image2.bin");

        // Collect SoC image paths
        let soc_image_paths = Some(vec![soc_image1_path.clone(), soc_image2_path.clone()]);

        // Specify the output file path
        let output_path = PROJECT_ROOT
            .join("target")
            .join("tmp")
            .join("flash_image.bin");
        let output_path = output_path.to_str().unwrap();

        // Build the flash image
        flash_image_create(
            &caliptra_fw_path,
            &soc_manifest_path,
            &mcu_runtime_path,
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
        let magic_number = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let header_version = u16::from_le_bytes(data[4..6].try_into().unwrap());
        let image_count = u16::from_le_bytes(data[6..8].try_into().unwrap());

        assert_eq!(magic_number, FLASH_IMAGE_MAGIC_NUMBER);
        assert_eq!(header_version, HEADER_VERSION);
        assert_eq!(image_count, 5); // 3 main images + 2 SoC images

        // Verify checksums
        let header_checksum = u32::from_le_bytes(data[8..12].try_into().unwrap());
        let payload_checksum = u32::from_le_bytes(data[12..16].try_into().unwrap());
        let calculated_header_checksum = FlashImageChecksum::calculate_checksum(&data[0..8]);
        let calculated_payload_checksum = FlashImageChecksum::calculate_checksum(&data[16..]);
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
        let mut offset = 16; // Start after header and checksums

        for i in 0..image_count as usize {
            let identifier = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
            let image_offset = u32::from_le_bytes(data[offset + 4..offset + 8].try_into().unwrap());
            let size = u32::from_le_bytes(data[offset + 8..offset + 12].try_into().unwrap());

            // Verify identifier and size
            assert_eq!(identifier, expected_images[i].0);
            assert_eq!(size as usize, expected_images[i].1.len());

            image_offsets.push((image_offset as usize, size as usize));
            offset += 12;
        }

        // Verify image data using offsets
        for (i, (start_offset, size)) in image_offsets.iter().enumerate() {
            let actual_data = &data[*start_offset..*start_offset + size];
            assert_eq!(actual_data, expected_images[i].1);
        }

        // Cleanup temporary files
        fs::remove_file(caliptra_fw_path).unwrap();
        fs::remove_file(soc_manifest_path).unwrap();
        fs::remove_file(mcu_runtime_path).unwrap();
        fs::remove_file(soc_image1_path).unwrap();
        fs::remove_file(soc_image2_path).unwrap();
        fs::remove_file(output_path).unwrap();
    }

    #[test]
    fn test_flash_image_verify_happy_path() {
        let image_path = PROJECT_ROOT
            .join("target")
            .join("tmp")
            .join("flash_image_happy_path.bin");
        let image_path = image_path.to_str().unwrap();

        // Create a valid firmware image
        let mut expected_images = [
            FirmwareImage {
                identifier: CALIPTRA_FMC_RT_IDENTIFIER,
                data: b"Caliptra Firmware Data - ABCDEFGH".to_vec(),
            },
            FirmwareImage {
                identifier: SOC_MANIFEST_IDENTIFIER,
                data: b"Soc Manifest Data - 123456789".to_vec(),
            },
            FirmwareImage {
                identifier: MCU_RT_IDENTIFIER,
                data: b"MCU Runtime Data - QWERTYUI".to_vec(),
            },
            FirmwareImage {
                identifier: SOC_IMAGES_BASE_IDENTIFIER,
                data: b"Soc Image 1 Data - ZXCVBNMLKJ".to_vec(),
            },
            FirmwareImage {
                identifier: SOC_IMAGES_BASE_IDENTIFIER + 1,
                data: b"Soc Image 2 Data - POIUYTREWQ".to_vec(),
            },
        ];
        // Create a flash image from the mutable slice
        let flash_image = FlashImage::new(&mut expected_images);
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
        FlashImage::new(&mut vec![
            FirmwareImage {
                identifier: CALIPTRA_FMC_RT_IDENTIFIER,
                data: b"Valid Caliptra Firmware Data".to_vec(),
            },
            FirmwareImage {
                identifier: SOC_MANIFEST_IDENTIFIER,
                data: b"Valid SOC Manifest Data".to_vec(),
            },
        ])
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
