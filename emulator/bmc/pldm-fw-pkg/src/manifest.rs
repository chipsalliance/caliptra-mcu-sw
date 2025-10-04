/*++

Licensed under the Apache-2.0 license.

--*/
use chrono::{DateTime, Datelike, NaiveDate, NaiveDateTime, NaiveTime, Timelike, Utc};
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::FromPrimitive;
use num_traits::ToPrimitive;
use serde::de::{self, Error as DeError};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::fs;
use std::fs::File;
use std::io::{self, Read, Write};
use std::io::{BufReader, BufWriter};
use std::str::FromStr;
use uuid::Uuid;

use crc::{Crc, CRC_32_ISO_HDLC};

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
pub struct FirmwareManifest {
    pub package_header_information: PackageHeaderInformation,
    pub firmware_device_id_records: Vec<FirmwareDeviceIdRecord>,
    pub downstream_device_id_records: Option<Vec<DownstreamDeviceIdRecord>>,
    pub component_image_information: Vec<ComponentImageInformation>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct PackageHeaderInformation {
    pub package_header_identifier: Uuid,
    pub package_header_format_revision: u8,
    pub package_release_date_time: DateTime<Utc>,
    pub package_version_string_type: StringType,
    pub package_version_string: Option<String>,
    #[serde(skip)]
    pub package_header_size: u16,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct FirmwareDeviceIdRecord {
    pub firmware_device_package_data: Option<Vec<u8>>,
    pub device_update_option_flags: u32,
    pub component_image_set_version_string_type: StringType,
    pub component_image_set_version_string: Option<String>,
    pub applicable_components: Option<Vec<u8>>,
    pub initial_descriptor: Descriptor,
    pub additional_descriptors: Option<Vec<Descriptor>>,
    pub reference_manifest_data: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct DownstreamDeviceIdRecord {
    pub update_option_flags: u32, // bitfield32
    pub self_contained_activation_min_version_string_type: StringType,
    pub applicable_components: Option<Vec<u8>>, // Variable bitfield
    pub self_contained_activation_min_version_string: Option<String>, // Up to 255 bytes
    pub self_contained_activation_min_version_comparison_stamp: Option<u32>,
    pub record_descriptors: Vec<Descriptor>, // Reference to Descriptor struct
    pub package_data: Option<Vec<u8>>,       // Optional variable data field
    pub reference_manifest_data: Option<Vec<u8>>, // Optional reference manifest
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ComponentImageInformation {
    pub image_location: Option<String>,
    pub classification: u16,
    pub identifier: u16,
    pub comparison_stamp: Option<u32>, // Optional uint32 based on ComponentOptions
    pub options: u16,                  // Bitfield16
    pub requested_activation_method: u16, // Bitfield16
    pub version_string_type: StringType,
    pub version_string: Option<String>, // Variable length up to 255 bytes
    pub opaque_data: Option<Vec<u8>>,   // Variable length data
    #[serde(skip)]
    pub offset: u32,  // Offset to the start of the image
    #[serde(skip)]
    pub size: u32,    // Size of the image
    #[serde(skip)]
    pub image_data: Option<Vec<u8>>, // Optional image data, to be filled when package is decoded
}

#[derive(Debug, PartialEq)]
enum PldmVersion {
    Version10,
    Version11,
    Version12,
    Version13,
    Unknown, // For handling unknown UUIDs
}

impl PldmVersion {
    // Function to return the corresponding UUID for each PLDM version
    fn get_uuid(&self) -> Option<Uuid> {
        match self {
            PldmVersion::Version13 => Uuid::from_str("7B291C996DB64208801B02026E463C78").ok(),
            PldmVersion::Version12 => Uuid::from_str("3119CE2FE80A4A99AF6D46F8B121F6BF").ok(),
            PldmVersion::Version11 => Uuid::from_str("1244D2648D7D4718A030FC8A56587D5A").ok(),
            PldmVersion::Version10 => Uuid::from_str("F018878CCB7D49439800A02F059ACA02").ok(),
            PldmVersion::Unknown => None, // No UUID for unknown versions
        }
    }
}

// Function to determine PLDM version based on UUID
fn get_pldm_version(uuid: Uuid) -> PldmVersion {
    match uuid.to_string().replace("-", "").to_uppercase().as_str() {
        // UUID for Version 1.3
        "7B291C996DB64208801B02026E463C78" => PldmVersion::Version13,

        // UUID for Version 1.2
        "3119CE2FE80A4A99AF6D46F8B121F6BF" => PldmVersion::Version12,

        // UUID for Version 1.1
        "1244D2648D7D4718A030FC8A56587D5A" => PldmVersion::Version11,

        // UUID for Version 1.0
        "F018878CCB7D49439800A02F059ACA02" => PldmVersion::Version10,

        // If UUID does not match any known version
        _ => PldmVersion::Unknown,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, FromPrimitive, ToPrimitive, Default)]
pub enum DescriptorType {
    PciVendorId = 0x0000,
    IanaEnterpriseId = 0x0001,
    Uuid = 0x0002,
    PnpVendorId = 0x0003,
    AcpiVendorId = 0x0004,
    IeeeAssignedCompanyId = 0x0005,
    ScsiVendorId = 0x0006,
    PciDeviceId = 0x0100,
    PciSubsystemVendorId = 0x0101,
    PciSubsystemId = 0x0102,
    PciRevisionId = 0x0103,
    PnpProductIdentifier = 0x0104,
    AcpiProductIdentifier = 0x0105,
    AsciiModelNumberLong = 0x0106,
    AsciiModelNumberShort = 0x0107,
    ScsiProductId = 0x0108,
    UbmControllerDeviceCode = 0x0109,
    IeeeEui64Id = 0x010A,
    PciRevisionIdRange = 0x010B,
    VendorDefined = 0x8000,
    #[default]
    Unknown = 0xFFFF,
}

impl DescriptorType {
    fn as_string(&self) -> &str {
        match *self {
            DescriptorType::PciVendorId => "PCI_VENDOR_ID",
            DescriptorType::IanaEnterpriseId => "IANA_ENTERPRISE_ID",
            DescriptorType::Uuid => "UUID",
            DescriptorType::PnpVendorId => "PNP_VENDOR_ID",
            DescriptorType::AcpiVendorId => "ACPI_VENDOR_ID",
            DescriptorType::IeeeAssignedCompanyId => "IEEE_ASSIGNED_COMPANY_ID",
            DescriptorType::ScsiVendorId => "SCSI_VENDOR_ID",
            DescriptorType::PciDeviceId => "PCI_DEVICE_ID",
            DescriptorType::PciSubsystemVendorId => "PCI_SUBSYSTEM_VENDOR_ID",
            DescriptorType::PciSubsystemId => "PCI_SUBSYSTEM_ID",
            DescriptorType::PciRevisionId => "PCI_REVISION_ID",
            DescriptorType::PnpProductIdentifier => "PNP_PRODUCT_IDENTIFIER",
            DescriptorType::AcpiProductIdentifier => "ACPI_PRODUCT_IDENTIFIER",
            DescriptorType::AsciiModelNumberLong => "ASCII_MODEL_NUMBER_LONG",
            DescriptorType::AsciiModelNumberShort => "ASCII_MODEL_NUMBER_SHORT",
            DescriptorType::ScsiProductId => "SCSI_PRODUCT_ID",
            DescriptorType::UbmControllerDeviceCode => "UBM_CONTROLLER_DEVICE_CODE",
            DescriptorType::IeeeEui64Id => "IEEE_EUI_64_ID",
            DescriptorType::PciRevisionIdRange => "PCI_REVISION_ID_RANGE",
            DescriptorType::VendorDefined => "VENDOR_DEFINED",
            _ => "UNKNOWN",
        }
    }
}

impl fmt::Display for DescriptorType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_string())
    }
}

impl Serialize for DescriptorType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = self.as_string();
        serializer.serialize_str(s)
    }
}

impl FromStr for DescriptorType {
    type Err = String;

    fn from_str(input: &str) -> Result<DescriptorType, Self::Err> {
        match input.to_uppercase().as_str() {
            "PCI_VENDOR_ID" => Ok(DescriptorType::PciVendorId),
            "IANA_ENTERPRISE_ID" => Ok(DescriptorType::IanaEnterpriseId),
            "UUID" => Ok(DescriptorType::Uuid),
            "PNP_VENDOR_ID" => Ok(DescriptorType::PnpVendorId),
            "ACPI_VENDOR_ID" => Ok(DescriptorType::AcpiVendorId),
            "IEEE_ASSIGNED_COMPANY_ID" => Ok(DescriptorType::IeeeAssignedCompanyId),
            "SCSI_VENDOR_ID" => Ok(DescriptorType::ScsiVendorId),
            "PCI_DEVICE_ID" => Ok(DescriptorType::PciDeviceId),
            "PCI_SUBSYSTEM_VENDOR_ID" => Ok(DescriptorType::PciSubsystemVendorId),
            "PCI_SUBSYSTEM_ID" => Ok(DescriptorType::PciSubsystemId),
            "PCI_REVISION_ID" => Ok(DescriptorType::PciRevisionId),
            "PNP_PRODUCT_IDENTIFIER" => Ok(DescriptorType::PnpProductIdentifier),
            "ACPI_PRODUCT_IDENTIFIER" => Ok(DescriptorType::AcpiProductIdentifier),
            "ASCII_MODEL_NUMBER_LONG" => Ok(DescriptorType::AsciiModelNumberLong),
            "ASCII_MODEL_NUMBER_SHORT" => Ok(DescriptorType::AsciiModelNumberShort),
            "SCSI_PRODUCT_ID" => Ok(DescriptorType::ScsiProductId),
            "UBM_CONTROLLER_DEVICE_CODE" => Ok(DescriptorType::UbmControllerDeviceCode),
            "IEEE_EUI_64_ID" => Ok(DescriptorType::IeeeEui64Id),
            "PCI_REVISION_ID_RANGE" => Ok(DescriptorType::PciRevisionIdRange),
            "VENDOR_DEFINED" => Ok(DescriptorType::VendorDefined),
            _ => Err(format!("Invalid string type: {}", input)),
        }
    }
}

impl<'de> Deserialize<'de> for DescriptorType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        DescriptorType::from_str(&s).map_err(DeError::custom)
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Default, Clone)]
pub struct Descriptor {
    pub descriptor_type: DescriptorType,
    pub descriptor_data: Vec<u8>, // Variable length payload
}

#[derive(Debug, Copy, Clone, PartialEq, FromPrimitive, ToPrimitive, Default)]
pub enum StringType {
    Unknown = 0,
    Ascii = 1,
    #[default]
    Utf8 = 2,
    Utf16 = 3,
    Utf16Le = 4,
    Utf16Be = 5,
}

impl StringType {
    fn as_string(&self) -> &str {
        match *self {
            StringType::Ascii => "ASCII",
            StringType::Utf8 => "UTF-8",
            StringType::Utf16 => "UTF-16",
            StringType::Utf16Le => "UTF-16LE",
            StringType::Utf16Be => "UTF-16BE",
            _ => "UNKNOWN",
        }
    }
}

impl fmt::Display for StringType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_string())
    }
}

impl FromStr for StringType {
    type Err = String; // Changed to String for error messages

    fn from_str(input: &str) -> Result<StringType, Self::Err> {
        match input.to_uppercase().as_str() {
            "ASCII" => Ok(StringType::Ascii),
            "UTF-8" => Ok(StringType::Utf8),
            "UTF-16" => Ok(StringType::Utf16),
            "UTF-16LE" => Ok(StringType::Utf16Le),
            "UTF-16BE" => Ok(StringType::Utf16Be),
            _ => Err(format!("Invalid string type: {}", input)), // Return descriptive error
        }
    }
}

impl<'de> Deserialize<'de> for StringType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        StringType::from_str(&s).map_err(de::Error::custom)
    }
}

impl Serialize for StringType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = self.as_string();
        serializer.serialize_str(s)
    }
}

#[derive(Debug)]
pub struct Timestamp104 {
    pub data: [u8; 13],
}

impl Timestamp104 {
    // Convert DateTime<Utc> to Timestamp104 format
    pub fn from_datetime(dt: DateTime<Utc>) -> Self {
        let mut data = [0u8; 13];

        // Byte 12: UTC resolution (bits 7:4) and Time resolution (bits 3:0)
        data[12] = (3 << 4) | 6; // UTC resolution: hour (3), Time resolution: second (6)

        // Bytes 11:10 - Year as uint16
        let year = dt.year() as u16;
        data[10] = (year & 0xFF) as u8;
        data[11] = (year >> 8) as u8;

        // Byte 9 - Month as uint8 (starting with 1)
        data[9] = dt.month() as u8;

        // Byte 8 - Day within the month as uint8 (starting with 1)
        data[8] = dt.day() as u8;

        // Byte 7 - Hour within the day as uint8 (24-hour representation starting with 0)
        data[7] = dt.hour() as u8;

        // Byte 6 - Minute within the hour as uint8 (starting with 0)
        data[6] = dt.minute() as u8;

        // Byte 5 - Seconds within the minute as uint8 (starting with 0)
        data[5] = dt.second() as u8;

        // Bytes 4:2 - Microseconds within the second as a 24-bit binary integer
        let microseconds = dt.timestamp_subsec_micros();
        data[2] = (microseconds & 0xFF) as u8;
        data[3] = ((microseconds >> 8) & 0xFF) as u8;
        data[4] = ((microseconds >> 16) & 0xFF) as u8;

        // Bytes 1:0 - UTC offset in minutes as sint16 (UTC offset is 0 for DateTime<Utc>)
        data[0] = 0;
        data[1] = 0;

        Timestamp104 { data }
    }

    // Encode the Timestamp104 into a binary format
    pub fn encode<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.data)?;
        Ok(())
    }

    // Decode a binary format back into a Timestamp104 struct
    pub fn decode<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut data = [0u8; 13];
        reader.read_exact(&mut data)?;
        Ok(Timestamp104 { data })
    }

    pub fn to_datetime(&self) -> Option<DateTime<Utc>> {
        let year = u16::from_le_bytes([self.data[10], self.data[11]]) as i32;
        let month = self.data[9] as u32;
        let day = self.data[8] as u32;
        let hour = self.data[7] as u32;
        let minute = self.data[6] as u32;
        let second = self.data[5] as u32;
        let microseconds = u32::from_le_bytes([self.data[2], self.data[3], self.data[4], 0]);

        let date = NaiveDate::from_ymd_opt(year, month, day)?;
        let time = NaiveTime::from_hms_micro_opt(hour, minute, second, microseconds)?;

        let naive_datetime = NaiveDateTime::new(date, time);
        Some(DateTime::from_naive_utc_and_offset(naive_datetime, Utc))
    }
}

impl FirmwareManifest {
    pub fn verify(&self) -> Result<(), String> {
        let component_count = self.component_image_information.len();

        // Verify package_header_information
        self.package_header_information.verify()?;

        // Verify firmware_device_id_records
        for (index, record) in self.firmware_device_id_records.iter().enumerate() {
            if let Err(e) = record.verify(component_count) {
                return Err(format!("firmware_device_id_records[{}]: {}", index, e));
            }
        }

        // Verify downstream_device_id_records
        if let Some(downstream_device_id_records) = &self.downstream_device_id_records {
            for (index, record) in downstream_device_id_records.iter().enumerate() {
                if let Err(e) = record.verify(component_count) {
                    return Err(format!("downstream_device_id_records[{}]: {}", index, e));
                }
            }
        }

        // Verify component_image_information
        for (index, component) in self.component_image_information.iter().enumerate() {
            if let Err(e) = component.verify() {
                return Err(format!("component_image_information[{}]: {}", index, e));
            }
        }

        Ok(())
    }

    pub fn generate_firmware_package(&self, output_file_path: &String) -> io::Result<()> {
        println!("Generating firmware package: {}", output_file_path);
        let file = File::create(output_file_path)?;
        let mut writer = BufWriter::new(file);
        let mut buffer: Vec<u8> = Vec::new();

        // Encode package_header_information
        self.package_header_information.encode(
            &mut buffer,
            &self.firmware_device_id_records,
            &self.downstream_device_id_records,
            &self.component_image_information,
        )?;

        let component_bitmap_bit_length = self.component_image_information.len() as u16;

        // Encode firmware_device_id_records
        let num_firmware_records = self.firmware_device_id_records.len() as u8;
        buffer.push(num_firmware_records);
        for record in &self.firmware_device_id_records {
            record.encode(&mut buffer, component_bitmap_bit_length)?;
        }

        // Encode downstream_device_id_records
        if let Some(downstream_device_id_records) = &self.downstream_device_id_records {
            let num_downstream_records = downstream_device_id_records.len() as u8;
            buffer.push(num_downstream_records);
            for record in downstream_device_id_records {
                record.encode(&mut buffer, component_bitmap_bit_length)?;
            }
        } else {
            buffer.push(0);
        }

        // Encode component_image_information
        let num_components = self.component_image_information.len() as u16;
        let mut offset = self.package_header_information.get_header_size(
            &self.firmware_device_id_records,
            &self.downstream_device_id_records,
            &self.component_image_information,
        ) as u32;
        buffer.write_all(&num_components.to_le_bytes())?;
        for component in &self.component_image_information {
            offset += component.encode(&mut buffer, offset)?;
        }

        // Define a buffer for the component image data
        let mut image_data: Vec<u8> = Vec::new();

        // For each component, read the image data from the file and append to the image_data buffer
        for component in &self.component_image_information {
            if let Some(location) = &component.image_location {
                // Read the image data from the file
                let mut file = File::open(location)?;
                let mut data = Vec::new();
                file.read_to_end(&mut data)?;
                image_data.append(&mut data);
            } else if let Some(data) = &component.image_data {
                // If image_data is provided, use it directly
                let mut data = data.clone();
                image_data.append(&mut data);
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "No image data or location provided for component",
                ));
            }
        }

        // Calculate the checksum of the package header
        let crc32 = Crc::<u32>::new(&CRC_32_ISO_HDLC);
        let package_header_checksum = crc32.checksum(&buffer);

        // Calculate the checksum of the image data
        let pldm_fw_package_payload_checksum = crc32.checksum(&image_data);

        // Write the package header to the writer
        writer.write_all(&buffer)?;

        // Write the checksums to the writer
        writer.write_all(&package_header_checksum.to_le_bytes())?;
        writer.write_all(&pldm_fw_package_payload_checksum.to_le_bytes())?;

        // Write the image data to the writer
        writer.write_all(&image_data)?;
        writer.flush()?;

        Ok(())
    }

    pub fn parse_manifest_file(file_path: &String) -> io::Result<Self> {
        let manifest_contents = fs::read_to_string(file_path).expect("Failed to read file");
        let manifest: FirmwareManifest = toml::de::from_str(&manifest_contents)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        manifest
            .verify()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(manifest)
    }

    pub fn decode_firmware_package(
        fw_package_file_path: &String,
        output_dir_path: Option<&String>,
    ) -> io::Result<Self> {
        if let Some(output_dir_path) = output_dir_path {
            match fs::metadata(output_dir_path) {
                Ok(metadata) => {
                    if !metadata.is_dir() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("{} is not a directory", output_dir_path),
                        ));
                    }
                }
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("{} does not exist", output_dir_path),
                    ));
                }
            }
        }

        let bin_file = File::open(fw_package_file_path)?;
        let mut reader = BufReader::new(bin_file);

        // Decode package_header_information
        let (package_header_information, component_bitmap_length) =
            PackageHeaderInformation::decode(&mut reader)?;

        let pldm_version = get_pldm_version(package_header_information.package_header_identifier);

        // Error if pldm version is unknown with uuid
        if pldm_version == PldmVersion::Unknown {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Unknown PLDM version {}",
                    package_header_information.package_header_identifier
                ),
            ));
        }

        // Decode firmware_device_id_records
        let mut firmware_device_id_records = Vec::new();
        let mut buffer = [0u8; 1];
        reader.read_exact(&mut buffer)?;
        let num_firmware_records = buffer[0];
        for _ in 0..num_firmware_records {
            firmware_device_id_records.push(FirmwareDeviceIdRecord::decode(
                &mut reader,
                component_bitmap_length,
                &pldm_version,
            )?);
        }

        // Decode downstream_device_id_records
        let mut downstream_device_id_records = Vec::new();
        match pldm_version {
            PldmVersion::Version11 | PldmVersion::Version12 | PldmVersion::Version13 => {
                reader.read_exact(&mut buffer)?;
                let num_downstream_records = buffer[0];
                for _ in 0..num_downstream_records {
                    downstream_device_id_records.push(DownstreamDeviceIdRecord::decode(
                        &mut reader,
                        component_bitmap_length,
                        &pldm_version,
                    )?);
                }
            }
            _ => {}
        }
        let downstream_device_id_records = if downstream_device_id_records.is_empty() {
            None
        } else {
            Some(downstream_device_id_records)
        };

        // Decode component_image_information
        let mut component_image_information = Vec::new();
        let mut buffer = [0u8; 2];
        reader.read_exact(&mut buffer)?;
        let num_components = u16::from_le_bytes(buffer);

        for _ in 0..num_components {
            component_image_information.push(ComponentImageInformation::decode(
                &mut reader,
                &pldm_version,
            )?);
        }

        // Read the package header checksum
        let mut buffer = [0u8; 4];
        reader.read_exact(&mut buffer)?;

        // if version is at 1.3, then read the pldm_fw_package_payload_checksum
        if pldm_version == PldmVersion::Version13 {
            reader.read_exact(&mut buffer)?;
        }

        for (component_idx, component) in component_image_information.iter_mut().enumerate() {
            // Get the size of the component
            let size = component.size as usize;
            // Allocate buffer for the firmwarGe image
            let mut image_data = vec![0u8; size];
            // Read the image data from the reader
            reader.read_exact(&mut image_data)?;
            if output_dir_path.is_some() {
                // Write the image data to a file, the filename has a prefix of img_xx where xx is the component identifier
                let file_path =
                    format!("{}/img_{:02}.bin", output_dir_path.unwrap(), component_idx);
                let mut file = File::create(&file_path)?;
                file.write_all(&image_data)?;
                // Update the image location of the component to the filename
                component.image_location = Some(file_path);
            }
            component.image_data = Some(image_data);
        }

        let manifest = FirmwareManifest {
            package_header_information,
            firmware_device_id_records,
            downstream_device_id_records,
            component_image_information,
        };

        if let Some(output_dir_path) = output_dir_path {
            let manifest_data = toml::to_string(&manifest).expect("Failed to encode TOML");
            let file_path = format!("{}/manifest.toml", output_dir_path);
            let mut file = File::create(&file_path)?;
            file.write_all(manifest_data.as_bytes())?;
        }

        Ok(manifest)
    }
}

impl PackageHeaderInformation {
    fn get_header_size(
        &self,
        firmware_device_records: &[FirmwareDeviceIdRecord],
        downstream_device_records: &Option<Vec<DownstreamDeviceIdRecord>>,
        component_image_information: &[ComponentImageInformation],
    ) -> u16 {
        // Calculate the size of the header
        let mut size = 0;
        size += 16; // package_header_identifier
        size += 1; // package_header_format_revision
        size += 2; // header size
        size += 13; // package_release_date_time
        size += 2; // component_bitmap_bit_length
        size += 1; // package_version_string_type
        size += 1; // package_version_string_length
        if let Some(ref version_string) = self.package_version_string {
            size += version_string.len() as u16;
        }

        let component_bitmap_length = component_image_information.len() as u16;
        size += 1; // device_id_record_count
        for record in firmware_device_records {
            size += record.total_bytes(component_bitmap_length) as u16;
        }

        size += 1; // downstream device_id_record_count
        if let Some(downstream_device_records) = downstream_device_records {
            for record in downstream_device_records {
                size += record.total_bytes(component_bitmap_length) as u16;
            }
        }

        size += 2; // component_image_information_count
        for component in component_image_information {
            size += component.total_bytes() as u16;
        }

        size += 4; // package_header_checksum
        size += 4; // pldm_fw_package_payload_checksum
        size
    }

    fn encode(
        &self,
        buffer: &mut Vec<u8>,
        firmware_device_record: &[FirmwareDeviceIdRecord],
        downstream_device_record: &Option<Vec<DownstreamDeviceIdRecord>>,
        component_image_information: &[ComponentImageInformation],
    ) -> io::Result<()> {
        // Always encode as version 1.3
        let version13_uuid = PldmVersion::Version13.get_uuid().unwrap();
        buffer.write_all(version13_uuid.as_bytes())?;
        buffer.write_all(&self.package_header_format_revision.to_le_bytes())?;
        let header_size = self.get_header_size(
            firmware_device_record,
            downstream_device_record,
            component_image_information,
        );
        buffer.write_all(&header_size.to_le_bytes())?; // TODO: add size for firmware_device_id_records, downstream_device_id_records, component_image_information

        let timestamp: Timestamp104 = Timestamp104::from_datetime(self.package_release_date_time);
        timestamp.encode(buffer)?;

        let component_bitmap_bit_length = component_image_information.len() as u16;
        buffer.write_all(&component_bitmap_bit_length.to_le_bytes())?;
        buffer.push(self.package_version_string_type.to_u8().unwrap_or(0));

        if let Some(ref version_string) = self.package_version_string {
            buffer.push(version_string.len() as u8);
            buffer.write_all(version_string.as_bytes())?;
        } else {
            buffer.push(0);
        }

        Ok(())
    }
    fn decode<R: Read>(reader: &mut R) -> io::Result<(Self, u16)> {
        let mut uuid_bytes = [0u8; 16];
        reader.read_exact(&mut uuid_bytes)?;
        let package_header_identifier = Uuid::from_bytes(uuid_bytes);

        let mut buffer1 = [0u8; 1];
        reader.read_exact(&mut buffer1)?;
        let package_header_format_revision = u8::from_le_bytes([buffer1[0]]);

        let mut buffer2 = [0u8; 2];
        reader.read_exact(&mut buffer2)?;
        let package_header_size = u16::from_le_bytes(buffer2);

        let package_release_date_time = Timestamp104::decode(reader)?.to_datetime().unwrap();

        reader.read_exact(&mut buffer2)?;
        let component_bitmap_bit_length = u16::from_le_bytes(buffer2);

        reader.read_exact(&mut buffer1)?;
        let package_version_string_type =
            StringType::from_u8(buffer1[0]).unwrap_or(StringType::Unknown);

        reader.read_exact(&mut buffer1)?;
        let package_version_string_length = buffer1[0];

        let mut version_string_bytes = vec![0u8; package_version_string_length as usize];
        reader.read_exact(&mut version_string_bytes)?;
        let package_version_string = String::from_utf8(version_string_bytes).ok();

        Ok((
            PackageHeaderInformation {
                package_header_identifier,
                package_header_format_revision,
                package_release_date_time,
                package_version_string_type,
                package_version_string,
                package_header_size,
            },
            component_bitmap_bit_length,
        ))
    }
    pub fn verify(&self) -> Result<(), String> {
        // Verify UUID
        let pldm_version = get_pldm_version(self.package_header_identifier);
        if pldm_version != PldmVersion::Version13 {
            return Err(format!(
                "Only v1.3 PLDM format is supported. UUID in manifest: {}",
                self.package_header_identifier
            ));
        }

        // Verify version string length is less than 255
        if let Some(ref version_string) = self.package_version_string {
            if version_string.len() > 255 {
                return Err(format!(
                    "Package version string length exceeds 255: {}",
                    version_string.len()
                ));
            }
        }

        Ok(())
    }
}

impl FirmwareDeviceIdRecord {
    // Encode the FirmwareDeviceIdRecord into a binary format
    pub fn encode(&self, buffer: &mut Vec<u8>, component_bitmap_length: u16) -> io::Result<()> {
        // Encode record_length (u16)
        let record_length = self.total_bytes(component_bitmap_length) as u16;
        buffer.write_all(&record_length.to_le_bytes())?;

        // Encode descriptor_count (u8), Add one for initial_descriptor
        if let Some(additional_descriptors) = &self.additional_descriptors {
            buffer.push(1u8 + additional_descriptors.len() as u8);
        } else {
            buffer.push(1u8);
        }

        // Encode device_update_option_flags (u32)
        buffer.write_all(&self.device_update_option_flags.to_le_bytes())?;

        // Encode component_image_set_version_string_type (u8)
        buffer.push(
            self.component_image_set_version_string_type
                .to_u8()
                .unwrap_or(0),
        );

        // Encode component_image_set_version_string_length (u8)
        let version_string_length = self
            .component_image_set_version_string
            .as_ref()
            .unwrap()
            .len() as u8;
        buffer.push(version_string_length);

        // Encode firmware_device_package_data_length (u16)
        if let Some(firmware_package_data_ref) = &self.firmware_device_package_data {
            let firmware_package_data_length = firmware_package_data_ref.len() as u16;
            buffer.write_all(&firmware_package_data_length.to_le_bytes())?;
        } else {
            buffer.write_all(&0u16.to_le_bytes())?; // No package data, write zero length
        }

        // Encode reference_manifest_length (u32)
        if let Some(reference_manifest_data_ref) = &self.reference_manifest_data {
            let reference_manifest_length = reference_manifest_data_ref.len() as u32;
            buffer.write_all(&reference_manifest_length.to_le_bytes())?;
        } else {
            buffer.write_all(&0u32.to_le_bytes())?; // No manifest data, write zero length
        }

        // Encode applicable_components
        let mut bitmap = vec![0u8; component_bitmap_length.div_ceil(8) as usize];
        let num_components = component_bitmap_length;
        if let Some(ref components) = self.applicable_components {
            for &component in components {
                if component < num_components as u8 {
                    let byte_index = component as usize / 8;
                    let bit_index = component % 8;
                    bitmap[byte_index] |= 1 << bit_index;
                }
            }
        }
        buffer.write_all(&bitmap)?;

        // Encode component_image_set_version_string
        if let Some(version_string) = &self.component_image_set_version_string {
            let version_string_bytes = version_string.as_bytes();
            buffer.write_all(version_string_bytes)?;
        }

        // Encode initial_descriptor
        self.initial_descriptor.encode(buffer)?;

        // Encode additional_descriptors length as u8, followed by each descriptor
        if let Some(additional_descriptors) = &self.additional_descriptors {
            for descriptor in additional_descriptors {
                descriptor.encode(buffer)?;
            }
        }

        // Encode firmware_device_package_data
        if let Some(package_data) = &self.firmware_device_package_data {
            buffer.write_all(package_data)?;
        }

        // Encode reference_manifest_data
        if let Some(manifest_data) = &self.reference_manifest_data {
            buffer.write_all(manifest_data)?;
        }

        Ok(())
    }

    // Decode a binary format back into a FirmwareDeviceIdRecord struct
    fn decode<R: Read>(
        reader: &mut R,
        component_bitmap_length: u16,
        pldm_version: &PldmVersion,
    ) -> io::Result<Self> {
        let mut buffer = [0u8; 4];

        // Decode record_length (u16)
        let mut record_length_bytes = [0u8; 2];
        reader.read_exact(&mut record_length_bytes)?;
        let _record_length = u16::from_le_bytes(record_length_bytes);

        // Decode descriptor_count (u8)
        let mut descriptor_count = [0u8; 1];
        reader.read_exact(&mut descriptor_count)?;
        let descriptor_count = descriptor_count[0];

        // Decode device_update_option_flags (u32)
        reader.read_exact(&mut buffer)?;
        let device_update_option_flags = u32::from_le_bytes(buffer);

        // Decode component_image_set_version_string_type (u8)
        let mut string_type = [0u8; 1];
        reader.read_exact(&mut string_type)?;
        let component_image_set_version_string_type =
            StringType::from_u8(string_type[0]).unwrap_or(StringType::Unknown);

        // Decode component_image_set_version_string_length (u8)
        let mut version_string_length = [0u8; 1];
        reader.read_exact(&mut version_string_length)?;
        let component_image_set_version_string_length = version_string_length[0];

        // Decode firmware_device_package_data_length (u16)
        let mut package_data_length_bytes = [0u8; 2];
        reader.read_exact(&mut package_data_length_bytes)?;
        let firmware_device_package_data_length = u16::from_le_bytes(package_data_length_bytes);

        let mut reference_manifest_length = 0u32;
        if *pldm_version == PldmVersion::Version13 {
            // Decode reference_manifest_length (u32)
            reader.read_exact(&mut buffer)?;
            reference_manifest_length = u32::from_le_bytes(buffer);
        }

        // Decode applicable_components
        let mut bitmap = vec![0u8; component_bitmap_length.div_ceil(8) as usize];
        let num_components = component_bitmap_length;
        reader.read_exact(&mut bitmap)?;

        // Decode the bitmap into the applicable_components vector
        let mut applicable_components = Vec::new();
        for (byte_index, &byte) in bitmap.iter().enumerate() {
            for bit_index in 0..8 {
                if byte & (1 << bit_index) != 0 {
                    let component_index = (byte_index * 8 + bit_index) as u8;
                    if component_index < num_components as u8 {
                        applicable_components.push(component_index);
                    }
                }
            }
        }
        let applicable_components = if applicable_components.is_empty() {
            None
        } else {
            Some(applicable_components)
        };

        // Decode component_image_set_version_string
        let component_image_set_version_string = if component_image_set_version_string_length > 0 {
            let mut version_string_bytes =
                vec![0u8; component_image_set_version_string_length.into()];
            reader.read_exact(&mut version_string_bytes)?;
            Some(String::from_utf8(version_string_bytes).unwrap())
        } else {
            None
        };

        // Decode initial_descriptor
        let initial_descriptor = Descriptor::decode(reader)?;

        // Decode additional_descriptors
        let mut additional_descriptors = Vec::with_capacity((descriptor_count - 1) as usize);
        for _ in 0..descriptor_count - 1 {
            additional_descriptors.push(Descriptor::decode(reader)?);
        }

        let additional_descriptors = if additional_descriptors.is_empty() {
            None
        } else {
            Some(additional_descriptors)
        };

        // Decode firmware_device_package_data
        let firmware_device_package_data = if firmware_device_package_data_length > 0 {
            let mut package_data = vec![0u8; firmware_device_package_data_length as usize];
            reader.read_exact(&mut package_data)?;
            Some(package_data)
        } else {
            None
        };

        // Decode reference_manifest_data
        let reference_manifest_data =
            if reference_manifest_length > 0 && (*pldm_version == PldmVersion::Version13) {
                let mut manifest_data = vec![0u8; reference_manifest_length as usize];
                reader.read_exact(&mut manifest_data)?;
                Some(manifest_data)
            } else {
                None
            };

        Ok(FirmwareDeviceIdRecord {
            device_update_option_flags,
            component_image_set_version_string_type,
            applicable_components,
            component_image_set_version_string,
            initial_descriptor,
            additional_descriptors,
            firmware_device_package_data,
            reference_manifest_data,
        })
    }

    pub fn total_bytes(&self, component_bitmap_length: u16) -> usize {
        // Fixed-size fields
        let mut total_size = 0;

        total_size += 2; // record_length (u16)
        total_size += 1; // descriptor_count (u8)
        total_size += 4; // device_update_option_flags (u32)
        total_size += 1; // component_image_set_version_string_type (u8)
        total_size += 1; // component_image_set_version_string_length (u8)
        total_size += 2; // firmware_device_package_data_length (u16)
        total_size += 4; // reference_manifest_length (u32)

        // applicable_components bitmap
        total_size += component_bitmap_length.div_ceil(8) as usize;

        // component_image_set_version_string
        if let Some(ref version_string) = self.component_image_set_version_string {
            total_size += version_string.len(); // actual string bytes
        }

        // initial_descriptor size
        total_size += self.initial_descriptor.total_bytes();

        // additional_descriptors length
        if let Some(ref descriptors) = self.additional_descriptors {
            for descriptor in descriptors {
                total_size += descriptor.total_bytes();
            }
        }

        // firmware_device_package_data
        if let Some(ref package_data) = self.firmware_device_package_data {
            total_size += package_data.len(); // actual data bytes
        }

        // reference_manifest_data
        if let Some(ref manifest_data) = self.reference_manifest_data {
            total_size += manifest_data.len(); // actual data bytes
        }

        total_size
    }

    fn verify(&self, component_count: usize) -> Result<(), String> {
        // Verify applicable_components
        if let Some(components) = &self.applicable_components {
            for &comp_index in components {
                if comp_index as usize >= component_count {
                    return Err(format!("Invalid applicable component index {}", comp_index));
                }
            }
        }
        // Verify component_image_set_version_string length is less than 255
        if let Some(ref version_string) = self.component_image_set_version_string {
            if version_string.len() > 255 {
                return Err(format!(
                    "Component image set version string length exceeds 255: {}",
                    version_string.len()
                ));
            }
        }

        Ok(())
    }
}

impl Descriptor {
    // Encode the Descriptor into a binary format
    pub fn encode<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        // Encode descriptor_type (u16)
        writer.write_all(&(self.descriptor_type.to_i32().unwrap_or(0) as u16).to_le_bytes())?;
        // Encode descriptor_length (u16)
        let descriptor_length = self.descriptor_data.len() as u16;
        writer.write_all(&descriptor_length.to_le_bytes())?;
        // Encode descriptor_data (Vec<u8>)
        writer.write_all(&self.descriptor_data)?;

        Ok(())
    }

    // Decode a binary format back into a Descriptor struct
    pub fn decode<R: Read>(reader: &mut R) -> io::Result<Self> {
        // Decode descriptor_type (u16)
        let mut descriptor_type_bytes = [0u8; 2];
        reader.read_exact(&mut descriptor_type_bytes)?;
        let descriptor_type = DescriptorType::from_u16(u16::from_le_bytes(descriptor_type_bytes))
            .unwrap_or(DescriptorType::Unknown);

        // Decode descriptor_length (u16)
        let mut descriptor_length_bytes = [0u8; 2];
        reader.read_exact(&mut descriptor_length_bytes)?;
        let descriptor_length = u16::from_le_bytes(descriptor_length_bytes);

        // Decode descriptor_data (Vec<u8>)
        let mut descriptor_data = vec![0u8; descriptor_length as usize];
        reader.read_exact(&mut descriptor_data)?;

        Ok(Descriptor {
            descriptor_type,
            descriptor_data,
        })
    }

    pub fn total_bytes(&self) -> usize {
        2 + 2 + self.descriptor_data.len() // descriptor_type (u16) + descriptor_length (u16) + descriptor_data
    }
}

impl DownstreamDeviceIdRecord {
    // Encode the DownstreamDeviceIdRecord into a binary format
    pub fn encode(&self, writer: &mut Vec<u8>, component_bitmap_length: u16) -> io::Result<()> {
        // Calculate the total bytes required for encoding and set it to record_length
        let record_length = self.total_bytes(component_bitmap_length) as u16;

        // Encode record_length (u16)
        writer.write_all(&record_length.to_le_bytes())?;

        // Encode descriptor_count (u8)
        writer.push(self.record_descriptors.len() as u8);

        // Encode update_option_flags (u32)
        writer.write_all(&self.update_option_flags.to_le_bytes())?;

        // Encode self_contained_activation_min_version_string_type (u8)
        writer.push(
            self.self_contained_activation_min_version_string_type
                .to_u8()
                .unwrap_or(0),
        );

        // Calculate and encode self_contained_activation_min_version_string_length
        let version_string_length = self
            .self_contained_activation_min_version_string
            .as_ref()
            .map(|s| s.len() as u8)
            .unwrap_or(0);
        writer.push(version_string_length);

        // Encode package_data_length (u16)
        if let Some(package_data_ref) = &self.package_data {
            let package_data_ref_length = package_data_ref.len() as u16;
            writer.write_all(&package_data_ref_length.to_le_bytes())?;
        } else {
            writer.write_all(&0u16.to_le_bytes())?; // No package data, write zero length
        }

        // Encode reference_manifest_length (u32)
        if let Some(reference_data_ref) = &self.reference_manifest_data {
            let length = reference_data_ref.len() as u32;
            writer.write_all(&length.to_le_bytes())?;
        } else {
            writer.write_all(&0u32.to_le_bytes())?; // No reference data, write zero length
        }

        // Encode applicable_components
        let mut bitmap = vec![0u8; component_bitmap_length.div_ceil(8) as usize];
        let num_components = component_bitmap_length;
        if let Some(ref components) = self.applicable_components {
            for &component in components {
                if component < num_components as u8 {
                    let byte_index = component as usize / 8;
                    let bit_index = component % 8;
                    bitmap[byte_index] |= 1 << bit_index;
                }
            }
        }
        writer.write_all(&bitmap)?;

        // Encode self_contained_activation_min_version_string
        if let Some(version_string) = &self.self_contained_activation_min_version_string {
            let version_string_bytes = version_string.as_bytes();
            writer.write_all(version_string_bytes)?;
        }

        // Encode self_contained_activation_min_version_comparison_stamp (optional u32)
        if let Some(comparison_stamp) = self.self_contained_activation_min_version_comparison_stamp
        {
            writer.write_all(&comparison_stamp.to_le_bytes())?;
        }

        // Encode each record_descriptor
        for descriptor in &self.record_descriptors {
            descriptor.encode(writer)?;
        }

        // Encode package_data (optional u16 length + data)
        if let Some(package_data) = &self.package_data {
            writer.write_all(package_data)?;
        }

        // Encode reference_manifest_data (optional u32 length + data)
        if let Some(manifest_data) = &self.reference_manifest_data {
            writer.write_all(manifest_data)?;
        }

        Ok(())
    }

    // Decode a binary format back into a DownstreamDeviceIdRecord struct
    fn decode<R: Read>(
        reader: &mut R,
        component_bitmap_length: u16,
        pldm_version: &PldmVersion,
    ) -> io::Result<Self> {
        let mut buffer = [0u8; 4];

        // Decode record_length (u16)
        let mut record_length_bytes = [0u8; 2];
        reader.read_exact(&mut record_length_bytes)?;
        let _record_length = u16::from_le_bytes(record_length_bytes);

        // Decode descriptor_count (u8)
        let mut descriptor_count = [0u8; 1];
        reader.read_exact(&mut descriptor_count)?;
        let descriptor_count = descriptor_count[0];

        // Decode update_option_flags (u32)
        reader.read_exact(&mut buffer)?;
        let update_option_flags = u32::from_le_bytes(buffer);

        // Decode self_contained_activation_min_version_string_type (u8)
        let mut string_type = [0u8; 1];
        reader.read_exact(&mut string_type)?;
        let self_contained_activation_min_version_string_type =
            StringType::from_u8(string_type[0]).unwrap_or(StringType::Unknown);

        // Decode self_contained_activation_min_version_string_length (u8)
        let mut string_length = [0u8; 1];
        reader.read_exact(&mut string_length)?;
        let self_contained_activation_min_version_string_length = string_length[0];

        // Decode package_data_length (u16)
        let mut package_data_length_bytes = [0u8; 2];
        reader.read_exact(&mut package_data_length_bytes)?;
        let package_data_length = u16::from_le_bytes(package_data_length_bytes);

        let mut reference_manifest_length = 0u32;
        if *pldm_version == PldmVersion::Version13 {
            // Decode reference_manifest_length (u32)
            reader.read_exact(&mut buffer)?;
            reference_manifest_length = u32::from_le_bytes(buffer);
        }

        // Decode applicable_components
        // Read the bitmap from the reader
        let mut bitmap = vec![0u8; component_bitmap_length.div_ceil(8) as usize];
        let num_components = component_bitmap_length;
        reader.read_exact(&mut bitmap)?;

        // Decode the bitmap into the applicable_components vector
        let mut applicable_components = Vec::new();
        for (byte_index, &byte) in bitmap.iter().enumerate() {
            for bit_index in 0..8 {
                if byte & (1 << bit_index) != 0 {
                    let component_index = (byte_index * 8 + bit_index) as u8;
                    if component_index < num_components as u8 {
                        applicable_components.push(component_index);
                    }
                }
            }
        }
        let applicable_components = if applicable_components.is_empty() {
            None
        } else {
            Some(applicable_components)
        };

        let self_contained_activation_min_version_string =
            if self_contained_activation_min_version_string_length > 0 {
                let mut version_string_bytes =
                    vec![0u8; self_contained_activation_min_version_string_length as usize];
                reader.read_exact(&mut version_string_bytes)?;
                Some(String::from_utf8(version_string_bytes).unwrap())
            } else {
                None
            };

        // Decode self_contained_activation_min_version_comparison_stamp
        let mut self_contained_activation_min_version_comparison_stamp: Option<u32> = None;
        if (update_option_flags & 0x00000001) != 0 {
            reader.read_exact(&mut buffer)?;
            self_contained_activation_min_version_comparison_stamp =
                Some(u32::from_le_bytes(buffer));
        }

        // Decode record_descriptors
        let mut record_descriptors = Vec::with_capacity(descriptor_count as usize);
        for _ in 0..descriptor_count {
            record_descriptors.push(Descriptor::decode(reader)?);
        }

        // Decode package_data
        let package_data = if package_data_length > 0 {
            let mut data = vec![0u8; package_data_length as usize];
            reader.read_exact(&mut data)?;
            Some(data)
        } else {
            None
        };

        // Decode reference_manifest_data
        let reference_manifest_data =
            if reference_manifest_length > 0 && *pldm_version == PldmVersion::Version13 {
                let mut manifest_data = vec![0u8; reference_manifest_length as usize];
                reader.read_exact(&mut manifest_data)?;
                Some(manifest_data)
            } else {
                None
            };

        Ok(DownstreamDeviceIdRecord {
            update_option_flags,
            self_contained_activation_min_version_string_type,
            applicable_components,
            self_contained_activation_min_version_string,
            self_contained_activation_min_version_comparison_stamp,
            record_descriptors,
            package_data,
            reference_manifest_data,
        })
    }

    pub fn total_bytes(&self, component_bitmap_length: u16) -> usize {
        // Fixed-size fields
        let mut total_size = 0;

        total_size += 2; // record_length (u16)
        total_size += 1; // descriptor_count (u8)
        total_size += 4; // update_option_flags (u32)
        total_size += 1; // self_contained_activation_min_version_string_type (u8)
        total_size += 1; // self_contained_activation_min_version_string_length (u8)
        total_size += 2; // package_data_length (u16)
        total_size += 4; // reference_manifest_length (u32)

        // applicable_components bitmap
        total_size += component_bitmap_length.div_ceil(8) as usize;

        // self_contained_activation_min_version_string
        if let Some(ref version_string) = self.self_contained_activation_min_version_string {
            total_size += version_string.len(); // actual string bytes
        }

        // self_contained_activation_min_version_comparison_stamp (u32)
        total_size += 4;

        // record_descriptors
        for descriptor in &self.record_descriptors {
            total_size += descriptor.total_bytes();
        }

        // package_data
        if let Some(ref package_data) = self.package_data {
            total_size += package_data.len(); // actual data bytes
        }

        // reference_manifest_data
        if let Some(ref manifest_data) = self.reference_manifest_data {
            total_size += manifest_data.len(); // actual data bytes
        }

        total_size
    }

    fn verify(&self, component_count: usize) -> Result<(), String> {
        // Verify applicable_components
        if let Some(components) = &self.applicable_components {
            for &comp_index in components {
                if comp_index as usize >= component_count {
                    return Err(format!("Invalid applicable component index {}", comp_index));
                }
            }
        }
        // Verify self_contained_activation_min_version_string length is less than 255
        if let Some(ref version_string) = self.self_contained_activation_min_version_string {
            if version_string.len() > 255 {
                return Err(format!(
                    "Self contained activation min version string length exceeds 255: {}",
                    version_string.len()
                ));
            }
        }
        Ok(())
    }
}

impl ComponentImageInformation {
    // Encode the ComponentImageInformation into a binary format
    pub fn encode(&self, writer: &mut Vec<u8>, offset: u32) -> io::Result<u32> {
        // Encode classification (u16)
        writer.write_all(&self.classification.to_le_bytes())?;

        // Encode identifier (u16)
        writer.write_all(&self.identifier.to_le_bytes())?;

        // Encode comparison_stamp (u32)
        if (self.options & 0x0001) != 0 {
            writer.write_all(&self.comparison_stamp.unwrap_or(0u32).to_le_bytes())?;
        } else {
            let all_ones = 0xFFFFFFFFu32;
            writer.write_all(&all_ones.to_le_bytes())?;
        }

        // Encode options (u16)
        writer.write_all(&self.options.to_le_bytes())?;

        // Encode requested_activation_method (u16)
        writer.write_all(&self.requested_activation_method.to_le_bytes())?;

        // Encode location_offset (u32)
        writer.write_all(&offset.to_le_bytes())?;

        // Encode size (u32)
        let mut file_size = 0u32;
        if let Some(image_location) = &self.image_location {
            // get the size of the file at image_location
            let metadata = std::fs::metadata(image_location)?;
            file_size = metadata.len() as u32;
        } else if let Some(image_data) = &self.image_data {
            file_size = image_data.len() as u32;
        }
        writer.write_all(&file_size.to_le_bytes())?;

        // Encode version_string_type (u8)
        writer.push(self.version_string_type.to_u8().unwrap_or(0));

        // Calculate and encode version_string_length
        let version_string_length = self
            .version_string
            .as_ref()
            .map(|s| s.len() as u8)
            .unwrap_or(0);
        writer.push(version_string_length);

        // Encode version_string
        if let Some(version_string) = &self.version_string {
            writer.write_all(version_string.as_bytes())?;
        }

        // Encode opaque_data_length (u32)
        let opaque_data_length = self
            .opaque_data
            .as_ref()
            .map(|d| d.len() as u32)
            .unwrap_or(0);
        writer.write_all(&opaque_data_length.to_le_bytes())?;

        // Encode opaque_data (optional)
        if let Some(opaque_data) = &self.opaque_data {
            writer.write_all(opaque_data)?;
        }

        Ok(file_size)
    }

    // Decode a binary format back into a ComponentImageInformation struct
    fn decode<R: Read>(reader: &mut R, pldm_version: &PldmVersion) -> io::Result<Self> {
        let mut buffer = [0u8; 4];

        // Decode classification (u16)
        let mut classification_bytes = [0u8; 2];
        reader.read_exact(&mut classification_bytes)?;
        let classification = u16::from_le_bytes(classification_bytes);

        // Decode identifier (u16)
        let mut identifier_bytes = [0u8; 2];
        reader.read_exact(&mut identifier_bytes)?;
        let identifier = u16::from_le_bytes(identifier_bytes);

        // Decode comparison_stamp (u32)
        reader.read_exact(&mut buffer)?;
        let comparison_stamp = Some(u32::from_le_bytes(buffer));

        // Decode options (u16)
        let mut options_bytes = [0u8; 2];
        reader.read_exact(&mut options_bytes)?;
        let options = u16::from_le_bytes(options_bytes);

        // Decode requested_activation_method (u16)
        let mut activation_method_bytes = [0u8; 2];
        reader.read_exact(&mut activation_method_bytes)?;
        let requested_activation_method = u16::from_le_bytes(activation_method_bytes);

        // Decode location_offset (u32)
        reader.read_exact(&mut buffer)?;
        let offset = u32::from_le_bytes(buffer);

        // Decode size (u32)
        reader.read_exact(&mut buffer)?;
        let size = u32::from_le_bytes(buffer);

        // Decode version_string_type (u8)
        let mut version_type = [0u8; 1];
        reader.read_exact(&mut version_type)?;
        let version_string_type =
            StringType::from_u8(version_type[0]).unwrap_or(StringType::Unknown);

        // Decode version_string_length (u8)
        let mut version_length = [0u8; 1];
        reader.read_exact(&mut version_length)?;
        let version_string_length = version_length[0] as usize;

        // Decode version_string (Option<String>)
        let version_string = if version_string_length > 0 {
            let mut string_bytes = vec![0u8; version_string_length];
            reader.read_exact(&mut string_bytes)?;
            Some(String::from_utf8(string_bytes).unwrap())
        } else {
            None
        };

        let mut opaque_data_length = 0u32;
        if *pldm_version == PldmVersion::Version13 || *pldm_version == PldmVersion::Version12 {
            // Decode opaque_data_length (u32)
            reader.read_exact(&mut buffer)?;
            opaque_data_length = u32::from_le_bytes(buffer);
        }

        // Decode opaque_data (Option<Vec<u8>>)
        let opaque_data = if opaque_data_length > 0
            && (*pldm_version == PldmVersion::Version13 || *pldm_version == PldmVersion::Version12)
        {
            let mut data = vec![0u8; opaque_data_length as usize];
            reader.read_exact(&mut data)?;
            Some(data)
        } else {
            None
        };

        Ok(ComponentImageInformation {
            image_location: None,
            classification,
            identifier,
            comparison_stamp,
            options,
            requested_activation_method,
            version_string_type,
            version_string,
            opaque_data,
            offset,
            size,
            image_data: None,
        })
    }

    pub fn total_bytes(&self) -> usize {
        let mut total_size = 0;

        // Fixed-size fields
        total_size += 2; // classification (u16)
        total_size += 2; // identifier (u16)
        total_size += 4; // comparison_stamp (u32)
        total_size += 2; // options (u16)
        total_size += 2; // requested_activation_method (u16)
        total_size += 4; // location_offset (u32)
        total_size += 4; // size (u32)
        total_size += 1; // version_string_type (u8)
        total_size += 1; // version_string_length (u8)

        // Variable-length fields
        if let Some(ref version_string) = self.version_string {
            total_size += version_string.len(); // actual length of the version_string
        }

        total_size += 4; // opaque_data_length (u32)

        if let Some(ref opaque_data) = self.opaque_data {
            total_size += opaque_data.len(); // actual length of the opaque_data
        }

        total_size
    }

    fn verify(&self) -> Result<(), String> {
        if let Some(image_location) = &self.image_location {
            // Verify file exists in the image location
            if fs::metadata(image_location).is_err() {
                return Err(format!(
                    "Component image file does not exist: {}",
                    image_location
                ));
            }
        } else if self.image_data.is_none() {
            return Err("Component image location or image data must be provided.".to_string());
        }
        // Verify version_string length is less than 255
        if let Some(ref version_string) = self.version_string {
            if version_string.len() > 255 {
                return Err(format!(
                    "Component version string length exceeds 255: {}",
                    version_string.len()
                ));
            }
        }

        Ok(())
    }
}
