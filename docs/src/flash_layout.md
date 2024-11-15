## SPI Flash Layout

Overall, the SPI Flash consists of a Header, Checksum and an Image Payload (which includes the component info and the images).

The specific image components of the flash consists of the Caliptra FW, MCU RT, SOC Manifest, and other SOC images, if any.

![Typical SPI Flash Layout](images/flash_layout.png)

*Note: All fields are little endian unless specified*

### Header

The Header section contains the metadata for the images stored in the flash.

| Field           | Size (bytes) | Description                                                                                                                              |
| --------------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------- |
| Magic Number    | 4            | A unique identifier to mark the start of the header.<br />The value must be 0x464C5348 ('FLSH' in ASCII)                                 |
| Header Version  | 2            | The header version format, allowing for backward compatibility if the package format changes over time.<br />(Current version is 0x0001) |
| Component Count | 2            | The number of image components stored in the flash.<br />Each component will have its own component information section.                 |

### Checksum

The checksum section contains integrity checksums for the header and the payload sections.

| Field            | Size (bytes) | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| ---------------- | ------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Header Checksum  | 4            | The integrity checksum of the Header section.<br />It is calculated starting at the first byte of the Header until the last byte of the Component Count field.<br /><br />For this specification, the CRC-32 algorithm with the polynomial <br />x32 + x26 + x23 + x22 + x16 + x12  + x11 + x10 + x8 + x7 + x5 + x4 + x2 + x + 1 <br />(same as the one used by IEEE 802.3) shall be used  for the integrity checksum computation. <br />The CRC computation involves processing a byte at a time  with the least significant bit first.            |
| Payload Checksum | 4            | The integrity checksum of the payload section.<br />It is calculated starting at the first byte of the first component information until the last byte of the last image.<br /><br />For this specification, the CRC-32 algorithm with the polynomial<br />x32 + x26 + x23 + x22 + x16 + x12  + x11 + x10 + x8 + x7 + x5 + x4 + x2 + x + 1 <br />(same as the one used by IEEE 802.3) shall be used  for the integrity checksum computation. <br />The CRC computation involves processing a byte at a time  with the least significant bit first. |

### Component Information

The Component Information section is repeated for each image component and provides detailed manifest data specific to that component.

| Field               | Size (bytes) | Descr                                                                                                                                                                                                                           |
| ------------------- | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Classification      | 2            | 0x000A :For Caliptra FMC+RT  (Firmware)<br />0x0001: For SOC Manifest  (Other)<br />0x000A: For MCU RT: (Firmware)<br />For other SOC images: Refer to Component Classification Type for possible values                     |
| Identifier          | 2            | Vendor selected unique value to distinguish between component images.<br /><br />0x0001: Caliptra FMC+RT <br />0x0002: SOC Manifest: <br />0x0003: MCU RT<br />0x1000-0xFFFF - Reserved for other Vendor-defined SOC images  |
| VersionString       | 256          | A null terminated ascii string pertaining to the version of the image                                                                                                                                                           |
| ImageLocationOffset | 4            | Offset in Bytes from byte 0 of the header to where the component image begins.                                                                                                                                                  |
| Size                | 4            | Size in bytes of the image.                                                                                                                                                                                                     |
| OpaqueDataLength    | 1            | Length in bytes of the OpaqueData field. If no data is provided, set to 0x00.                                                                                                                                                   |
| OpaqueData          | 128          | Optional data field that allows for Vendor defined metadata associated with the image.<br />OpaqueDataLength is set to 0x00, this field is set to zero.                                                                         |

#### Component Classification Type

| Value         | Package Classification Type        |
| ------------- | ---------------------------------- |
| 0x0000        | Unknown                            |
| 0x0001        | Other                              |
| 0x0002        | Driver                             |
| 0x0003        | Configuration Software             |
| 0x0004        | Application Software               |
| 0x0005        | Instrumentation                    |
| 0x0006        | Firmware/BIOS                      |
| 0x0007        | Diagnostic Software                |
| 0x0008        | Operating System                   |
| 0x0009        | Middleware                         |
| 0x000A        | Firmware                           |
| 0x000B        | BIOS/FCode                         |
| 0x000C        | Support/Service Pack               |
| 0x000D        | Software Bundle                    |
| 0x8000-0xFFFE | Reserved for Vendor Defined values |
| 0xFFFF        | Downstream Device                  |

### Component Image

The images (raw binary data) are appended after the Component Informations section, and should be in the same order to their corresponding Component Information.

| Field | Size (bytes) | Description   |
| ----- | ------------ | ------------- |
| Data  | N            | Image content |

* Caliptra FMC and RT (refer to the [Caliptra Firmware Image Bundle Format](https://github.com/chipsalliance/caliptra-sw/blob/main-2.x/rom/dev/README.md#firmware-image-bundle))
* SOC Manifest (refer to the description of the [SOC Manifest](https://github.com/chipsalliance/caliptra-sw/blob/main-2.x/auth-manifest/README.md))
* MCU RT: This is the image binary of the MCU Realtime firmware
* Other SOC images (if any)
