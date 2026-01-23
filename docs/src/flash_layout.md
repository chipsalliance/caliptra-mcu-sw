# SPI Flash Layout

Overall, the SPI Flash consists of a Header, Checksum and an Image Payload (which includes the image information and the image binary).

The specific images of the flash consists of the Caliptra FW, MCU RT, SoC Manifest, and other SoC images, if any.

## Typical flash Layout

*Note: All fields are little-endian byte-ordered unless specified otherwise.*

A typical overall flash layout is:

| Flash Layout |
| ------------ |
| Header       |
| Payload      |

The Payload contains the following fields:

| Payload                        |
| ------------------------------ |
| Image Info (Caliptra FMC + RT) |
| Image Info (SoC Manifest)      |
| Image Info (MCU RT)            |
| Image Info (SoC Image 1)       |
| ...                            |
| Image Info (SoC Image N)       |
| Caliptra FMC + RT Package      |
| SoC Manifest                   |
| MCU RT                         |
| SoC Image 1                    |
| ...                            |
| SoC Image N                    |

* Caliptra FMC and RT (refer to the [Caliptra Firmware Image Bundle Format](https://github.com/chipsalliance/caliptra-sw/blob/main-2.x/rom/dev/README.md#firmware-image-bundle))
* SoC Manifest (refer to the description of the [SoC Manifest](https://github.com/chipsalliance/caliptra-sw/blob/main-2.x/auth-manifest/README.md))
* MCU RT: This is the image binary of the MCU Runtime firmware
* Other SoC images (if any)

## Header

The Header section contains the metadata for the images stored in the flash.

| Field          | Size (bytes) | Description                                                                                                                                |
| -------------- | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------ |
| Magic Number   | 4            | A unique identifier to mark the start of the header.<br />The value must be `0x464C5348` (`"FLSH"` in ASCII)                               |
| Header Version | 2            | The header version format, allowing for backward compatibility if the package format changes over time.<br />(Current version is `0x0001`) |
| Image Count    | 2            | The number of image stored in the flash.<br />Each image will have its own image information section.                                      |
| Payload Offset | 4            | Offset in bytes of the header to where the first byte of the Payload is located.  |
| Header Checksum | 4            | CRC-32 checksum calculated for the header excluding this field  |

## Image Information

The Image Information section is repeated for each image and provides detailed manifest data specific to that image.

| Field               | Size (bytes) | Descr                                                                                  |
| ------------------- | ------------ | -------------------------------------------------------------------------------------- |
| Identifier          | 4            | Vendor selected unique value to distinguish between images.                            |
|                     |              | `0x00000001`: Caliptra FMC+RT                                                              |
|                     |              | `0x00000002`: SoC Manifest                                                                |
|                     |              | `0x00000003`: MCU RT<br />`0x00001000`-`0xFFFFFFFF` - Reserved for other Vendor-defined SoC images |
| ImageLocationOffset | 4            | Offset in bytes from byte 0 of the header to where the image content begins.           |
| Size                | 4            | Size in bytes of the image. This is the actual size of the image without padding.      |
|                     |              | The image itself as written to the flash should be 4-byte aligned and additional       |
|                     |              | padding will be required to guarantee alignment.                                       |
| Image Checksum      | 4            | CRC-32 checksum calculated for the binary image located at `ImageLocationOffset` |
| Image Info Checksum | 4            | CRC-32 checksum calculated for the header excluding this field  |

## Image

The images (raw binary data) are appended after the Image Information section, and should be in the same order as their corresponding Image Information.

| Field | Size (bytes) | Description                                                           |
| ----- | ------------ | --------------------------------------------------------------------- |
| Data  | N            | Image content.                                                        |
|       |              | Note: The image should be 4-byte aligned.                             |
|       |              | If the size of a firmware image is not a multiple of 4 bytes,         |
|       |              | `0x00` padding bytes will be added to meet the alignment requirement. |
