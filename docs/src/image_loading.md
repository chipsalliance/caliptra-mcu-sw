# Image Loading

## Overview

The Image Loading module is a component of the MCU Runtime SDK designed for managing SOC images. This module provides APIs for:

- Loading SOC images to target components. The SOC images could come from a [flash storage](./flash_layout.md) or from another platform capable of streaming images through PLDM T5 (e.g., a BMC Recovery Agent).
- Retrieving the SOC Image Metadata (as defined in the [SOC Manifest](https://github.com/chipsalliance/caliptra-sw/blob/main-2.x/auth-manifest/README.md) documentation)
- Verifying and authenticating the SOC Images through the Caliptra Core. Images that are loaded to the target SOC components will be authenticated using a mailbox command to the Caliptra core and are verified against the measurements in the SOC Manifest.

The diagram below provides an **example** of how the Caliptra subsystem, integrated with custom SOC elements (highlighted in green), facilitates the loading of SOC images to vendor components.

Custom SOC elements:

* **External Flash** : A flash storage containing SOC manifest and the SOC images.
* **Vendor CPU**: A custom CPU that executes code from a coupled Vendor RAM
* **Vendor RAM**: RAM exclusively used by the Vendor CPU and is programmable via AXI bus.
* **Vendor Cfg Storage**: A volatile memory storage used to contain vendor specific configurations.
* **SOC Images** SOC Image 1 is a firmware for Vendor CPU and loaded to Vendor RAM. SOC Image 2 is a configuration binary to be loaded to Vendor Cfg Storage.
* **SOC Config** : A register accessible by the MCU ROM to select appropriate source (flash or PLDM) for loading the SOC images.
* **Caliptra 'Go' Wire** : A signal controlled by the Caliptra core routed to the reset line of the Vendor CPU.

<p align="center">
    <img src="images/image_loading_sample.svg" alt="flash_config" width="80%">
</p>

## Image Loading Steps

The sequence diagram below shows the high level steps of loading MCU RT image and SOC images.

* *Red Arrows indicates actions taken by Caliptra RT*
* *Purple Arrows indicates actions taken by MCU ROM*
* *Blue Arrows indicates actions taken by MCU RT*
* *Black Arrows indicates actions taken by the PLDM FW Update Agent*

<p align="center">
    <!--- https://www.plantuml.com/plantuml/uml/ZLFVRzem47xtNt7hNZQf3OEjFyf3LKOBhTI82gWsQQqcannWoN6YvCBM_VMx60muCBgNnFPzz-Exk--w89bJcMZnZkQO82GoBqJ6RofIcJG4HrsfLKQvF09PWBluaD5T1pfHP15ytkyFeLHwalwkKExi8yFkapNoVyS0es4dTDQVrSM7335A5vY_mdsZPs7kmOSzFjo4qFi6p-OfYoKXT6Peo3fK9X_SqxAOMviz2M5IzgYYhllGXc5fZ3ApzGiC1w5em0RAzMvGVB40mOUJ7--pCiyqlbnPJ3E0-qJE44PfcKVyGuqHFPiFDdkZgk_ZdXAEhRaDhG0w9StJNFr1a2Q6XrJ6MsMDcVTU1f-3EWc75kxEfUOOlrovfhRX2pkXZ5zXckOm6dGXb4PDiI0XDIrxMNrEjbnE0sReGL4NkEgj_Muwuhcrwcuc5i81N6chZMh3cO_U9R5XVhvi6HgUkIJq_0wHlzWcRqSwNexkt-GlWwQ7_3_kbyozvcRY7UfE4Rn2dsfmuMmEo_9a60_YZdE24zQ17ZMvWcwQi33y_h24R8X50Ilvsv278l6YZP3Wzljjjz4Vm5T5DRGJ0YzNFuLVYbCMI7MjECWD4aQ4CInZWIeEeJcpxOdJ5IZ31PjuC9q2oOb6KPDiypJmPJjsgfteSXtvZ458kS85lX7UZtzSBGZxdrS36py2cZB1N99AZRz4Bj_sb2zucVfhFY6IZ2L97fFcr3P4VRlsHscz5OMNxPe_PQB_0W00 -->
    <img src="images/image_loading_sequence.svg" alt="flash_config" width="100%">
</p>

The following steps are done for every SOC image:

<p align="center">
    <!--- https://www.plantuml.com/plantuml/uml/TLB1RjD04BtlLxmM2S41bmOua4FLO5gAH0GYIa4Y5ThQOsSbUzVQ7LFQhsUys4bNIdsmP_QzcNdxnkU1jUU-RTGHRwabjDe7rScPAKodBUCurutfsEjZw80fIIchgmKMHH4P4X-knrARvjRzZQmnJfdBV1r1-IgLGj--V5pYyWSsTjsLcWcBcYn7zW2bvCj6Xst4OfI2rsHBvv6xjdDswb5CcPAdSQv39HpwG_uUgwyvJAjhKhhX_zEEEg_hLeF9FO1zJseuVlNhsMtJqytPhjiSf--pqmoVX_AJlAgLeYRGA2k-doYQFIuInKeysL57y-QOlSwWUzuwRnxeHHJvsvGlrQwNb7WgRyvaAS9Eb4nhcIXJBZmPVatULFUu4eKm5kE2nVuxmzjeoL9RKr7WoDdOQDYau811wRZ7TtYJuJjnxor2NnGKWdgE4TtVE5_FiHhXlHM9whSPLiIu-7cHdtno-60OhjflTcCBvpq5oKfZQx3Roqt59RkOlSiWtUwC9mJYOHSOVX1rBb7VDly0_ -->
    <img src="images/image_loading_sequence_loop.svg" alt="flash_config" width="80%">
</p>  
The following outlines the steps carried out by the MCU RT during the SOC boot process:

1. MCU ROM reads a SOC Configuration register (implementation specific) to determine the source of the images to load (Flash/PLDM).
2. Caliptra RT authorizes and loads Caliptra RT (refer to [Caliptra Subsystem boot flow](https://github.com/chipsalliance/Caliptra/blob/main/doc/Caliptra.md#subsystem-boot-flow) for the detailed steps).
3. Caliptra switches to Caliptra RT FW.
4. Caliptra RT indicates to Recovery I/F that it is ready for the SOC manifest image (refer to [Caliptra Subsystem Recovery Sequence](https://github.com/chipsalliance/Caliptra/blob/main/doc/Caliptra.md#caliptra-subsystem-recovery-sequence) for the detailed steps).
5. Retrieve SOC Manifest

   1. If image is coming from PLDM, PLDM FW Update Agent transfers SOC manifest to Recovery I/F
   2. If Image is coming from Flash, MCU ROM transfers SOC manifest from flash to Recovery I/F
6. Caliptra RT transfers SOC Manifest to Caliptra Mailbox (MB) SRAM
7. Caliptra RT will authenticate its image sitting in Caliptra MB SRAM
8. Caliptra RT indicates to Recovery I/F that it is ready for the next image that should be the MCU RT Image (refer to [Caliptra Subsystem Recovery Sequence](https://github.com/chipsalliance/Caliptra/blob/main/doc/Caliptra.md#caliptra-subsystem-recovery-sequence) for the detailed steps)..
9. Retrieve MCU RT Image

   1. If Image is coming from PLDM, PLDM FW Update Agent sends MCU RT Image to Recovery I/F (refer to [Caliptra Subsystem boot flow](https://github.com/chipsalliance/Caliptra/blob/main/doc/Caliptra.md#subsystem-boot-flow)).
   2. If Image is coming from Flash, MCU ROM transfers MCU RT Image to Recovery I/F
10. Caliptra RT FW will read the recovery interface registers over AXI manager interface and write the image to MCU SRAM aperture
11. Caliptra RT FW will instruct its SHA accelerator to hash the MCU RT Image in the MCU SRAM.
12. Caliptra RT FW will use this hash and verify it against the hash in the SOC manifest.
13. Once the digest is verified, Caliptra RT FW sets the [EXEC/GO bit](https://chipsalliance.github.io/caliptra-rtl/main/external-regs/?p=caliptra_top_reg.generic_and_fuse_reg.SS_GENERIC_FW_EXEC_CTRL%5B0%5D).
14. The EXEC/GO bit sets a Caliptra wire to MCU (as a consequence of setting the EXEC/GO bit in the previous step). When MCU detects this event, it sets a parameter using the FW HandOff table to indicate the image source (i.e. the image source where it booted from).
15. MCU switches to MCU RT
16. MCU RT retrieves the image source from HandOff table
17. BMC or a similar platform component will now do MCTP enumeration flow to MCU over I3C. This will be used for transfering SOC images via PLDM.
18. Retrieve SOC Images Metadata

    1. If Image is coming from PLDM, retrieve Image Metadata Collection (from the PLDM SoC Manifest component) through PLDM T5 flow.
    2. If Image is coming from flash, read Flash Image Metadata Collection section of the SOC Manifest.

For every image listed in the Metadata collection:

19. Retrieve the SOC Image (could be Firmware or Configuration payload). MCU RT writes directly the image to the target load address as specified in the image metadata. (In the example custom SOC design, this will be the Vendor RAM or Vendor Cfg Storage)
20. MCU RT sends a Caliptra mailbox command to authorize the image in the SHA Acc identified by the image_id in the image metadata.
21. Caliptra RT sends the image to the SHA Acc.
22. Caliptra RT verifies the computed hash in SHA acc versus the one in the SOC manifest corresponding to the image_id given.
23. Once verified, Caliptra RT returns Success response to MCU via the mailbox.

Steps 24-25, are SOC design-specific options One option is to use the Caliptra 'Go' register to set the corresponding 'Go' wire to allow the target component to process the loaded image.
24. MCU RT sets the corresponding Go bit in Caliptra register corresponding to the image component.
25. The Go bit sets the corresponding wire that indicates the component can process the loaded image.

## Architecture

The following diagram presents the software stack architecture where the Image Loading module resides.

<p align="left">
    <img src="images/image_loading_sw_stack.svg" alt="sw_stack" width="80%">
</p>

At the top of the stack, the user application interacts with the Image Loading module through high-level APIs. The user application is responsible for initiating the image loading and verification.

The Image Loading module provides the interface to retrieve and parse the manifest from the flash storage, and transfer SOC images from the storage to the target destination.

### Application Interfaces

The APIs are presented as methods of the ImageLoader trait.

```rust


/// Trait defining the Image Loading module
pub trait ImageLoader {
    /// Retrieves the Image Metadata collection from the image source.
    /// The ImageLoader module automatically selects the appropriate image source based on the parameter passed by MCU ROM in the HandOff FW table.
    ///
    /// # Returns
    /// - `Ok(ImageMetadataCollection)`: The ImageMetadataCollection if successfully retrieved.
    /// - `Err(DynError)`: An error if retrieval fails.
    async fn get_imc(&self) -> Result<ImageMetadataCollection, DynError>;

    /// Loads the specified image to a storage mapped to the AXI bus memory map.
    /// If the image will be loaded directly to the target component, the AXI mapped load address in the image metadata can be used.
    ///
    /// # Returns
    /// - `Ok()`: Image has been loaded and authorized succesfully.
    /// - `Err(DynError)`: Indication of the failure to load or authorize the image.
    async fn load_and_authorize(&self, image_id: u32, address: u64) -> Result<(), DynError>;
}
```

## Using ImageLoader in the Application

This section describes how to use ImageLoader to load an image.

1. Retrieve the SOC manifest from flash using ImageLoader.

```rust
loader.get_imc().await?
```

3. Load and authorize the image

```rust
    for entry in &imc.image_metadata_entries {
        loader.load_and_authorize(entry.image_identifier, entry.load_address).await?;
        // Call API to indicate to target component that image has been authenticated and is ready to be executed / processed.
 
    }
```
