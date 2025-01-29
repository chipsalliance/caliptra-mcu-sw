# Firmware Update

## Overview

The MCU SDK provides an API that allows for updating the firmware of Caliptra FMC & RT, MCU RT and other SOC Images through PLDM - T5.

## Architecture

The MCU PLDM stack handles the PLDM firmware messages from an external Firmware Update Agent. The stack will generate upstream notifications to the Firmware Update API to handle application specific actions such as writing firmware chunks to a staging or permanent storage location, verifying components, etc. The API notifies the application of the start and completion of the firmware update process.

![flash_config](images/firmware_update_software_stack.svg)

## PLDM Firmware Download Sequence

<!--
https://www.plantuml.com/plantuml/svg/ZLLDJyCu4BtdLumuxMfLxMal710X_I1IFxfDMAHLfMfe9iN2iREEMvP_lpPktE1iA4W1wdb-C_FUJ7FVQ5JwMF58Cyq9fanLxwW8dke2DS7la6b5M35nW0SfDMJqpv74dgAeDXVPdjKeDDoSuV61XBu1R60z7o--Gko9OSFz6umW_yEYVBgloB28U9rQjFqRHRZNKi5DAfXcQFvraRgEeiZy7jqPqArDexHdtuepKKRgn4pj1ZEwQwDNqIOZEza3NsraU-ao_7aazJ4c2qyB4fgLZ5GJjO3HdRrm2tr4Zsb6klsmHeKLwVyZwaFwJ1lhLADTCvx12UILFI7Z-C9DqqjfQzgZPb8uWOoSLu61agkteDIWZAtOK5DBqHWDkPGr78qI793phTZBoaH8wArWefHGOzDGqMjhROwJ2_GNV-tNC7K8zQb9562pdsiefG8w6GF1SmLPMnckvhNQXjX0CVE3N8UBzdcsI9v0AiXM2QGL7joSEixP9DzbUJnBbxDTF1vl9bcs5GlZoOlyrvPTeIWYiWzlADXPopr8Eb_5uokCvhdkSzXrr-ckrLsN6oZak-0I2og6vgOz7gF6dYlTOEX2DmQ10mCUUA4MA5XfadUqUZYM9IdG4hZS8__qQXCldDu9SbPhXJ1T9Bzjyiwr99wdwtmJxwRFdr9V94vQYGs1Oyk7p7zMJ9D9lHMPneErDLQ4pfZhVlTvO6uaXxWe53MDOv3wbLG3GcgxZFATlFTzwplx4vgMAnIDrSdE0IUZQMZBNwHO-G5-JW9hld4WCzCQF-MFkqMyJAUJBD-ARpHaGU_svcgJ_ZtPnSknNQNiyNB_fpFkYX_iBQvhxhz4WjO6bZxeDlIg6xJ6JJashyPkgKntFncTHDOVJWiebQoW7Q0-r_2csnCdWElGzt-PWt0nu_Chipq9bFBndaHNsibCId_PHOED6XpQy9NckmXCTlJ1k-hUS1uh_Xy0
-->

The diagram below shows the steps and interaction between the different software layers as the firmware update process is performed. It also shows the actions if streaming boot is performed instead.

Note: For streaming boot, only SOC images are allowed to be downloaded.

<img src="images/firmware_update_sequence.svg" width="50%">

## Firmware Update Steps

Note: Actions below are performed by MCU RT Firmware.

1. An Initiator (such as custom user application) starts the firmware service througn the Firmware Update API ("API"). The initiator should provide the appropriate DeviceIdentifies and FirmwareParameters as defined by DMTF DSP0267 1.3.0 specification.
2. API will be notified by PLDM stack if firmware image is available for update.
3. API will be notified by PLDM stack which component is being downloaded using the UpdateComponent Notification. If the image is MCU RT or SOC Image, then the staging address will be retrieved from the SOC Manifest stored in the Caliptra Core using a mailbox command.
4. FirmwareData notification will be notified by the PLDM stack to the API for every chunk of firmware received. This includies the data,size and the chunk offset.
   1. If the component is a SOC Manifest, it is stored temporarily in a local buffer
   2. If the component is Caliptra FMC+RT, it is uploaded to Caliptra core using CALIPTRA_FW_UPLOAD command
   3. If the component is MCU RT or SOC Image, it is written to a staging area determined in step 3
5. Once all firmware chunks are downloaded, the PLDM stack will notify the API to verify the component
   1. If the component is a SOC Manifest, the MCU will send a SET_AUTH_MANIFEST mailbox command that contains the downloaded manifest to the Caliptra Core. The mailbox command response will indicate the authenticity and correctness of the manifest
   2. If the component is a MCU RT or SOC Image, the MCU will send the AUTHORIZE_AND_STASH command with an indication that the image to be verified is in the staging area.
6. After verification, PLDM Stack will notify API to apply the image. MCU will write the images to permanent storage from the temporary or staging area.
7. When Update Agent sends the 'ActivateFirmware' command, the API will get a notification and prompts it to send an 'ActivateImage' mailbox command to the Caliptra core. Actions taken by the Caliptra core are described in [the main Caliptra specification.](https://github.com/chipsalliance/Caliptra/blob/main/doc/Caliptra.md#subsystem-support-for-hitless-updates)

## Interfaces

```
pub trait FirmwareUpdateApi {

    /// Start the firmware update service.
    /// 
    /// # Arguments
    /// device_identifier - The PLDM device identifier to be used.
    /// parameters - The PLDM firmware update parameters to be used.
    /// 
    /// # Returns
    /// Returns a future that will remain unset until the service is stopped.
    /// Ok(()) - The service has been terminated successfully.
    /// Err(FirmwareUpdateError) - The service has been terminated with an error.
    async fn start_service(&self, device_identifier: DeviceIdentifiers, parameters: FirmwareParameters) -> Result<(), FirmwareUpdateError>;

    /// Stop the firmware update service.
    /// 
    /// # Returns
    /// Ok() - The service has been terminated successfully.
    /// Err(ErrorCode) - The service can not be stopped.
    fn stop_service(&self) -> Result<(), ErrorCode>;

    /// Register a callback to be called when a firmware update event occurs.
    /// 
    /// # Arguments
    /// callback - The callback to be called when a firmware update event occurs.
    fn register_callback(&self, callback: FirmwareUpdateCallback);


}

/// Define the callback function signature for firmware update events.
/// Returns Ok(()) if the notification is handled successfully, otherwise an error code.
pub type FirmwareUpdateCallback = fn(FirmwareUpdateNotification) -> Result<(),ErrorCode>;

pub enum FirmwareUpdateNotification<'a>{
    // Firmware Update is available and ready for download.
    UpdateAvailable,

    // Firmware Update is complete.
    UpdateComplete,

    // Firmware Update is cancelled.
    UpdateCancelled,

}
```
