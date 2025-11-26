// Licensed under the Apache-2.0 license

#include "caliptra_test_utils.h"
#include <stdlib.h>
#include <string.h>

// Forward declarations for the default MailboxDriver implementation functions
static enum CaliptraError c_mock_mailbox_send_command(
    struct CMailboxDriver *driver,
    uint32_t external_cmd,
    const uint8_t *payload,
    uintptr_t payload_len,
    const uint8_t **response,
    uintptr_t *response_len
);

static bool c_mock_mailbox_is_ready(struct CMailboxDriver *driver);
static enum CaliptraError c_mock_mailbox_connect(struct CMailboxDriver *driver);
static enum CaliptraError c_mock_mailbox_disconnect(struct CMailboxDriver *driver);

// Default vtable instance
static CMailboxDriverVTable default_vtable = {
    .send_command = c_mock_mailbox_send_command,
    .is_ready = c_mock_mailbox_is_ready,
    .connect = c_mock_mailbox_connect,
    .disconnect = c_mock_mailbox_disconnect
};

enum CaliptraError caliptra_mock_mailbox_driver_create(uint16_t device_id, 
                                                       struct CMailboxDriver **driver) {
    if (driver == NULL) {
        return InvalidArgument;
    }

    // Allocate the driver
    struct CMailboxDriver *new_driver = malloc(sizeof(struct CMailboxDriver));
    if (new_driver == NULL) {
        return Memory;
    }

    // Initialize the driver with default values
    new_driver->vtable = &default_vtable;
    new_driver->device_id = device_id;
    new_driver->vendor_id = 0x1234;
    new_driver->subsystem_vendor_id = 0x5678;
    new_driver->subsystem_id = 0x9ABC;
    new_driver->ready = true;
    new_driver->connected = false;
    memset(new_driver->response_buffer, 0, sizeof(new_driver->response_buffer));

    *driver = new_driver;
    return Success;
}

enum CaliptraError caliptra_mock_mailbox_driver_destroy(struct CMailboxDriver *driver) {
    if (driver == NULL) {
        return InvalidArgument;
    }

    // Free the driver (vtable is static, so no need to free it)
    free(driver);
    return Success;
}

// Default C implementation functions
static enum CaliptraError c_mock_mailbox_send_command(
    struct CMailboxDriver *driver,
    uint32_t external_cmd,
    const uint8_t *payload,
    uintptr_t payload_len,
    const uint8_t **response,
    uintptr_t *response_len
) {
    (void)payload;      // Mark unused parameter
    (void)payload_len;  // Mark unused parameter
    if (driver == NULL || response == NULL || response_len == NULL) {
        return InvalidArgument;
    }

    if (!driver->ready) {
        return Device;
    }
    
    if (!driver->connected) {
        return Transport;
    }

    // Mock responses for external mailbox commands
    switch (external_cmd) {
        case 0x4D444944: { // MC_DEVICE_ID ("MDID")
            // Build GetDeviceId response
            uint8_t *response_data = driver->response_buffer;
            size_t offset = 0;
            
            // Simple response structure (checksum + payload)
            // This is a simplified version - real implementation would calculate proper checksum
            
            // Checksum (placeholder)
            uint32_t checksum = 0x00000000;
            memcpy(&response_data[offset], &checksum, sizeof(checksum));
            offset += sizeof(checksum);
            
            // FIPS status  
            uint32_t fips_status = 0x00000001;
            memcpy(&response_data[offset], &fips_status, sizeof(fips_status));
            offset += sizeof(fips_status);
            
            // Vendor ID
            memcpy(&response_data[offset], &driver->vendor_id, sizeof(driver->vendor_id));
            offset += sizeof(driver->vendor_id);
            
            // Device ID
            memcpy(&response_data[offset], &driver->device_id, sizeof(driver->device_id));
            offset += sizeof(driver->device_id);
            
            // Subsystem Vendor ID
            memcpy(&response_data[offset], &driver->subsystem_vendor_id, sizeof(driver->subsystem_vendor_id));
            offset += sizeof(driver->subsystem_vendor_id);
            
            // Subsystem ID
            memcpy(&response_data[offset], &driver->subsystem_id, sizeof(driver->subsystem_id));
            offset += sizeof(driver->subsystem_id);
            
            *response = response_data;
            *response_len = offset;
            return Success;
        }
        case 0x4D434150: { // MC_DEVICE_CAPABILITIES ("MCAP")
            uint8_t *response_data = driver->response_buffer;
            uint8_t capabilities[] = {0x01, 0x00, 0xFF, 0xFF};
            memcpy(response_data, capabilities, sizeof(capabilities));
            *response = response_data;
            *response_len = sizeof(capabilities);
            return Success;
        }
        case 0x4D44494E: { // MC_DEVICE_INFO ("MDIN")
            uint8_t *response_data = driver->response_buffer;
            uint8_t device_info[] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00};
            memcpy(response_data, device_info, sizeof(device_info));
            *response = response_data;
            *response_len = sizeof(device_info);
            return Success;
        }
        default:
            return NotSupported;
    }
}

static bool c_mock_mailbox_is_ready(struct CMailboxDriver *driver) {
    if (driver == NULL) {
        return false;
    }
    return driver->ready;
}

static enum CaliptraError c_mock_mailbox_connect(struct CMailboxDriver *driver) {
    if (driver == NULL) {
        return InvalidArgument;
    }
    
    if (!driver->ready) {
        return Transport;
    }
    
    driver->connected = true;
    return Success;
}

static enum CaliptraError c_mock_mailbox_disconnect(struct CMailboxDriver *driver) {
    if (driver == NULL) {
        return InvalidArgument;
    }
    
    driver->connected = false;
    return Success;
}

// Test utility functions

enum CaliptraError caliptra_cmd_get_device_id_demo(struct GetDeviceIdResponse *device_id) {
    if (device_id == NULL) {
        return InvalidArgument;
    }

    // Return mock device ID data for testing
    device_id->vendor_id = 0x1234;
    device_id->device_id = 0x5678;
    device_id->subsystem_vendor_id = 0x9ABC;
    device_id->subsystem_id = 0xDEF0;
    
    return Success;
}