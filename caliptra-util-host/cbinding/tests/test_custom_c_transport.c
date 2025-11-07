// Licensed under the Apache-2.0 license

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

// Include the main C API headers
#include "../include/caliptra_util_host.h"

/**
 * Integration test demonstrating custom C transport implementation.
 * 
 * This test shows how to:
 * 1. Implement a custom transport in pure C using function pointers
 * 2. Create a transport using the custom vtable approach
 * 3. Create a session with Custom protocol type
 * 4. Send/receive data through the custom transport (loopback example)
 * 
 * The custom transport implemented here is a simple loopback that echoes
 * back the sent message, demonstrating the integration mechanism.
 */

// Test assertion macro
#define TEST_ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            printf("FAIL: %s\n", message); \
            return -1; \
        } \
    } while(0)

#define TEST_ASSERT_EQ(actual, expected, message) \
    do { \
        if ((actual) != (expected)) { \
            printf("FAIL: %s (expected %d, got %d)\n", message, expected, actual); \
            return -1; \
        } \
    } while(0)

// Custom transport context that simulates a Caliptra device
typedef struct {
    bool connected;
    uint8_t response_buffer[1024];
    size_t response_len;
    uint32_t last_command_id;
    bool has_pending_response;
} MockCaliptraTransportCtx;

// Custom transport implementation functions
static enum CaliptraError mock_connect(void *ctx) {
    printf("  Custom transport: mock_connect called with ctx=%p\n", ctx);
    if (ctx == NULL) {
        printf("  ERROR: ctx is NULL in mock_connect\n");
        return InvalidArgument;
    }
    MockCaliptraTransportCtx *transport = (MockCaliptraTransportCtx*)ctx;
    printf("  Custom transport: Connecting mock Caliptra device\n");
    transport->connected = true;
    transport->has_pending_response = false;
    return Success;
}

static enum CaliptraError mock_disconnect(void *ctx) {
    MockCaliptraTransportCtx *transport = (MockCaliptraTransportCtx*)ctx;
    printf("  Custom transport: Disconnecting mock Caliptra device\n");
    transport->connected = false;
    transport->has_pending_response = false;
    return Success;
}

// Mock hardcoded GetDeviceId response
// This simulates a response that would contain GetDeviceIdResponse fields
static const uint8_t MOCK_DEVICE_ID_RESPONSE[] = {
    // GetDeviceIdResponse structure in little-endian:
    0x78, 0x12,  // vendor_id = 0x1278
    0x34, 0x56,  // device_id = 0x5634
    0x00, 0x00,  // subsystem_vendor_id = 0x0000
    0x00, 0x00   // subsystem_id = 0x0000
};

static enum CaliptraError mock_send(void *ctx, uint32_t command_id, const uint8_t *data, size_t len) {
    printf("  Custom transport: mock_send called with ctx=%p, command_id=0x%08X, len=%zu\n", ctx, command_id, len);
    if (ctx == NULL) {
        printf("  ERROR: ctx is NULL in mock_send\n");
        return InvalidArgument;
    }
    MockCaliptraTransportCtx *transport = (MockCaliptraTransportCtx*)ctx;
    
    if (!transport->connected) {
        return State;
    }
    
    if (len > 256) {  // Reasonable command size limit
        return InvalidArgument;
    }
    
    printf("  Custom transport: Sending %zu bytes with command_id 0x%08X to mock Caliptra device\n", len, command_id);
    
    // Store the command ID for analysis and prepare appropriate response
    transport->last_command_id = command_id;
    
    // For this demo, we assume any command is a GetDeviceId request
    // and prepare the hardcoded response
    transport->has_pending_response = true;
    memcpy(transport->response_buffer, MOCK_DEVICE_ID_RESPONSE, sizeof(MOCK_DEVICE_ID_RESPONSE));
    transport->response_len = sizeof(MOCK_DEVICE_ID_RESPONSE);
    
    printf("  Custom transport: Prepared hardcoded device ID response\n");
    return Success;
}

static enum CaliptraError mock_receive(void *ctx, uint8_t *buffer, size_t buffer_len, size_t *received_len) {
    MockCaliptraTransportCtx *transport = (MockCaliptraTransportCtx*)ctx;
    
    if (!transport->connected) {
        return State;
    }
    
    if (!transport->has_pending_response) {
        return IO; // No data available
    }
    
    if (buffer_len < transport->response_len) {
        return InvalidArgument;
    }
    
    printf("  Custom transport: Receiving %zu bytes (command_id was 0x%08X)\n", 
           transport->response_len, transport->last_command_id);
    
    // Return the hardcoded mock response
    memcpy(buffer, transport->response_buffer, transport->response_len);
    *received_len = transport->response_len;
    
    // Clear the pending response after receiving
    transport->has_pending_response = false;
    
    return Success;
}

static bool mock_is_connected(void *ctx) {
    MockCaliptraTransportCtx *transport = (MockCaliptraTransportCtx*)ctx;
    return transport->connected;
}

static void mock_destroy(void *ctx) {
    MockCaliptraTransportCtx *transport = (MockCaliptraTransportCtx*)ctx;
    printf("  Custom transport: Destroying mock Caliptra transport\n");
    // In a real implementation, you might free resources here
    transport->connected = false;
    transport->has_pending_response = false;
}

int test_custom_c_transport_device_id(void) {
    printf("\n=== Test: Custom C Transport (Mock Device ID) ===\n");
    
    enum CaliptraError result;
    struct CaliptraTransport* transport = NULL;
    struct CaliptraSession* session = NULL;
    
    // Note: No explicit library initialization needed for this basic demo
    
    // 1. Set up mock transport context
    MockCaliptraTransportCtx transport_ctx = {0};
    
    // 2. Define the transport vtable with our C functions
    struct CTransportVTable vtable = {
        .send = mock_send,
        .receive = mock_receive,
        .connect = mock_connect,
        .disconnect = mock_disconnect,
        .is_connected = mock_is_connected,
        .destroy = mock_destroy,
    };
    
    printf("✓ Created custom mock Caliptra transport implementation\n");
    
    // 3. Create transport using the custom vtable
    result = caliptra_transport_create_from_c_vtable(&vtable, &transport_ctx, &transport);
    TEST_ASSERT_EQ(result, Success, "Custom transport creation should succeed");
    TEST_ASSERT(transport != NULL, "Transport handle should not be NULL");
    
    printf("✓ Successfully created transport from C vtable\n");
    
    // 4. Create session with Custom protocol type
    result = caliptra_session_create_with_protocol(transport, Custom, &session);
    TEST_ASSERT_EQ(result, Success, "Session creation with custom protocol should succeed");
    TEST_ASSERT(session != NULL, "Session handle should not be NULL");
    
    printf("✓ Successfully created session with custom protocol\n");
    
    // 5. Connect the session (this will call our custom connect function)
    result = caliptra_session_connect(session);
    TEST_ASSERT_EQ(result, Success, "Session connect should succeed");
    TEST_ASSERT(transport_ctx.connected == true, "Transport should be connected");
    
    printf("✓ Successfully connected session (custom transport connected)\n");
    
    // 6. Test actual Caliptra command through custom transport
    // This demonstrates using the high-level API with a custom transport that returns hardcoded responses
    
    struct GetDeviceIdResponse device_id_response = {0};
    result = caliptra_cmd_get_device_id_c_impl(session, &device_id_response);
    TEST_ASSERT_EQ(result, Success, "Get device ID command should succeed");
    
    // Verify we got the expected mock device ID fields
    // Our hardcoded response has 0x78563412, which would map to device_id=0x5634, vendor_id=0x1278 in little-endian
    uint16_t expected_vendor_id = 0x1278;
    uint16_t expected_device_id = 0x5634;
    TEST_ASSERT(device_id_response.vendor_id == expected_vendor_id, "Vendor ID should match expected mock value");
    TEST_ASSERT(device_id_response.device_id == expected_device_id, "Device ID should match expected mock value");
    
    printf("✓ Successfully executed get_device_id through custom transport\n");
    printf("  Retrieved Vendor ID: 0x%04X, Device ID: 0x%04X\n", 
           device_id_response.vendor_id, device_id_response.device_id);
    printf("  Expected Vendor ID:  0x%04X, Device ID: 0x%04X\n", 
           expected_vendor_id, expected_device_id);
    
    // Verify transport context shows command was processed
    TEST_ASSERT(transport_ctx.has_pending_response == false, "Response should have been consumed");
    printf("✓ Verified transport state after command execution\n");
    
    // 7. Disconnect and cleanup
    result = caliptra_session_disconnect(session);
    TEST_ASSERT_EQ(result, Success, "Session disconnect should succeed");
    TEST_ASSERT(transport_ctx.connected == false, "Transport should be disconnected");
    
    printf("✓ Successfully disconnected session\n");
    
    // 8. Destroy session
    result = caliptra_session_destroy(session);
    TEST_ASSERT_EQ(result, Success, "Session destruction should succeed");
    
    printf("✓ Successfully destroyed session\n");
    
        // Note: No explicit library cleanup needed for this basic demo
    
    printf("✓ Custom C transport mock device test completed successfully!\n");
    printf("✓ Demonstrated: Custom transport implementation, session with Custom protocol, high-level API integration\n");
    
    return 0;
}

int main() {
    printf("Custom C Transport Integration Test\n");
    printf("===================================\n");
    
    int result = test_custom_c_transport_device_id();
    
    if (result == 0) {
        printf("\n✓ All tests PASSED!\n");
    } else {
        printf("\n✗ Some tests FAILED!\n");
    }
    
    return result;
}