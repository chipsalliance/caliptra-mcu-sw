# Caliptra C Bindings Tests

This directory contains test utilities and test programs for the Caliptra C bindings library.

## Test Structure

### Test Headers
- `caliptra_test_utils.h` - Test-specific utilities and C MailboxDriver definitions (local to tests)

### Test Programs  
- `test_custom_c_mock.c` - Demonstration of pure C-based MailboxDriver creation

### Build System
- `Makefile` - Build configuration for all tests
- `cbindgen_test.toml` - Test-specific cbindgen configuration (if needed)

## Testing Utilities

The testing utilities provide a complete pure C implementation of a MailboxDriver:

### CMockMailboxDriver
The `CMockMailboxDriver` is an opaque struct that provides complete MailboxDriver functionality implemented entirely in C.

### Testing Functions
- `caliptra_mock_mailbox_driver_create()` - Create complete C MailboxDriver implementation
- `caliptra_mock_mailbox_driver_destroy()` - Clean up C MailboxDriver
- `caliptra_transport_create_from_c_mailbox_driver()` - Create transport from C MailboxDriver

## Usage Example

### Pure C MailboxDriver (Preferred Approach)
```c
#include "../include/caliptra.h"
#include "caliptra_test_utils.h"

// Create complete C MailboxDriver implementation
struct CMockMailboxDriver* driver = NULL;
caliptra_mock_mailbox_driver_create(0x1234, &driver);

// Create transport from C MailboxDriver
CaliptraTransport* transport = NULL;
caliptra_transport_create_from_c_mailbox_driver(driver, &transport);

// Use transport for session operations...

// Cleanup
caliptra_mock_mailbox_driver_destroy(driver);
```

## Building and Running

```bash
# Build all tests
make

# Run all tests  
make test

# Build and run specific test
make test_custom_c_mock && ./test_custom_c_mock
```

## Key Benefits of This Structure

1. **Separation of Concerns**: Test utilities are isolated from production API
2. **Clean Main API**: The main `../include/` directory only contains production headers  
3. **Pure C Implementation**: Complete MailboxDriver implementation in C with no Rust dependencies
4. **Opaque Struct Design**: CMockMailboxDriver provides encapsulation and clean API
5. **Local Dependencies**: Test headers are local to the test directory

## Note

These testing utilities should **never** be used in production code. They are designed specifically for testing the C bindings and validating the API functionality.