// Licensed under the Apache-2.0 license

#define _POSIX_C_SOURCE 200809L
#include <libusb.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

int main(void) {
    libusb_context *context = NULL;
    libusb_device_handle *device = NULL;
    int status = libusb_init(&context);
    if (status < 0) {
        fprintf(stderr, "libusb_init: %s\n", libusb_error_name(status));
        return 1;
    }

    const struct timespec delay = {.tv_sec = 0, .tv_nsec = 100000000};
    for (int attempt = 0; attempt < 100; ++attempt) {
        device = libusb_open_device_with_vid_pid(context, 0xca5e, 0x0001);
        if (device != NULL) {
            break;
        }
        nanosleep(&delay, NULL);
    }
    if (device == NULL) {
        fprintf(stderr, "USB/IP device ca5e:0001 did not enumerate/open within 10 seconds\n");
        libusb_exit(context);
        return 1;
    }

    int result = 1;
    int configuration = 0;
    for (int attempt = 0; attempt < 100; ++attempt) {
        status = libusb_get_configuration(device, &configuration);
        if (status < 0 || configuration == 1) {
            break;
        }
        nanosleep(&delay, NULL);
    }
    if (status < 0 || configuration != 1) {
        fprintf(stderr, "Expected configuration 1, got %d (%s)\n",
                configuration, libusb_error_name(status));
        goto cleanup;
    }

    unsigned char payload[] = "host-device round trip over Linux USB/IP";
    unsigned char response[64] = {0};
    const int length = sizeof(payload) - 1;
    status = libusb_control_transfer(device, 0x40, 0x5a, 0, 0, payload, length, 3000);
    if (status != length) {
        fprintf(stderr, "Control OUT: expected %d bytes, got %d (%s)\n",
                length, status, libusb_error_name(status));
        goto cleanup;
    }
    status = libusb_control_transfer(device, 0xc0, 0x5b, 0, 0,
                                     response, sizeof(response), 3000);
    if (status != length || memcmp(payload, response, length) != 0) {
        fprintf(stderr, "Control IN payload mismatch: expected %d bytes, got %d (%s)\n",
                length, status, libusb_error_name(status));
        goto cleanup;
    }
    printf("PASS: configured USB device ca5e:0001; %d-byte OUT/IN payload round trip via libusb + VHCI + USB/IP\n",
           length);
    result = 0;

cleanup:
    libusb_close(device);
    libusb_exit(context);
    return result;
}
