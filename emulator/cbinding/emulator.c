/*++

Licensed under the Apache-2.0 license.

File Name:

    emulator.c

Abstract:

    C version of the Caliptra MCU Emulator main program.
    Supports the same command line arguments as the Rust version.

Build Instructions:

    This file is built automatically by the xtask system:
    
    For debug build:
    cargo xtask emulator-cbinding build-emulator
    
    For release build:
    cargo xtask emulator-cbinding build-emulator --release
    
    Build artifacts are organized in:
    <PROJECT_ROOT>/target/<debug|release>/emulator_cbinding/
    - libemulator_cbinding.a (static library)
    - emulator_cbinding.h (C header)
    - emulator (binary executable)
    - cfi_stubs.o (CFI stub object)

--*/

#define _DEFAULT_SOURCE  // For usleep on some systems
#include "emulator_cbinding.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>
#include <termios.h>
#include <fcntl.h>
#include <sys/select.h>

// Global emulator pointer for signal handler
static struct CEmulator* global_emulator = NULL;

// Terminal settings for raw input
static struct termios original_termios;
static int terminal_raw_mode = 0;

// Function to enable raw terminal mode for immediate character input
void enable_raw_mode() {
    if (terminal_raw_mode) return;
    
    if (tcgetattr(STDIN_FILENO, &original_termios) == -1) {
        return; // Not a terminal
    }
    
    struct termios raw = original_termios;
    // Disable echo and canonical mode, but keep output processing for proper newlines
    raw.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL | ICANON | ISIG | IEXTEN);
    raw.c_iflag &= ~(IXON | ICRNL | INLCR); // Disable flow control and CR/LF translation on input
    // Keep OPOST enabled for proper output formatting (newline handling)
    raw.c_cc[VMIN] = 0;  // Non-blocking read
    raw.c_cc[VTIME] = 0; // No timeout
    
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) == 0) {
        terminal_raw_mode = 1;
    }
}

// Function to restore terminal mode
void disable_raw_mode() {
    if (terminal_raw_mode) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &original_termios);
        terminal_raw_mode = 0;
    }
}

// Signal handler for Ctrl+C
void signal_handler(int sig) {
    if (sig == SIGINT) {
        printf("\nReceived SIGINT, requesting exit...\n");
        disable_raw_mode(); // Restore terminal
        emulator_trigger_exit();
    }
}

void print_usage(const char* program_name) {
    printf("Usage: %s [OPTIONS]\n", program_name);
    printf("\nCaliptra MCU Emulator\n\n");
    printf("Required arguments:\n");
    printf("  -r, --rom <ROM>                      ROM binary path\n");
    printf("  -f, --firmware <FIRMWARE>           Firmware binary path\n");
    printf("      --caliptra-rom <CALIPTRA_ROM>   The ROM path for the Caliptra CPU\n");
    printf("      --caliptra-firmware <CALIPTRA_FIRMWARE>\n");
    printf("                                       The Firmware path for the Caliptra CPU\n");
    printf("      --soc-manifest <SOC_MANIFEST>   SoC manifest path\n");
    printf("\nOptional arguments:\n");
    printf("  -o, --otp <OTP>                      Optional file to store OTP / fuses between runs\n");
    printf("  -g, --gdb-port <GDB_PORT>            GDB Debugger Port\n");
    printf("  -l, --log-dir <LOG_DIR>              Directory in which to log execution artifacts\n");
    printf("  -t, --trace-instr                    Trace instructions\n");
    printf("      --no-stdin-uart                  Don't pass stdin to the MCU UART Rx\n");
    printf("      --i3c-port <I3C_PORT>            I3C socket port\n");
    printf("      --manufacturing-mode             Enable manufacturing mode\n");
    printf("      --vendor-pk-hash <VENDOR_PK_HASH>\n");
    printf("                                       Vendor public key hash\n");
    printf("      --owner-pk-hash <OWNER_PK_HASH> Owner public key hash\n");
    printf("      --streaming-boot <STREAMING_BOOT>\n");
    printf("                                       Path to the streaming boot PLDM firmware package\n");
    printf("      --primary-flash-image <PRIMARY_FLASH_IMAGE>\n");
    printf("                                       Primary flash image path\n");
    printf("      --secondary-flash-image <SECONDARY_FLASH_IMAGE>\n");
    printf("                                       Secondary flash image path\n");
    printf("      --hw-revision <HW_REVISION>      HW revision in semver format (default: 2.0.0)\n");
    printf("  -h, --help                           Print help\n");
    printf("  -V, --version                        Print version\n");
    printf("\nMemory layout overrides (use hex values like 0x40000000):\n");
    printf("      --rom-offset <ROM_OFFSET>        Override ROM offset\n");
    printf("      --rom-size <ROM_SIZE>            Override ROM size\n");
    printf("      --uart-offset <UART_OFFSET>      Override UART offset\n");
    printf("      --uart-size <UART_SIZE>          Override UART size\n");
    printf("      --sram-offset <SRAM_OFFSET>      Override SRAM offset\n");
    printf("      --sram-size <SRAM_SIZE>          Override SRAM size\n");
    printf("      --pic-offset <PIC_OFFSET>        Override PIC offset\n");
    printf("      --dccm-offset <DCCM_OFFSET>      Override DCCM offset\n");
    printf("      --dccm-size <DCCM_SIZE>          Override DCCM size\n");
    printf("      --i3c-offset <I3C_OFFSET>        Override I3C offset\n");
    printf("      --i3c-size <I3C_SIZE>            Override I3C size\n");
    printf("      --mci-offset <MCI_OFFSET>        Override MCI offset\n");
    printf("      --mci-size <MCI_SIZE>            Override MCI size\n");
    printf("      --primary-flash-offset <PRIMARY_FLASH_OFFSET>\n");
    printf("                                       Override primary flash offset\n");
    printf("      --primary-flash-size <PRIMARY_FLASH_SIZE>\n");
    printf("                                       Override primary flash size\n");
    printf("      --secondary-flash-offset <SECONDARY_FLASH_OFFSET>\n");
    printf("                                       Override secondary flash offset\n");
    printf("      --secondary-flash-size <SECONDARY_FLASH_SIZE>\n");
    printf("                                       Override secondary flash size\n");
    printf("      --soc-offset <SOC_OFFSET>        Override Caliptra SoC interface offset\n");
    printf("      --soc-size <SOC_SIZE>            Override Caliptra SoC interface size\n");
    printf("      --otp-offset <OTP_OFFSET>        Override OTP offset\n");
    printf("      --otp-size <OTP_SIZE>            Override OTP size\n");
    printf("      --lc-offset <LC_OFFSET>          Override LC offset\n");
    printf("      --lc-size <LC_SIZE>              Override LC size\n");
    printf("      --mbox-offset <MBOX_OFFSET>      Override Caliptra mailbox offset\n");
    printf("      --mbox-size <MBOX_SIZE>          Override Caliptra mailbox size\n");
}

// Free run function similar to main.rs
void free_run(struct CEmulator* emulator) {
    printf("Running emulator in normal mode...\n");
    printf("Console input enabled - type characters to send to UART RX\n");
    
    // Enable raw terminal mode for immediate character input
    enable_raw_mode();
    
    // Buffer for UART output (streaming mode)
    const size_t uart_buffer_size = 1024;
    char* uart_buffer = malloc(uart_buffer_size);
    if (!uart_buffer) {
        fprintf(stderr, "Failed to allocate UART buffer\n");
        disable_raw_mode();
        return;
    }
    
    printf("Allocated UART buffer: %zu bytes\n", uart_buffer_size);
    
    int step_count = 0;
    while (1) {
        // Check for console input and send to UART RX if available
        char input_char;
        if (read(STDIN_FILENO, &input_char, 1) == 1) {
            // Handle special characters
            if (input_char == 3) { // Ctrl+C
                break;
            } else if (input_char == 127) { // Backspace
                input_char = 8; // Convert to ASCII backspace
            }
            
            // Try to send character to UART RX
            if (emulator_uart_rx_ready(emulator)) {
                emulator_send_uart_char(emulator, input_char);
                // No local echo - let the UART output handle display
            }
        }
        
        enum CStepAction action = emulator_step(emulator);
        
        // Check for UART output (streaming mode)
        int uart_len = emulator_get_uart_output_streaming(emulator, uart_buffer, uart_buffer_size);
        if (uart_len > 0) {
            // Print UART output to console (without extra newline if it already ends with one)
            printf("%.*s", uart_len, uart_buffer);
            fflush(stdout);
        }
        
        switch (action) {
            case Continue:
                step_count++;
                // Yield occasionally to avoid busy waiting
                if (step_count % 1000 == 0) {
                    usleep(100); // 0.1ms sleep every 1000 steps
                }
                break;
                
            case Break:
                printf("\nEmulator hit breakpoint after %d steps\n", step_count);
                disable_raw_mode();
                free(uart_buffer);
                return;
                
            case ExitSuccess:
                printf("\nEmulator finished successfully after %d steps\n", step_count);
                disable_raw_mode();
                free(uart_buffer);
                return;
                
            case ExitFailure:
                printf("\nEmulator exited with failure after %d steps\n", step_count);
                disable_raw_mode();
                free(uart_buffer);
                return;
        }
    }
    
    disable_raw_mode();
    free(uart_buffer);
}

unsigned int parse_hex_or_decimal(const char* str) {
    if (strncmp(str, "0x", 2) == 0 || strncmp(str, "0X", 2) == 0) {
        return (unsigned int)strtoul(str, NULL, 16);
    } else {
        return (unsigned int)strtoul(str, NULL, 10);
    }
}

int main(int argc, char *argv[]) {
    // Initialize config with defaults
    struct CEmulatorConfig config = {
        .mRomPath = NULL,
        .mFirmwarePath = NULL,
        .mCaliptraRomPath = NULL,
        .mCaliptraFirmwarePath = NULL,
        .mSocManifestPath = NULL,
        .mOtpPath = NULL,
        .mLogDirPath = NULL,
        .mGdbPort = 0,
        .mI3cPort = 0,
        .mTraceInstr = 0,
        .mStdinUart = 1,  // Default to true
        .mManufacturingMode = 0,
        .mCaptureUartOutput = 1,  // Default to capturing UART output
        .mVendorPkHash = NULL,
        .mOwnerPkHash = NULL,
        .mStreamingBootPath = NULL,
        .mPrimaryFlashImagePath = NULL,
        .mSecondaryFlashImagePath = NULL,
        .mHwRevisionMajor = 2,
        .mHwRevisionMinor = 0,
        .mHwRevisionPatch = 0,
        // Initialize all memory layout overrides to -1 (use defaults)
        .mRomOffset = -1,
        .mRomSize = -1,
        .mUartOffset = -1,
        .mUartSize = -1,
        .mCtrlOffset = -1,
        .mCtrlSize = -1,
        .mSpiOffset = -1,
        .mSpiSize = -1,
        .mSramOffset = -1,
        .mSramSize = -1,
        .mPicOffset = -1,
        .mExternalTestSramOffset = -1,
        .mExternalTestSramSize = -1,
        .mDccmOffset = -1,
        .mDccmSize = -1,
        .mI3cOffset = -1,
        .mI3cSize = -1,
        .mPrimaryFlashOffset = -1,
        .mPrimaryFlashSize = -1,
        .mSecondaryFlashOffset = -1,
        .mSecondaryFlashSize = -1,
        .mMciOffset = -1,
        .mMciSize = -1,
        .mDmaOffset = -1,
        .mDmaSize = -1,
        .mMboxOffset = -1,
        .mMboxSize = -1,
        .mSocOffset = -1,
        .mSocSize = -1,
        .mOtpOffset = -1,
        .mOtpSize = -1,
        .mLcOffset = -1,
        .mLcSize = -1,
        .mExternalReadCallback = NULL,
        .mExternalWriteCallback = NULL,
        .mCallbackContext = NULL,
    };

    // Define long options
    static struct option long_options[] = {
        {"rom", required_argument, 0, 'r'},
        {"firmware", required_argument, 0, 'f'},
        {"otp", required_argument, 0, 'o'},
        {"gdb-port", required_argument, 0, 'g'},
        {"log-dir", required_argument, 0, 'l'},
        {"trace-instr", no_argument, 0, 't'},
        {"no-stdin-uart", no_argument, 0, 128},
        {"caliptra-rom", required_argument, 0, 129},
        {"caliptra-firmware", required_argument, 0, 130},
        {"soc-manifest", required_argument, 0, 131},
        {"i3c-port", required_argument, 0, 132},
        {"manufacturing-mode", no_argument, 0, 133},
        {"vendor-pk-hash", required_argument, 0, 134},
        {"owner-pk-hash", required_argument, 0, 135},
        {"streaming-boot", required_argument, 0, 136},
        {"primary-flash-image", required_argument, 0, 137},
        {"secondary-flash-image", required_argument, 0, 138},
        {"hw-revision", required_argument, 0, 139},
        {"rom-offset", required_argument, 0, 140},
        {"rom-size", required_argument, 0, 141},
        {"uart-offset", required_argument, 0, 142},
        {"uart-size", required_argument, 0, 143},
        {"sram-offset", required_argument, 0, 144},
        {"sram-size", required_argument, 0, 145},
        {"pic-offset", required_argument, 0, 146},
        {"dccm-offset", required_argument, 0, 147},
        {"dccm-size", required_argument, 0, 148},
        {"i3c-offset", required_argument, 0, 149},
        {"i3c-size", required_argument, 0, 150},
        {"mci-offset", required_argument, 0, 151},
        {"mci-size", required_argument, 0, 152},
        {"primary-flash-offset", required_argument, 0, 153},
        {"primary-flash-size", required_argument, 0, 154},
        {"secondary-flash-offset", required_argument, 0, 155},
        {"secondary-flash-size", required_argument, 0, 156},
        {"soc-offset", required_argument, 0, 157},
        {"soc-size", required_argument, 0, 158},
        {"otp-offset", required_argument, 0, 159},
        {"otp-size", required_argument, 0, 160},
        {"lc-offset", required_argument, 0, 161},
        {"lc-size", required_argument, 0, 162},
        {"mbox-offset", required_argument, 0, 163},
        {"mbox-size", required_argument, 0, 164},
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0}
    };

    int c;
    int option_index = 0;
    
    while ((c = getopt_long(argc, argv, "r:f:o:g:l:thV", long_options, &option_index)) != -1) {
        switch (c) {
            case 'r':
                config.mRomPath = optarg;
                break;
            case 'f':
                config.mFirmwarePath = optarg;
                break;
            case 'o':
                config.mOtpPath = optarg;
                break;
            case 'g':
                config.mGdbPort = atoi(optarg);
                break;
            case 'l':
                config.mLogDirPath = optarg;
                break;
            case 't':
                config.mTraceInstr = 1;
                break;
            case 128: // --no-stdin-uart
                config.mStdinUart = 0;
                break;
            case 129: // --caliptra-rom
                config.mCaliptraRomPath = optarg;
                break;
            case 130: // --caliptra-firmware
                config.mCaliptraFirmwarePath = optarg;
                break;
            case 131: // --soc-manifest
                config.mSocManifestPath = optarg;
                break;
            case 132: // --i3c-port
                config.mI3cPort = atoi(optarg);
                break;
            case 133: // --manufacturing-mode
                config.mManufacturingMode = 1;
                break;
            case 134: // --vendor-pk-hash
                config.mVendorPkHash = optarg;
                break;
            case 135: // --owner-pk-hash
                config.mOwnerPkHash = optarg;
                break;
            case 136: // --streaming-boot
                config.mStreamingBootPath = optarg;
                break;
            case 137: // --primary-flash-image
                config.mPrimaryFlashImagePath = optarg;
                break;
            case 138: // --secondary-flash-image
                config.mSecondaryFlashImagePath = optarg;
                break;
            case 139: // --hw-revision
                // Parse semver format like "2.0.0"
                if (sscanf(optarg, "%u.%u.%u", &config.mHwRevisionMajor, 
                          &config.mHwRevisionMinor, &config.mHwRevisionPatch) != 3) {
                    fprintf(stderr, "Invalid hw-revision format. Expected format: major.minor.patch\n");
                    return 1;
                }
                break;
            case 140: // --rom-offset
                config.mRomOffset = parse_hex_or_decimal(optarg);
                break;
            case 141: // --rom-size
                config.mRomSize = parse_hex_or_decimal(optarg);
                break;
            case 142: // --uart-offset
                config.mUartOffset = parse_hex_or_decimal(optarg);
                break;
            case 143: // --uart-size
                config.mUartSize = parse_hex_or_decimal(optarg);
                break;
            case 144: // --sram-offset
                config.mSramOffset = parse_hex_or_decimal(optarg);
                break;
            case 145: // --sram-size
                config.mSramSize = parse_hex_or_decimal(optarg);
                break;
            case 146: // --pic-offset
                config.mPicOffset = parse_hex_or_decimal(optarg);
                break;
            case 147: // --dccm-offset
                config.mDccmOffset = parse_hex_or_decimal(optarg);
                break;
            case 148: // --dccm-size
                config.mDccmSize = parse_hex_or_decimal(optarg);
                break;
            case 149: // --i3c-offset
                config.mI3cOffset = parse_hex_or_decimal(optarg);
                break;
            case 150: // --i3c-size
                config.mI3cSize = parse_hex_or_decimal(optarg);
                break;
            case 151: // --mci-offset
                config.mMciOffset = parse_hex_or_decimal(optarg);
                break;
            case 152: // --mci-size
                config.mMciSize = parse_hex_or_decimal(optarg);
                break;
            case 153: // --primary-flash-offset
                config.mPrimaryFlashOffset = parse_hex_or_decimal(optarg);
                break;
            case 154: // --primary-flash-size
                config.mPrimaryFlashSize = parse_hex_or_decimal(optarg);
                break;
            case 155: // --secondary-flash-offset
                config.mSecondaryFlashOffset = parse_hex_or_decimal(optarg);
                break;
            case 156: // --secondary-flash-size
                config.mSecondaryFlashSize = parse_hex_or_decimal(optarg);
                break;
            case 157: // --soc-offset
                config.mSocOffset = parse_hex_or_decimal(optarg);
                break;
            case 158: // --soc-size
                config.mSocSize = parse_hex_or_decimal(optarg);
                break;
            case 159: // --otp-offset
                config.mOtpOffset = parse_hex_or_decimal(optarg);
                break;
            case 160: // --otp-size
                config.mOtpSize = parse_hex_or_decimal(optarg);
                break;
            case 161: // --lc-offset
                config.mLcOffset = parse_hex_or_decimal(optarg);
                break;
            case 162: // --lc-size
                config.mLcSize = parse_hex_or_decimal(optarg);
                break;
            case 163: // --mbox-offset
                config.mMboxOffset = parse_hex_or_decimal(optarg);
                break;
            case 164: // --mbox-size
                config.mMboxSize = parse_hex_or_decimal(optarg);
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            case 'V':
                printf("Caliptra MCU Emulator (C binding) 1.0.0\n");
                return 0;
            case '?':
                // getopt_long already printed an error message
                return 1;
            default:
                abort();
        }
    }

    // Check required arguments
    if (!config.mRomPath) {
        fprintf(stderr, "Error: ROM path is required (--rom)\n");
        print_usage(argv[0]);
        return 1;
    }
    if (!config.mFirmwarePath) {
        fprintf(stderr, "Error: Firmware path is required (--firmware)\n");
        print_usage(argv[0]);
        return 1;
    }
    if (!config.mCaliptraRomPath) {
        fprintf(stderr, "Error: Caliptra ROM path is required (--caliptra-rom)\n");
        print_usage(argv[0]);
        return 1;
    }
    if (!config.mCaliptraFirmwarePath) {
        fprintf(stderr, "Error: Caliptra firmware path is required (--caliptra-firmware)\n");
        print_usage(argv[0]);
        return 1;
    }
    if (!config.mSocManifestPath) {
        fprintf(stderr, "Error: SoC manifest path is required (--soc-manifest)\n");
        print_usage(argv[0]);
        return 1;
    }

    // Set up signal handler for Ctrl+C
    signal(SIGINT, signal_handler);

    // Get memory requirements and allocate
    size_t emulator_size = emulator_get_size();
    size_t emulator_alignment = emulator_get_alignment();
    
    void* memory = aligned_alloc(emulator_alignment, emulator_size);
    if (!memory) {
        fprintf(stderr, "Failed to allocate memory: %s\n", strerror(errno));
        return 1;
    }

    printf("Allocated %zu bytes for emulator (alignment: %zu)\n", emulator_size, emulator_alignment);

    // Initialize emulator
    enum EmulatorError result = emulator_init((struct CEmulator*)memory, &config);
    if (result != Success) {
        fprintf(stderr, "Failed to initialize emulator: %d\n", result);
        free(memory);
        return 1;
    }

    global_emulator = (struct CEmulator*)memory;
    printf("Emulator initialized successfully\n");

    // Check if we're in GDB mode
    if (emulator_is_gdb_mode(global_emulator)) {
        unsigned int port = emulator_get_gdb_port(global_emulator);
        printf("GDB server available on port %u\n", port);
        printf("Connect with: gdb -ex 'target remote :%u'\n", port);
        
        // Start GDB server (blocking)
        printf("Starting GDB server (this will block until GDB disconnects)\n");
        enum EmulatorError gdb_result = emulator_run_gdb_server(global_emulator);
        if (gdb_result == Success) {
            printf("GDB session completed successfully\n");
        } else {
            printf("GDB session failed with error %d\n", gdb_result);
        }
    } else {
        // Normal mode - free run like main.rs
        free_run(global_emulator);
    }

    // Final UART output check (get any remaining output)
    char final_output[4096];
    int final_len = emulator_get_uart_output_streaming(global_emulator, final_output, sizeof(final_output) - 1);
    if (final_len > 0) {
        final_output[final_len] = '\0';
        printf("Final UART output:\n%s", final_output);
    }

    // Clean up
    disable_raw_mode(); // Ensure terminal is restored
    emulator_destroy(global_emulator);
    free(memory);
    
    printf("Emulator cleaned up\n");
    return 0;
}
