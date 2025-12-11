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
#include <errno.h>

#ifdef _WIN32
    #include <windows.h>
    #include <conio.h>
    #include <io.h>
    #include <malloc.h>
    #define STDIN_FILENO 0

    // Windows doesn't have getopt, so we'll use a simplified version
    char *optarg = NULL;
    int optind = 1;
    int opterr = 1;
    int optopt = 0;

    // Windows getopt_long structures and constants
    struct option {
        const char *name;
        int has_arg;
        int *flag;
        int val;
    };

    #define no_argument 0
    #define required_argument 1
    #define optional_argument 2

    int getopt(int argc, char * const argv[], const char *optstring);
    int getopt_long(int argc, char * const argv[], const char *optstring,
                   const struct option *longopts, int *longindex);

    // Windows signal handling
    #include <signal.h>

    // Windows equivalent of aligned_alloc
    #define aligned_alloc(alignment, size) _aligned_malloc(size, alignment)

    // Windows POSIX function mappings
    #define read _read

#else
    #include <unistd.h>
    #include <signal.h>
    #include <getopt.h>
    #include <termios.h>
    #include <fcntl.h>
    #include <sys/select.h>
#endif

#ifdef _WIN32
// Windows implementation of getopt
int getopt(int argc, char * const argv[], const char *optstring) {
    static int sp = 1;
    int c;
    char *cp;

    if (sp == 1) {
        if (optind >= argc || argv[optind][0] != '-' || argv[optind][1] == '\0')
            return -1;
        else if (strcmp(argv[optind], "--") == 0) {
            optind++;
            return -1;
        }
    }
    optopt = c = argv[optind][sp];
    if (c == ':' || (cp = strchr(optstring, c)) == NULL) {
        if (opterr)
            fprintf(stderr, "illegal option -- %c\n", c);
        if (argv[optind][++sp] == '\0') {
            optind++;
            sp = 1;
        }
        return '?';
    }
    if (*++cp == ':') {
        if (argv[optind][sp+1] != '\0')
            optarg = &argv[optind++][sp+1];
        else if (++optind >= argc) {
            if (opterr)
                fprintf(stderr, "option requires an argument -- %c\n", c);
            sp = 1;
            return '?';
        } else
            optarg = argv[optind++];
        sp = 1;
    } else {
        if (argv[optind][++sp] == '\0') {
            sp = 1;
            optind++;
        }
        optarg = NULL;
    }
    return c;
}

// Windows implementation of getopt_long
int getopt_long(int argc, char * const argv[], const char *optstring,
               const struct option *longopts, int *longindex) {
    static int sp = 1;
    int c;
    char *cp;

    if (longindex) *longindex = -1;

    if (sp == 1) {
        if (optind >= argc || argv[optind][0] != '-' || argv[optind][1] == '\0')
            return -1;
        else if (strcmp(argv[optind], "--") == 0) {
            optind++;
            return -1;
        } else if (argv[optind][0] == '-' && argv[optind][1] == '-') {
            // Long option
            char *long_name = argv[optind] + 2;
            char *equals_pos = strchr(long_name, '=');
            int name_len = equals_pos ? (int)(equals_pos - long_name) : (int)strlen(long_name);

            // Find matching long option
            for (int i = 0; longopts[i].name; i++) {
                if (strncmp(longopts[i].name, long_name, name_len) == 0 &&
                    strlen(longopts[i].name) == name_len) {
                    if (longindex) *longindex = i;

                    if (longopts[i].has_arg == required_argument) {
                        if (equals_pos) {
                            optarg = equals_pos + 1;
                        } else if (++optind >= argc) {
                            if (opterr)
                                fprintf(stderr, "option '--%s' requires an argument\n", longopts[i].name);
                            return '?';
                        } else {
                            optarg = argv[optind];
                        }
                        optind++;
                    } else {
                        if (equals_pos) {
                            if (opterr)
                                fprintf(stderr, "option '--%s' doesn't allow an argument\n", longopts[i].name);
                            return '?';
                        }
                        optarg = NULL;
                        optind++;
                    }

                    return longopts[i].val;
                }
            }

            if (opterr)
                fprintf(stderr, "unrecognized option '--%.*s'\n", name_len, long_name);
            optind++;
            return '?';
        }
    }

    // Short option - use regular getopt logic
    optopt = c = argv[optind][sp];
    if (c == ':' || (cp = strchr(optstring, c)) == NULL) {
        if (opterr)
            fprintf(stderr, "illegal option -- %c\n", c);
        if (argv[optind][++sp] == '\0') {
            optind++;
            sp = 1;
        }
        return '?';
    }
    if (*++cp == ':') {
        if (argv[optind][sp+1] != '\0')
            optarg = &argv[optind++][sp+1];
        else if (++optind >= argc) {
            if (opterr)
                fprintf(stderr, "option requires an argument -- %c\n", c);
            sp = 1;
            return '?';
        } else
            optarg = argv[optind++];
        sp = 1;
    } else {
        if (argv[optind][++sp] == '\0') {
            sp = 1;
            optind++;
        }
        optarg = NULL;
    }
    return c;
}

// Windows sleep function (usleep equivalent)
void usleep(unsigned int microseconds) {
    if (microseconds >= 1000) {
        Sleep(microseconds / 1000); // Sleep takes milliseconds
    } else if (microseconds > 0) {
        Sleep(1); // Minimum 1ms sleep for sub-millisecond requests
    }
}

// Windows version of kbhit check
int kbhit_available() {
    return _kbhit();
}

// Windows version of getch
int getch_char() {
    return _getch();
}

#else

// Unix versions
int kbhit_available() {
    fd_set read_fds;
    struct timeval timeout;

    FD_ZERO(&read_fds);
    FD_SET(STDIN_FILENO, &read_fds);
    timeout.tv_sec = 0;
    timeout.tv_usec = 0;

    return select(STDIN_FILENO + 1, &read_fds, NULL, NULL, &timeout) > 0;
}

int getch_char() {
    return getchar();
}

#endif

// Global emulator pointer for signal handler
static struct CEmulator* global_emulator = NULL;

// Function declarations
void free_run(struct CEmulator* emulator);

// Terminal settings for raw input
#ifdef _WIN32
    static DWORD original_console_mode;
    static int terminal_raw_mode = 0;
#else
    static struct termios original_termios;
    static int terminal_raw_mode = 0;
#endif

// Function to enable raw terminal mode for immediate character input
void enable_raw_mode() {
    if (terminal_raw_mode) return;

#ifdef _WIN32
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    if (hStdin == INVALID_HANDLE_VALUE) return;

    if (!GetConsoleMode(hStdin, &original_console_mode)) return;

    DWORD new_mode = original_console_mode;
    new_mode &= ~(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT);

    if (SetConsoleMode(hStdin, new_mode)) {
        terminal_raw_mode = 1;
    }
#else
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
#endif
}

// Function to restore terminal mode
void disable_raw_mode() {
    if (terminal_raw_mode) {
#ifdef _WIN32
        HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
        if (hStdin != INVALID_HANDLE_VALUE) {
            SetConsoleMode(hStdin, original_console_mode);
        }
        terminal_raw_mode = 0;
#else
        if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &original_termios) == 0) {
            terminal_raw_mode = 0;
        }
        // Even if tcsetattr fails, reset our flag to avoid repeated attempts
        terminal_raw_mode = 0;
#endif
    }
}

// Signal handler for various termination signals
void signal_handler(int sig) {
    const char* sig_name = "UNKNOWN";
    switch (sig) {
        case SIGINT: sig_name = "SIGINT"; break;
#ifndef _WIN32
        case SIGTERM: sig_name = "SIGTERM"; break;
        case SIGHUP: sig_name = "SIGHUP"; break;
        case SIGQUIT: sig_name = "SIGQUIT"; break;
#endif
    }

    printf("\nReceived %s, requesting exit...\n", sig_name);
    disable_raw_mode(); // Restore terminal

    if (sig == SIGINT) {
        emulator_trigger_exit();
    } else {
        // For other signals, exit immediately
        exit(1);
    }
}

// atexit handler to ensure terminal is always restored
void cleanup_on_exit(void) {
    disable_raw_mode();
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
    printf("      --device-security-state <value>     Device lifecycle: 0=Unprovisioned, 1=Manufacturing, 2=Reserved, 3=Production\n");
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
        // Only check input every 100 steps to reduce overhead
        if (step_count % 100 == 0) {
#ifdef _WIN32
            if (kbhit_available()) {
                char input_char = (char)getch_char();
#else
            char input_char;
            if (read(STDIN_FILENO, &input_char, 1) == 1) {
#endif
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
        }

        enum CStepAction action = emulator_step(emulator);

        // Check for UART output (streaming mode)
        int uart_len = emulator_get_uart_output_streaming(emulator, uart_buffer, uart_buffer_size);
        if (uart_len > 0) {
            // Print UART output to stderr to match Rust emulator behavior
            fprintf(stderr, "%.*s", uart_len, uart_buffer);
            fflush(stderr);
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
        .rom_path = NULL,
        .firmware_path = NULL,
        .caliptra_rom_path = NULL,
        .caliptra_firmware_path = NULL,
        .soc_manifest_path = NULL,
        .otp_path = NULL,
        .log_dir_path = NULL,
        .gdb_port = 0,
        .i3c_port = 0,
        .trace_instr = 0,
        .stdin_uart = 1,  // Default to true
        .device_security_state = 3, // Default to Production lifecycle
        .capture_uart_output = 1,  // Default to capturing UART output
        .vendor_pk_hash = NULL,
        .owner_pk_hash = NULL,
        .streaming_boot_path = NULL,
        .primary_flash_image_path = NULL,
        .secondary_flash_image_path = NULL,
        .hw_revision_major = 2,
        .hw_revision_minor = 0,
        .hw_revision_patch = 0,
        // Initialize all memory layout overrides to -1 (use defaults)
        .rom_offset = -1,
        .rom_size = -1,
        .uart_offset = -1,
        .uart_size = -1,
        .ctrl_offset = -1,
        .ctrl_size = -1,
        .sram_offset = -1,
        .sram_size = -1,
        .pic_offset = -1,
        .external_test_sram_offset = -1,
        .external_test_sram_size = -1,
        .dccm_offset = -1,
        .dccm_size = -1,
        .i3c_offset = -1,
        .i3c_size = -1,
        .primary_flash_offset = -1,
        .primary_flash_size = -1,
        .secondary_flash_offset = -1,
        .secondary_flash_size = -1,
        .mci_offset = -1,
        .mci_size = -1,
        .dma_offset = -1,
        .dma_size = -1,
        .mbox_offset = -1,
        .mbox_size = -1,
        .soc_offset = -1,
        .soc_size = -1,
        .otp_offset = -1,
        .otp_size = -1,
        .lc_offset = -1,
        .lc_size = -1,
        .external_read_callback = NULL,
        .external_write_callback = NULL,
        .callback_context = NULL,
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
        {"device-security-state", required_argument, 0, 133},
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
                config.rom_path = optarg;
                break;
            case 'f':
                config.firmware_path = optarg;
                break;
            case 'o':
                config.otp_path = optarg;
                break;
            case 'g':
                config.gdb_port = atoi(optarg);
                break;
            case 'l':
                config.log_dir_path = optarg;
                break;
            case 't':
                config.trace_instr = 1;
                break;
            case 128: // --no-stdin-uart
                config.stdin_uart = 0;
                break;
            case 129: // --caliptra-rom
                config.caliptra_rom_path = optarg;
                break;
            case 130: // --caliptra-firmware
                config.caliptra_firmware_path = optarg;
                break;
            case 131: // --soc-manifest
                config.soc_manifest_path = optarg;
                break;
            case 132: // --i3c-port
                config.i3c_port = atoi(optarg);
                break;
            case 133: // --device-security-state
                config.device_security_state = parse_hex_or_decimal(optarg);
                break;
            case 134: // --vendor-pk-hash
                config.vendor_pk_hash = optarg;
                break;
            case 135: // --owner-pk-hash
                config.owner_pk_hash = optarg;
                break;
            case 136: // --streaming-boot
                config.streaming_boot_path = optarg;
                break;
            case 137: // --primary-flash-image
                config.primary_flash_image_path = optarg;
                break;
            case 138: // --secondary-flash-image
                config.secondary_flash_image_path = optarg;
                break;
            case 139: // --hw-revision
                // Parse semver format like "2.0.0"
                if (sscanf(optarg, "%u.%u.%u", &config.hw_revision_major,
                          &config.hw_revision_minor, &config.hw_revision_patch) != 3) {
                    fprintf(stderr, "Invalid hw-revision format. Expected format: major.minor.patch\n");
                    return 1;
                }
                break;
            case 140: // --rom-offset
                config.rom_offset = parse_hex_or_decimal(optarg);
                break;
            case 141: // --rom-size
                config.rom_size = parse_hex_or_decimal(optarg);
                break;
            case 142: // --uart-offset
                config.uart_offset = parse_hex_or_decimal(optarg);
                break;
            case 143: // --uart-size
                config.uart_size = parse_hex_or_decimal(optarg);
                break;
            case 144: // --sram-offset
                config.sram_offset = parse_hex_or_decimal(optarg);
                break;
            case 145: // --sram-size
                config.sram_size = parse_hex_or_decimal(optarg);
                break;
            case 146: // --pic-offset
                config.pic_offset = parse_hex_or_decimal(optarg);
                break;
            case 147: // --dccm-offset
                config.dccm_offset = parse_hex_or_decimal(optarg);
                break;
            case 148: // --dccm-size
                config.dccm_size = parse_hex_or_decimal(optarg);
                break;
            case 149: // --i3c-offset
                config.i3c_offset = parse_hex_or_decimal(optarg);
                break;
            case 150: // --i3c-size
                config.i3c_size = parse_hex_or_decimal(optarg);
                break;
            case 151: // --mci-offset
                config.mci_offset = parse_hex_or_decimal(optarg);
                break;
            case 152: // --mci-size
                config.mci_size = parse_hex_or_decimal(optarg);
                break;
            case 153: // --primary-flash-offset
                config.primary_flash_offset = parse_hex_or_decimal(optarg);
                break;
            case 154: // --primary-flash-size
                config.primary_flash_size = parse_hex_or_decimal(optarg);
                break;
            case 155: // --secondary-flash-offset
                config.secondary_flash_offset = parse_hex_or_decimal(optarg);
                break;
            case 156: // --secondary-flash-size
                config.secondary_flash_size = parse_hex_or_decimal(optarg);
                break;
            case 157: // --soc-offset
                config.soc_offset = parse_hex_or_decimal(optarg);
                break;
            case 158: // --soc-size
                config.soc_size = parse_hex_or_decimal(optarg);
                break;
            case 159: // --otp-offset
                config.otp_offset = parse_hex_or_decimal(optarg);
                break;
            case 160: // --otp-size
                config.otp_size = parse_hex_or_decimal(optarg);
                break;
            case 161: // --lc-offset
                config.lc_offset = parse_hex_or_decimal(optarg);
                break;
            case 162: // --lc-size
                config.lc_size = parse_hex_or_decimal(optarg);
                break;
            case 163: // --mbox-offset
                config.mbox_offset = parse_hex_or_decimal(optarg);
                break;
            case 164: // --mbox-size
                config.mbox_size = parse_hex_or_decimal(optarg);
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
    if (!config.rom_path) {
        fprintf(stderr, "Error: ROM path is required (--rom)\n");
        print_usage(argv[0]);
        return 1;
    }
    if (!config.firmware_path) {
        fprintf(stderr, "Error: Firmware path is required (--firmware)\n");
        print_usage(argv[0]);
        return 1;
    }
    if (!config.caliptra_rom_path) {
        fprintf(stderr, "Error: Caliptra ROM path is required (--caliptra-rom)\n");
        print_usage(argv[0]);
        return 1;
    }
    if (!config.caliptra_firmware_path) {
        fprintf(stderr, "Error: Caliptra firmware path is required (--caliptra-firmware)\n");
        print_usage(argv[0]);
        return 1;
    }
    if (!config.soc_manifest_path) {
        fprintf(stderr, "Error: SoC manifest path is required (--soc-manifest)\n");
        print_usage(argv[0]);
        return 1;
    }

    // Set up signal handlers for various termination signals
    signal(SIGINT, signal_handler);   // Ctrl+C
#ifndef _WIN32
    signal(SIGTERM, signal_handler);  // Termination request
    signal(SIGHUP, signal_handler);   // Hangup
    signal(SIGQUIT, signal_handler);  // Quit signal
#endif

    // Register cleanup function to run on normal exit
    atexit(cleanup_on_exit);

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
#ifdef _WIN32
        _aligned_free(memory);
#else
        free(memory);
#endif
        return 1;
    }
    
    // Start I3C controller if i3c_port was specified
    // Note: This must be done after emulator_init
    if (config.i3c_port != 0) {
        printf("Starting I3C controller...\n");
        result = emulator_start_i3c_controller((struct CEmulator*)memory);
        if (result != Success) {
            fprintf(stderr, "Failed to start I3C controller: %d\n", result);
            emulator_destroy((struct CEmulator*)memory);
#ifdef _WIN32
            _aligned_free(memory);
#else
            free(memory);
#endif
            return 1;
        }
    }

    global_emulator = (struct CEmulator*)memory;
    printf("Emulator initialized successfully\n");

    // Check if we're in GDB mode
    if (emulator_is_gdb_mode(global_emulator)) {
        unsigned int port = emulator_get_gdb_port(global_emulator);

        // Traditional blocking GDB mode
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
        fprintf(stderr, "Final UART output:\n%s", final_output);
    }

    // Clean up
    disable_raw_mode(); // Ensure terminal is restored
    emulator_destroy(global_emulator);
#ifdef _WIN32
    _aligned_free(memory);
#else
    free(memory);
#endif

    printf("Emulator cleaned up\n");
    return 0;
}
