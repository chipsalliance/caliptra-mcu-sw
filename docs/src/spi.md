# SPI Flash Stack

## Overview

The SPI flash stack in the Caliptra MCU firmware is designed to provide efficient and reliable communication with flash devices, which is the foundation to enable flash-based boot flow. This document outlines the different SPI flash configurations being supported, the stack architecture, component interface and userspace API to interact with the SPI flash stack.

## SPI Flash Configurations

The SPI flash stack supports various configurations to cater to different use cases and hardware setups. The diagram below shows the flash configurations supported.

<p align="center">
    <img src="images/flash_config.svg" alt="flash_config">
</p>

**1. Single-Flash Configuration**
In this setup, a single SPI flash device is connected to the flash controller. Typically, the flash device is divided into two halves: the first half serves as the primary flash, storing the active running firmware image, while the second half is designated as the recovery flash, containing the recovery image. Additional partitions, such as a staging area for firmware updates, flash storage for certificates and debug logging, can also be incorporated into the primary flash.

**2. Dual-Flash Configuration**
In this setup, two SPI flash devices are connected to the same flash controller using different chip selects. This configuration provides increased storage capacity and redundancy. Typically, flash device 0 serves as the primary flash, storing the active running firmware image and additional partitions such as a staging area for firmware updates, flash store for certificates and debug logging. Flash device 1 is designated as the recovery flash, containing the recovery image.

**3. Multi-Flash Configuration**
In more complex systems, multiple flash controllers may be used, each with one or more SPI flash devices. This configuration provides flexibility and scalability. For example, a backup flash can be added to recover the SoC and provide more resiliency for the system.

## Architecture

The SPI flash stack design leverages TockOS's kernel space support for the SPI host, SPI flash device and associated virtualizer layers. Our reference implementation employs the OpenTitan SPI host controller IP as the peripheral hardware. The stack, from top to bottom, comprises the flash userland API, flash partition capsule, SPI flash driver capsule, flash virtualizer, SPI virtualizer, and OpenTitan SPI host driver. SPI flash stack architecture with dual-flash configuration is shown in the diagram below.

<p align="center">
    <img src="images/spi_flash_stack.svg" alt="SPI flash stack architecture diagram">
</p>

- Flash Userland API
  - Provides syscall library for userspace applications to issue IO requests (read, write, erase) to flash devices. Userspace application will instantiate the syscall library with unique driver number for individual flash partition.

- Flash Partition Capsule
  - Defines the flash partition structure with offset and size, providing methods for reading, writing, and erasing arbitrary lengths of data within the partitions. Each partition is logically represented by a `FlashUser`, which leverages the existing flash virtualizer layer to ensure flash operations are serialized and managed correctly. It also implements `SyscallDriver` trait to interact with the userland API.

- SPI Flash Device Driver Capsule
  - Provides the functionality required to send common flash commands to flash device via `VirtualSpiMaster`. It implements the `kernel::hil::flash::Flash` trait, which defines the standard interface (read, write, erase) page-based operations. Additional methods could be provided in the driver:
    - Initialize the SPI flash device and configure settings such as clock speed, address mode and other parameters.
    - Check the status of the flash device, such as whether it is busy or ready for a new operation.
    - Erase larger regions of flash memory, such as sectors or blocks, in addition to individual pages.
    - Read the device ID, manufacturer ID or other identifying information from the flash device.
    - Retrieve information about the flash memory layout, such as the size of pages, sectors, and blocks from SFDP.
    - Advance read/write operations by performing fast read or write operations using specific commands supported by the flash device.

- SPI Host Driver (Vendor-specific)
  - Provides the functionality needed to control an SPI bus as a master device. It defines the memory-mapped registers for the SPI hardware, provides methods to configure the SPI bus settings, such as clock polarity and phase and to initiate read, write, and transfer operations. It implements the `SpiMaster` trait, providing methods for reading from, writing to, and transferring data over the SPI bus. It handles the completion of SPI operations by invoking client callbacks, allowing higher-level components to be notified when an SPI operation completes.

This architecture can be extended to accommodate vendor-specific flash controller hardware. The SPI flash driver capsule and SPI host driver will be replaced by flash controller driver capsule and associated virtualizer layer.

## Common Interfaces

### Flash Userland API

It is defined in SPI flash syscall library to provide async interface (read, write, erase) to underlying flash devices.

```Rust
///spi_flash/src/lib.rs
///
/// A structure representing an asynchronous SPI flash memory interface.
///
/// This structure is generic over two types:
/// - `S`: A type that implements the `Syscalls` trait, representing the system calls interface.
/// - `C`: A type that implements the `Config` trait, representing the configuration for the SPI flash.
///   By default, this is set to `DefaultConfig`.
///
/// # Fields
///
/// - `syscall`: A marker for the `Syscalls` type, used to indicate that this type is used without storing it.
/// - `config`: A marker for the `Config` type, used to indicate that this type is used without storing it.
/// - `driver_num`: The driver number associated with this SPI flash interface.
pub struct AsyncSpiFlash<S:Syscalls, C:Config = DefaultConfig > {
    syscall: PhantomData<S>,
    config: PhantomData<C>,
    driver_num: u32,
}

/// Represents an asynchronous SPI flash memory interface.
///
/// This struct provides methods to interact with SPI flash memory in an asynchronous manner,
/// allowing for non-blocking read, write, and erase operations.
///
/// # Type Parameters
///
/// * `S`: A type that implements the `Syscalls` trait, representing the system calls interface.
/// * `C`: A type that implements the `Config` trait, representing the configuration interface.
impl<S:Syscalls, C:Config> AsyncSpiFlash<S, C> {
    /// Creates a new instance of `AsyncSpiFlash`.
    ///
    /// # Arguments
    ///
    /// * `driver_num` - The driver number associated with the SPI flash.
    ///
    /// # Returns
    ///
    /// A new instance of `AsyncSpiFlash`.
    pub fn new(driver_num: u32) -> Self {};

    /// Checks if the SPI flash exists.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the SPI flash exists.
    /// * `Err(ErrorCode)` if there is an error.
    pub fn exists() -> Result<(), ErrorCode> {};

    /// Reads an arbitrary number of bytes from the flash memory.
    ///
    /// This method reads `len` bytes from the flash memory starting at the specified `address`
    /// and stores them in the provided `buf`.
    ///
    /// # Arguments
    ///
    /// * `address` - The starting address to read from.
    /// * `len` - The number of bytes to read.
    /// * `buf` - The buffer to store the read bytes.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the read operation is successful.
    /// * `Err(ErrorCode)` if there is an error.
    pub async fn read(&self, address: usize, len: usize, buf: &mut [u8]) -> Result<(), ErrorCode> {};

    /// Writes an arbitrary number of bytes to the flash memory.
    ///
    /// This method writes the bytes from the provided `buf` to the flash memory starting at the
    /// specified `address`.
    ///
    /// # Arguments
    ///
    /// * `address` - The starting address to write to.
    /// * `buf` - The buffer containing the bytes to write.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the write operation is successful.
    /// * `Err(ErrorCode)` if there is an error.
    pub async fn write(&self, address: usize, buf: &[u8]) -> Result<(), ErrorCode> {};

    /// Erases an arbitrary number of bytes from the flash memory.
    ///
    /// This method erases `len` bytes from the flash memory starting at the specified `address`.
    ///
    /// # Arguments
    ///
    /// * `address` - The starting address to erase from.
    /// * `len` - The number of bytes to erase.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the erase operation is successful.
    /// * `Err(ErrorCode)` if there is an error.
    pub async fn erase(&self, address: usize, len: usize) -> Result<(), ErrorCode> {};
}
```

### Flash partition capsule

```Rust
/// A structure representing a partition of a flash memory.
///
/// This structure allows for operations on a specific partition of the flash memory,
/// defined by a start address and a size.
///
/// # Type Parameters
/// - `'a`: The lifetime of the flash memory and client references.
/// - `F`: The type of the flash memory, which must implement the `Flash` trait.
///
/// # Fields
/// - `flash_user`: A reference to the `FlashUser` that provides access to the flash memory.
/// - `start_address`: The starting address of the flash partition.
/// - `size`: The size of the flash partition.
/// - `client`: An optional reference to a client that implements the `FlashPartitionClient` trait.
pub struct FlashPartition<'a, F: Flash + 'a> {
    flash_user: &'a FlashUser<'a, F>,
    start_address: usize,
    size: usize,
    client: OptionalCell<&'a dyn FlashPartitionClient>,
}

/// A partition of a flash memory device.
///
/// This struct represents a partition of a flash memory device, allowing
/// operations such as reading, writing, and erasing within the partition.
///
/// # Type Parameters
///
/// - `F`: A type that implements the `Flash` trait.
///
/// # Lifetimes
///
/// - `'a`: The lifetime of the flash memory device and its user.
impl<'a, F: Flash + 'a> FlashPartition<'a, F> {
    /// Creates a new `FlashPartition`.
    ///
    /// # Arguments
    ///
    /// - `flash_user`: A reference to the `FlashUser` that owns the flash memory device.
    /// - `start_address`: The starting address of the partition within the flash memory device.
    /// - `size`: The size of the partition in bytes.
    ///
    /// # Returns
    ///
    /// A new `FlashPartition` instance.
    pub fn new(
        flash_user: &'a FlashUser<'a, F>,
        start_address: usize,
        size: usize,
    ) -> FlashPartition<'a, F> {}

    /// Sets the client for the flash partition.
    ///
    /// # Arguments
    ///
    /// - `client`: A reference to an object that implements the `FlashPartitionClient` trait.
    pub fn set_client(&self, client: &'a dyn FlashPartitionClient) {}

    /// Reads data from the flash partition.
    ///
    /// # Arguments
    ///
    /// - `buffer`: A mutable reference to a buffer where the read data will be stored.
    /// - `offset`: The offset within the partition from which to start reading.
    /// - `length`: The number of bytes to read.
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or an error code.
    pub fn read(
        &self,
        buffer: &'static mut [u8],
        offset: usize,
        length: usize,
    ) -> Result<(), ErrorCode> {}

    /// Writes data to the flash partition.
    ///
    /// # Arguments
    ///
    /// - `buffer`: A mutable reference to a buffer containing the data to be written.
    /// - `offset`: The offset within the partition at which to start writing.
    /// - `length`: The number of bytes to write.
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or an error code.
    pub fn write(
        &self,
        buffer: &'static mut [u8],
        offset: usize,
        length: usize,
    ) -> Result<(), ErrorCode> {}

    /// Erases data from the flash partition.
    ///
    /// # Arguments
    ///
    /// - `offset`: The offset within the partition at which to start erasing.
    /// - `length`: The number of bytes to erase.
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or an error code.
    pub fn erase(&self, offset: usize, length: usize) -> Result<(), ErrorCode> {}
}

/// Implementation of the `SyscallDriver` trait for the `FlashPartition` struct.
/// This implementation provides support for reading, writing, and erasing flash memory,
/// as well as allowing read/write and read-only buffers, and subscribing to callbacks.
impl<'a, F: Flash + 'a> SyscallDriver for FlashPartition<'a, F> {
    ///
    /// Handles commands from userspace.
    ///
    /// # Arguments
    ///
    /// * `command_number` - The command number to execute.
    /// * `arg1` - The first argument for the command.
    /// * `arg2` - The second argument for the command.
    /// * `process_id` - The ID of the process making the command.
    ///
    /// # Returns
    ///
    /// A `CommandReturn` indicating the result of the command.
    ///
    /// Commands:
    /// - `0`: Success (no operation).
    /// - `1`: Read operation. Reads `arg2` bytes from offset `arg1`.
    /// - `2`: Write operation. Writes `arg2` bytes to offset `arg1`.
    /// - `3`: Erase operation. Erases `arg2` bytes from offset `arg1`.
    /// - Any other command: Not supported.
    fn command(
        &self,
        command_number: usize,
        arg1: usize,
        arg2: usize,
        process_id: ProcessId,
    ) -> CommandReturn {};

    ///
    /// Allows a process to provide a read/write buffer.
    ///
    /// # Arguments
    ///
    /// * `process_id` - The ID of the process providing the buffer.
    /// * `readwrite_number` - The identifier for the buffer.
    /// * `buffer` - The buffer to be used for read/write operations.
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or failure.
    ///
    /// Buffers:
    /// - `0`: Write buffer.
    /// - Any other buffer: Not supported.
    fn allow_readwrite(
        &self,
        process_id: ProcessId,
        readwrite_number: usize,
        buffer: Option<WriteableProcessBuffer>,
    ) -> Result<(), ErrorCode>;

    ///
    /// Allows a process to provide a read-only buffer.
    ///
    /// # Arguments
    ///
    /// * `process_id` - The ID of the process providing the buffer.
    /// * `readonly_number` - The identifier for the buffer.
    /// * `buffer` - The buffer to be used for read-only operations.
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or failure.
    ///
    /// Buffers:
    /// - `0`: Read buffer.
    /// - Any other buffer: Not supported.
    fn allow_readonly(
        &self,
        process_id: ProcessId,
        readonly_number: usize,
        buffer: Option<ReadableProcessBuffer>,
    ) -> Result<(), ErrorCode>{}

    ///
    /// Subscribes a process to a callback.
    ///
    /// # Arguments
    ///
    /// * `subscribe_number` - The identifier for the callback.
    /// * `callback` - The callback to be subscribed.
    /// * `process_id` - The ID of the process subscribing to the callback.
    ///
    /// # Returns
    ///
    /// A `Result` containing the previous callback if successful, or an error code if not.
    ///
    /// Callbacks:
    /// - `0`: General callback.
    /// - Any other callback: Not supported.
    fn subscribe(
        &self,
        subscribe_number: usize,
        callback: Option<Callback>,
        process_id: ProcessId,
    ) -> Result<Callback, (Option<Callback>, ErrorCode)>;
}
```

### SPI Flash Device Driver Capsule

Below is a sample interface for the SPI flash device driver under the reference architecture, where flash devices connect to the OpenTitan SPI host controller. This layer can be customized to support vendor-specific flash controller drivers.

```Rust
/// Represents a SPI flash device.
///
/// # Type Parameters
/// - `'a`: Lifetime of the SPI flash device.
/// - `S`: A type that implements the `VirtualSpiMasterDevice` trait.
///
/// # Sample Methods
/// - `new(spi: &'a S) -> Self`: Creates a new instance of `SpiFlashDevice`.
///
/// - `initialize_device(&self, config: DeviceConfig) -> Result<(), FlashError>`:
///   Initializes the SPI flash device with the given configuration.
///
/// - `device_properties_discovery(&self) -> Result<(), FlashError>`:
///   Discovers the properties of the SPI flash device from the Serial Flash Discoverable Parameters (SFDP).
///
/// - `get_device_id(&self) -> Result<[u8; 3], FlashError>`:
///   Retrieves the device ID of the SPI flash device.
///
/// - `get_device_size(&self) -> Result<u32, FlashError>`:
///   Retrieves the size of the SPI flash device.
///
/// - `process_cmds(&self, cmd: &[u8], response: &mut [u8]) -> Result<(), FlashError>`:
///   Processes the given command and writes the response to the provided buffer.
///
impl<'a, S: VirtualSpiMasterDevice + 'a> SpiFlashDevice<'a, S> {
    pub fn new(spi: &'a S) -> Self {}
    pub fn initialize_device(&self, config: DeviceConfig) -> Result<(), FlashError> {}
    fn device_properties_discovery(&self) -> Result<(), FlashError> {}
    pub fn get_device_id(&self) -> Result<[u8; 3], FlashError> {}
    pub fn get_device_size(&self) -> Result<u32, FlashError> {}
    pub fn process_cmds(&self, cmd: &[u8], response: &mut [u8]) -> Result<(), FlashError> {};
    ....
}
```

## Flash-based KV store

TBD

## Flash-based logging

TBD
