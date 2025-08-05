# IDE_KM - Integrity and Data Encryption Key Management Protocol Support

The Caliptra subsystem enables IDE_KM protocol support over SPDM secure sessions by transmitting IDE_KM messages as application data. The IDE_KM protocol manages the provisioning of encryption keys for IDE streams, providing confidentiality, integrity, and replay protection for Translation Layer Packets (TLPs).

To implement IDE_KM, devices must provide the `IdeDriver` trait implementation. This trait defines the interfaces and configuration necessary for secure IDE key management. This documentation describes how to integrate IDE_KM with the Caliptra subsystem, outlines implementation requirements, and offers guidance for usage.


```rust

pub const IDE_STREAM_KEY_SIZE_DW: usize = 4;
pub const IDE_STREAM_IV_SIZE_DW: usize = 2;

/// Port Configuration structure contains the configuration and capabilities for a specific IDE port.
pub struct PortConfig<
    const LINK_IDE_REG_BLOCK_COUNT: usize,
    const SELECTIVE_IDE_REG_BLOCK_COUNT: usize,
> {
    port_index: u8,
    function_num: u8,
    bus_num: u8,
    segment: u8,
    max_port_index: u8,
    ide_cap_reg: u32,
    ide_ctrl_reg: u32,
    link_ide_stream_reg_block: [LinkIdeStreamRegBlock; LINK_IDE_REG_BLOCK_COUNT],
    selective_ide_stream_reg_block: [SelectiveIdeStreamRegBlock<1>; SELECTIVE_IDE_REG_BLOCK_COUNT],
}

/// Link IDE Register Block
pub struct LinkIdeStreamRegBlock {
    ctrl_reg: u32,
    status_reg: u32,
}

/// Selective IDE Stream Register Block
pub struct SelectiveIdeStreamRegBlock<const ADDR_ASSOC_COUNT: usize> {
    capability_reg: u32,
    ctrl_reg: u32,
    status_reg: u32,
    rid_association_reg_1: u32,
    rid_association_reg_2: u32,
    addr_assoc_reg_blk: [AddrAssociationRegBlock; ADDR_ASSOC_COUNT],
}

/// IDE Address Association Register Block
pub struct AddrAssociationRegBlock {
    reg1: u32,
    reg2: u32,
    reg3: u32,
}

/// IDE Driver Error Types
pub enum IdeDriverError {
    InvalidPortIndex,
    UnsupportedPortIndex,
    InvalidStreamId,
    InvalidArgument,
    GetPortConfigFail,
    KeyProgFail,
    KeySetGoFail,
    KeySetStopFail,
    NoMemory,
}

pub type IdeDriverResult<T> = Result<T, IdeDriverError>;


/// KeyInfo structure contains information about the key set, direction, and sub-stream.
bitfield! {
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub struct KeyInfo(u8);
    impl Debug;
    pub key_set_bit, set_key_set_bit: 0;
    pub key_direction, set_key_direction: 1;
    reserved, _: 3, 2;
    pub key_sub_stream, set_key_sub_stream: 7, 4;
}

/// IDE Driver Trait
///
/// Provides an interface for Integrity and Data Encryption (IDE) key management operations.
/// This trait abstracts hardware-specific implementations for different platforms.
///
/// # Implementation Notes
///
/// When implementing this trait, you should define your `PortConfig` associated type
/// using the generic `PortConfig` struct with your implementation's constants:
///
/// ```ignore
/// type PortConfig = PortConfig<
///     { Self::LINK_IDE_REG_BLOCK_COUNT },
///     { Self::SELECTIVE_IDE_REG_BLOCK_COUNT }
/// >;
/// ```
pub trait IdeDriver {
    /// Number of Link IDE register blocks supported by this implementation
    const LINK_IDE_REG_BLOCK_COUNT: usize;

    /// Number of Selective IDE register blocks supported by this implementation  
    const SELECTIVE_IDE_REG_BLOCK_COUNT: usize;

    /// Number of Address Association register blocks per Selective IDE block
    const SELECTIVE_ADDR_ASSOCIATION_REG_BLOCK_COUNT: usize;

    /// Associated type for PortConfig with implementation-specific array sizes.
    ///
    /// This should typically be defined as:
    /// ```ignore
    /// type PortConfig = PortConfig<
    ///     { Self::LINK_IDE_REG_BLOCK_COUNT },
    ///     { Self::SELECTIVE_IDE_REG_BLOCK_COUNT }
    /// >;
    /// ```
    type PortConfig;

    /// Get the port configuration for a given port index.
    ///
    /// # Arguments
    /// * `port_index` - The index of the port to retrieve the configuration for.
    ///
    /// # Returns
    /// A result containing the `PortConfig` for the specified port index, or an error
    /// if the port index is invalid or unsupported.
    async fn port_config(&self, port_index: u8) -> IdeDriverResult<Self::PortConfig>;

    /// Key programming for a specific port and stream.
    ///
    /// # Arguments
    /// * `stream_id` - Stream ID
    /// * `key_info` - Key information containing key set bit, direction, and sub-stream.
    /// * `port_index` - Port to which the key is to be programmed.
    /// * `key` - The key data to be programmed (4 DWORDs).
    /// * `iv` - The initialization vector (2 DWORDs).
    ///
    /// # Returns
    /// A result containing the status of the key programming operation:
    /// - `00h`: Successful
    /// - `01h`: Incorrect Length
    /// - `02h`: Unsupported Port Index value
    /// - `03h`: Unsupported value in other fields
    /// - `04h`: Unspecified Failure
    async fn key_prog(
        &self,
        stream_id: u8,
        key_info: KeyInfo,
        port_index: u8,
        key: &[u32; IDE_STREAM_KEY_SIZE_DW],
        iv: &[u32; IDE_STREAM_IV_SIZE_DW],
    ) -> IdeDriverResult<u8>;

    /// Start using the key set for a specific port and stream.
    ///
    /// # Arguments
    /// * `stream_id` - Stream ID
    /// * `key_info` - Key information containing key set bit, direction, and sub-stream.
    /// * `port_index` - Port to which the key set is to be started.
    ///
    /// # Returns
    /// A result containing the updated `KeyInfo` after starting the key set, or an
    /// error if the operation fails.
    async fn key_set_go(
        &self,
        stream_id: u8,
        key_info: KeyInfo,
        port_index: u8,
    ) -> IdeDriverResult<KeyInfo>;

    /// Stop the key set for a specific port and stream.
    ///
    /// # Arguments
    /// * `stream_id` - Stream ID
    /// * `key_info` - Key information containing key set bit, direction, and sub-stream.
    /// * `port_index` - Port to which the key set is to be stopped
    ///
    /// # Returns
    /// A result containing the updated `KeyInfo` after stopping the key set, or an error
    /// if the operation fails.
    async fn key_set_stop(
        &self,
        stream_id: u8,
        key_info: KeyInfo,
        port_index: u8,
    ) -> IdeDriverResult<KeyInfo>;
}
```