# IDE_KM - Integrity and Data Encryption Key Management Protocol Support

The Caliptra subsystem enables IDE_KM protocol support over SPDM secure sessions by transmitting IDE_KM messages as application data. The IDE_KM protocol manages the provisioning of encryption keys for IDE streams, providing confidentiality, integrity, and replay protection for Translation Layer Packets (TLPs).

To implement IDE_KM, devices must provide the `IdeDriver` trait implementation. This trait defines the interfaces and configuration necessary for secure IDE key management. This documentation describes how to integrate IDE_KM with the Caliptra subsystem, outlines implementation requirements, and offers guidance for usage.


```rust

pub const IDE_STREAM_KEY_SIZE_DW: usize = 8;
pub const IDE_STREAM_IV_SIZE_DW: usize = 2;
pub const MAX_SELECTIVE_IDE_ADDR_ASSOC_BLOCK_COUNT: usize = 15;

/// Port Configuration structure contains the configuration and capabilities for a specific IDE port.
pub struct PortConfig {
    port_index: u8,
    function_num: u8,
    bus_num: u8,
    segment: u8,
    max_port_index: u8,
}

/// IDE Capability and Control Register Block
pub struct IdeRegBlock {
    ide_cap_reg: IdeCapabilityReg,
    ide_ctrl_reg: IdeControlReg,
}

/// Link IDE Register Block
pub struct LinkIdeStreamRegBlock {
    ctrl_reg: LinkIdeStreamControlReg,
    status_reg: LinkIdeStreamStatusReg,
}

/// Selective IDE Stream Register Block
pub struct SelectiveIdeStreamRegBlock {
    capability_reg: SelectiveIdeStreamCapabilityReg,
    ctrl_reg: SelectiveIdeStreamControlReg,
    status_reg: SelectiveIdeStreamStatusReg,
    rid_association_reg_1: SelectiveIdeRidAssociationReg1,
    rid_association_reg_2: SelectiveIdeRidAssociationReg2,
    addr_association_reg_block: [AddrAssociationRegBlock; MAX_SELECTIVE_IDE_ADDR_ASSOC_BLOCK_COUNT],
}

/// IDE Address Association Register Block
pub struct AddrAssociationRegBlock {
    reg1: IdeAddrAssociationReg1,
    reg2: IdeAddrAssociationReg2,
    reg3: IdeAddrAssociationReg3,
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
#[async_trait]
pub trait IdeDriver {
    /// Get the port configuration for a given port index.
    ///
    /// # Arguments
    /// * `port_index` - The index of the port to retrieve the configuration for.
    ///
    /// # Returns
    /// A result containing the `PortConfig` for the specified port index, or an error
    /// if the port index is invalid or unsupported.
    fn port_config(&self, port_index: u8) -> IdeDriverResult<PortConfig>;

    /// Get the IDE register block.
    ///
    /// # Arguments
    /// * `port_index` - The index of the port.
    ///
    /// # Returns
    /// A result containing the `IdeRegBlock` for the specified port, or an error
    fn ide_register_block(&self, port_index: u8) -> IdeDriverResult<IdeRegBlock>;

    /// Get the link IDE register block for a specific port and block index.
    ///
    /// # Arguments
    /// * `port_index` - The index of the port.
    /// * `block_index` - The index of the register block.
    ///
    /// # Returns
    /// A result containing the `LinkIdeStreamRegBlock` for the specified port and block
    fn link_ide_reg_block(
        &self,
        port_index: u8,
        block_index: u8,
    ) -> IdeDriverResult<LinkIdeStreamRegBlock>;

    /// Get the selective IDE register block for a specific port and block index.
    ///
    /// # Arguments
    /// * `port_index` - The index of the port.
    /// * `block_index` - The index of the register block.
    ///
    /// # Returns
    /// A result containing the `SelectiveIdeStreamRegBlock` for the specified port and block
    fn selective_ide_reg_block(
        &self,
        port_index: u8,
        block_index: u8,
    ) -> IdeDriverResult<SelectiveIdeStreamRegBlock>;

    /// Key programming for a specific port and stream.
    ///
    /// # Arguments
    /// * `stream_id` - Stream ID
    /// * `key_info` - Key information containing key set bit, direction, and sub-stream.
    /// * `port_index` - Port to which the key is to be programmed.
    /// * `key` - The key data to be programmed (8 DWORDs).
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