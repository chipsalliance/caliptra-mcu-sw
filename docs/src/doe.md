# DOE Stack
The Caliptra subsystem supports SPDM, Secure-SPDM over PCI Data Object Exchange (DOE) mailbox protocol. The following diagram gives the over view of the DOE send and receive stack.

DOE Receive stack:

![The DOE Tock receive stack](images/doe_tock_receive.svg)


DOE Send stack:

![The DOE Tock send stack](images/doe_tock_send.svg)

```mermaid
sequenceDiagram
    participant Host as "Host(TSM)"
    participant SoC_PCI_DOE_FSM as "SoC PCI DOE Listener"
    participant MCU_DOE_TRANSPORT_DRIVER as "MCU DOE Transport Driver"
    participant DOE_CAPSULE as "DOE Capsule"
    participant SPDM_APP as "SPDM App"
    SPDM_APP -->> DOE_CAPSULE: App invokes receive_message<br> for SPDM or Secure-SPDM Data Object type 
    Host ->> Host: Host waits until<br> the `DOE Busy` bit is cleared in <br>DOE Status Register
    loop While there is remaining DOE object to send
        Host ->> SoC_PCI_DOE_FSM  : Host starts sending DOE data object
        SoC_PCI_DOE_FSM ->> SoC_PCI_DOE_FSM: Prepare the message in staging area <br> (eg: Mailbox or shared memory)
        Note right of Host: Repeat until Host sets DOE Go bit
        Host ->> SoC_PCI_DOE_FSM: Host writes `DOE Go` bit <br>in DOE Control Register<br> to indicate message ready
    end
    SoC_PCI_DOE_FSM ->> MCU_DOE_TRANSPORT_DRIVER: Notify that a new DOE object<br> is available to consume
    MCU_DOE_TRANSPORT_DRIVER ->> DOE_CAPSULE: receive() callback

    alt if DOE object is `Data Object 0`
        DOE_CAPSULE ->> DOE_CAPSULE: Copy DOE object payload <br>into local buffer
        DOE_CAPSULE ->> DOE_CAPSULE: Handle DOE Discovery
        DOE_CAPSULE ->> DOE_CAPSULE: Prepare DOE Discovery response object
    else if DOE object is `Data Object 1 or 2`
        DOE_CAPSULE ->> DOE_CAPSULE: Copy DOE object payload <br>into app buffer
        DOE_CAPSULE -->> SPDM_APP: Invoke upcall to userspace<br> to receive() message
    end
    DOE_CAPSULE ->> MCU_DOE_TRANSPORT_DRIVER: set_rx_buffer()<br> to set the receive buffer for the next DOE object
    SPDM_APP ->> SPDM_APP: App processes message <br>and prepares DOE response
    SPDM_APP -->> DOE_CAPSULE: App invokes send_message <br>to send DOE response
    DOE_CAPSULE ->> MCU_DOE_TRANSPORT_DRIVER: invoke transmit()<br> to send the DOE response
    MCU_DOE_TRANSPORT_DRIVER ->> SoC_PCI_DOE_FSM: Notify that DOE response is ready to send
    SoC_PCI_DOE_FSM ->> Host: Set `Data Object Ready` bit in<br> DOE Status Register
```
## DOE Capsule
The DOE capsule implements the system calls for the user space applications to send and receive the DOE data objects.

During board initialization, a `DoeDriver` instance is created and registered with a unique driver number. This instance manages the handling of DOE Discovery (Data Object Type 0), SPDM (Data Object Type 1), and Secure-SPDM (Data Object Type 2) data objects.


```Rust

/// PCI-SIG Vendor ID that defined the data object type
const PCI_SIG_VENDOR_ID: u16 = 0x0001;
/// Data Object Protocol
const DATA_OBJECT_PROTOCOL_DOE_DISCOVERY: u8 = 0x00;
const DATA_OBJECT_PROTOCOL_CMA_SPDM: u8 = 0x01;
const DATA_OBJECT_PROTOCOL_SECURE_CMA_SPDM: u8 = 0x02;

pub const DOE_SPDM_DRIVER_NUM: usize = 0xA000_0010;

/// IDs for subscribe calls
mod upcall {
    /// Callback for when the message is received
    pub const RECEIVED_MESSAGE: usize = 0;

    /// Callback for when the message is transmitted.
    pub const MESSAGE_TRANSMITTED: usize = 1;

    /// Number of upcalls
    pub const COUNT: u8 = 2;
}

/// IDs for read-only allow buffers
mod ro_allow {
    /// Buffer for the message to be transmitted
    pub const MESSAGE_WRITE: usize = 0;

    /// Number of read-only allow buffers
    pub const COUNT: u8 = 1;
}

/// IDs for read-write allow buffers
mod rw_allow {
    /// Buffer for the message to be received
    pub const MESSAGE_READ: usize = 0;

    /// Number of read-write allow buffers
    pub const COUNT: u8 = 1;
}

#[derive(Default)]
pub struct App {
    waiting_rx: Cell<bool>, // Indicates if a message is waiting to be received
    pending_tx: Cell<bool>, // Indicates if a message is in progress
}


pub struct DoeDriver {
    doe_transport: & dyn DoeTransport,
    apps: Grant<
        App,
        UpcallCount<{ upcall::COUNT }>,
        AllowRoCount<{ ro_allow::COUNT }>,
        AllowRwCount<{ rw_allow::COUNT }>,
    >,
    current_app: Cell<Option<ProcessId>>,
}

```

## DOE Transport Trait
The DOE Transport trait defines a platform-agnostic interface for sending and receiving DOE data objects. Integrators must provide a SoC-specific implementation of this trait to enable PCI-DOE communication with the host.

```Rust

pub trait DoeTransportTxClient<'a> {
    /// Called by driver to notify that the DOE data object transmission is done.
    ///
    /// # Arguments
    /// * `result` - Result indicating success or failure of the transmission
    fn send_done(&self, result: Result<(), ErrorCode>);
}

pub trait DoeTransportRxClient {
    /// Called to receive a DOE data object.
    ///
    /// # Arguments
    /// * `rx_buf` - buffer containing the received DOE data object
    /// * `len_dw` - The length of the data received in dwords
    fn receive(&self, rx_buf: &'static mut [u32], len_dw: usize);
}

pub trait DoeTransport<'a> {
    /// Sets the transmit and receive clients for the DOE transport instance
    fn set_tx_client(&self, client: &'a dyn DoeTransportTxClient<'a>);
    fn set_rx_client(&self, client: &'a dyn DoeTransportRxClient);

    /// Sets the buffer used for receiving incoming DOE Objects.
    /// This should be called in receive()
    fn set_rx_buffer(&self, rx_buf: &'static mut [u32]);

    /// Gets the maximum size of the data object that can be sent or received over DOE Transport.
    fn max_data_object_size(&self) -> usize;

    /// Enable the DOE transport driver instance.
    fn enable(&self);

    /// Disable the DOE transport driver instance.
    fn disable(&self);

    /// Send DOE Object to be transmitted over SoC specific DOE transport.
    ///
    /// # Arguments
    /// * `tx_buf` - Iterator that yields u32 values from data object to be transmitted.
    /// * `len` - The length of the message in dwords (4-byte words).
    fn transmit(&self, tx_buf: impl Iterator<Item = u32>, len_dw: usize) -> Result<(), ErrorCode>;
}

```
