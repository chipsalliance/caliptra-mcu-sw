// Licensed under the Apache-2.0 license

use caliptra_mcu_network_hil::ethernet::Ethernet;
use caliptra_mcu_network_hil::timers::Timers;
use core::cell::{Cell, RefCell, UnsafeCell};
use lwip_rs::ip::Ipv4Addr;
use lwip_rs::ip::Ipv6Addr;
use lwip_rs::netif_baremetal::{BaremetalCallbacks, BaremetalNetIf};
use lwip_rs::tftp_baremetal::{BaremetalTftpClient, BaremetalTftpOps};
use lwip_rs::BaremetalSysCallbacks;

/// Maximum chunk size for TFTP data buffering.
/// Data received from TFTP callbacks is stored here until the MCU
/// pulls it via ChunkAck.
pub const TFTP_CHUNK_BUF_SIZE: usize = 8192;

/// Errors from network operations.
#[derive(Debug)]
pub enum NetworkError {
    InitFailed,
    DhcpTimeout,
    DhcpFailed,
    Dhcpv6Timeout,
    Dhcpv6Failed,
    TftpInitFailed,
    TftpGetFailed,
    TftpTimeout,
    TftpError,
    NoBootFile,
}

/// IP-version-agnostic server address.
#[derive(Clone)]
pub enum ServerAddr {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

// ---------------------------------------------------------------------------
// Module-level statics (single-threaded bare-metal)
// ---------------------------------------------------------------------------

struct LwipState {
    netif: RefCell<BaremetalNetIf>,
    tftp: RefCell<BaremetalTftpClient>,
    initialized: Cell<bool>,
    chunk_buf: RefCell<[u8; TFTP_CHUNK_BUF_SIZE]>,
    chunk_buf_len: Cell<usize>,
    tftp_complete: Cell<bool>,
    tftp_has_error: Cell<bool>,
    tftp_write_count: Cell<u32>,
    tftp_close_count: Cell<u32>,
    tftp_total_bytes: Cell<usize>,
}

impl LwipState {
    const fn new() -> Self {
        Self {
            netif: RefCell::new(BaremetalNetIf::new()),
            tftp: RefCell::new(BaremetalTftpClient::new()),
            initialized: Cell::new(false),
            chunk_buf: RefCell::new([0u8; TFTP_CHUNK_BUF_SIZE]),
            chunk_buf_len: Cell::new(0),
            tftp_complete: Cell::new(false),
            tftp_has_error: Cell::new(false),
            tftp_write_count: Cell::new(0),
            tftp_close_count: Cell::new(0),
            tftp_total_bytes: Cell::new(0),
        }
    }
}

unsafe impl Send for LwipState {}

/// Thin wrapper to satisfy `Sync` for statics containing `RefCell`/`Cell`.
///
/// # Safety
/// Must only be used in a single-threaded context.
struct SyncCell(UnsafeCell<LwipState>);
unsafe impl Sync for SyncCell {}

impl SyncCell {
    const fn new(val: LwipState) -> Self {
        Self(UnsafeCell::new(val))
    }

    /// Access the inner state.
    ///
    /// # Safety
    /// Caller must ensure no re-entrant or concurrent access.
    fn lock<R>(&self, f: impl FnOnce(&LwipState) -> R) -> R {
        unsafe { f(&*self.0.get()) }
    }
}

static LWIP: SyncCell = SyncCell::new(LwipState::new());
static mut ETH: Option<*mut dyn Ethernet> = None;
static mut TIMER: Option<*const dyn Timers> = None;

// ---------------------------------------------------------------------------
// lwIP callbacks
// ---------------------------------------------------------------------------

fn eth_transmit(frame: &[u8]) -> bool {
    unsafe {
        match *core::ptr::addr_of!(ETH) {
            Some(ptr) => (*ptr).transmit(frame).is_ok(),
            None => false,
        }
    }
}

fn eth_receive(buffer: &mut [u8]) -> usize {
    unsafe {
        match *core::ptr::addr_of!(ETH) {
            Some(ptr) => {
                let e = &mut *ptr;
                if !e.rx_available() {
                    return 0;
                }
                e.receive(buffer).unwrap_or(0)
            }
            None => 0,
        }
    }
}

fn eth_mac_addr() -> [u8; 6] {
    unsafe {
        match *core::ptr::addr_of!(ETH) {
            Some(ptr) => (*ptr).mac_address(),
            None => [0; 6],
        }
    }
}

fn eth_rx_available() -> bool {
    unsafe {
        match *core::ptr::addr_of!(ETH) {
            Some(ptr) => (*ptr).rx_available(),
            None => false,
        }
    }
}

fn sys_now_ms() -> u32 {
    now_ms() as u32
}

/// Return the current elapsed time in milliseconds from the timer.
///
/// Returns 0 if the timer has not been initialized.
pub fn now_ms() -> u64 {
    unsafe {
        match *core::ptr::addr_of!(TIMER) {
            Some(ptr) => {
                let t = &*ptr;
                t.elapsed_ms(0, t.ticks())
            }
            None => 0,
        }
    }
}

fn sys_init() {}

fn sys_arch_protect() -> u32 {
    0
}

fn sys_arch_unprotect(_val: u32) {}

fn simple_rand() -> u32 {
    static mut STATE: u32 = 0x12345678;
    unsafe {
        let s = core::ptr::addr_of_mut!(STATE);
        *s ^= *s << 13;
        *s ^= *s >> 17;
        *s ^= *s << 5;
        *s
    }
}

// ---------------------------------------------------------------------------
// lwIP lifecycle
// ---------------------------------------------------------------------------

/// Initialize the lwIP stack and network interface.
///
/// `eth` is the Ethernet implementation used for all network I/O.
/// `timer` is the timer implementation used for lwIP time tracking.
///
/// # Safety
/// The `eth` and `timer` references must remain valid for the lifetime
/// of the network stack (i.e. until [`shutdown`] is called).
///
/// Must be called exactly once before any other network operation.
pub fn init_lwip(
    eth: &'static mut dyn Ethernet,
    timer: &'static dyn Timers,
) -> Result<(), NetworkError> {
    LWIP.lock(|s| {
        if s.initialized.get() {
            return Ok(());
        }
        // SAFETY: ETH / TIMER are only written here before any callbacks
        // are registered, and read from single-threaded fn-pointer callbacks.
        unsafe {
            *core::ptr::addr_of_mut!(ETH) = Some(eth as *mut dyn Ethernet);
            *core::ptr::addr_of_mut!(TIMER) = Some(timer as *const dyn Timers);
        }
        lwip_rs::register_sys_callbacks(BaremetalSysCallbacks {
            sys_now: sys_now_ms,
            sys_init,
            sys_arch_protect,
            sys_arch_unprotect,
            rand: simple_rand,
        });
        lwip_rs::init();

        s.netif
            .borrow_mut()
            .init(BaremetalCallbacks {
                transmit: eth_transmit,
                receive: eth_receive,
                mac_addr: eth_mac_addr,
                rx_available: eth_rx_available,
            })
            .map_err(|_| NetworkError::InitFailed)?;
        s.initialized.set(true);
        Ok(())
    })
}

/// Poll the network interface (process received packets and lwIP timers).
///
/// Must be called frequently from the main loop.
pub fn poll() {
    LWIP.lock(|s| {
        if s.initialized.get() {
            s.netif.borrow_mut().poll();
        }
    });
}

/// Poll the network interface, processing at most `max_packets` received
/// frames. Useful during TFTP streaming to prevent buffer overflow.
pub fn poll_limited(max_packets: usize) {
    LWIP.lock(|s| {
        if s.initialized.get() {
            s.netif.borrow_mut().poll_limited(max_packets);
        }
    });
}

/// Shut down the network interface.
pub fn shutdown() {
    LWIP.lock(|s| {
        if s.initialized.get() {
            s.netif.borrow_mut().shutdown();
            s.initialized.set(false);
        }
    });
}

// ---------------------------------------------------------------------------
// DHCP (non-blocking / incremental)
// ---------------------------------------------------------------------------

/// Start DHCPv4 discovery. Call [`dhcp_has_address`] from the main loop
/// to check when an address has been obtained.
pub fn start_dhcp() -> Result<(), NetworkError> {
    LWIP.lock(|s| {
        s.netif
            .borrow_mut()
            .dhcp_start()
            .map_err(|_| NetworkError::DhcpFailed)
    })
}

/// Start stateful DHCPv6 discovery. Call [`dhcp6_has_address`] from the main loop
/// to check when a global IPv6 address has been obtained.
#[cfg(feature = "ipv6-boot")]
pub fn start_dhcp6() -> Result<(), NetworkError> {
    LWIP.lock(|s| {
        s.netif
            .borrow_mut()
            .dhcp6_enable_stateful()
            .map_err(|_| NetworkError::Dhcpv6Failed)
    })
}

/// Returns true when DHCPv4 has obtained an IP address.
pub fn dhcp_has_address() -> bool {
    LWIP.lock(|s| s.netif.borrow().dhcp_has_address())
}

/// Returns true when stateful DHCPv6 has obtained a global IPv6 address.
#[cfg(feature = "ipv6-boot")]
pub fn dhcp6_has_address() -> bool {
    LWIP.lock(|s| s.netif.borrow().has_global_ipv6_address())
}

/// Extract the DHCP result (server IP, boot file) after [`dhcp_has_address`]
/// returns true. Returns `None` if no boot file was provided.
pub fn take_dhcp_result() -> Option<DhcpResult> {
    LWIP.lock(|s| {
        let netif = s.netif.borrow();

        let server_ip = netif.dhcp_server_ip();
        let boot_file_slice = netif.dhcp_boot_file_name();

        if boot_file_slice.is_empty() {
            return None;
        }

        let mut boot_file = [0u8; 128];
        let len = boot_file_slice.len().min(127);
        boot_file[..len].copy_from_slice(&boot_file_slice[..len]);

        Some(DhcpResult {
            server_ip: ServerAddr::V4(server_ip),
            boot_file,
            boot_file_len: len,
        })
    })
}

/// Extract the DHCPv6 result (server IP from Option 59, boot file path) after
/// [`dhcp6_has_address`] returns true. The TFTP server address and boot file
/// path are parsed from the Boot File URL (DHCPv6 Option 59, RFC 5970).
///
/// Returns `None` if no Boot File URL was provided.
#[cfg(feature = "ipv6-boot")]
pub fn take_dhcp6_result() -> Option<DhcpResult> {
    LWIP.lock(|s| {
        let netif = s.netif.borrow();

        let (server_addr, path) = netif.dhcp6_parse_boot_file_url()?;

        let mut boot_file = [0u8; 128];
        let len = path.len().min(127);
        boot_file[..len].copy_from_slice(&path[..len]);
        // Ensure null-termination for TFTP filename.
        if len < 128 {
            boot_file[len] = 0;
        }

        Some(DhcpResult {
            server_ip: ServerAddr::V6(server_addr),
            boot_file,
            boot_file_len: len,
        })
    })
}

// ---------------------------------------------------------------------------
// DHCP (blocking — for non-emulated platforms)
// ---------------------------------------------------------------------------

/// DHCP results extracted after a successful handshake.
pub struct DhcpResult {
    pub server_ip: ServerAddr,
    pub boot_file: [u8; 128],
    pub boot_file_len: usize,
}

/// Run DHCPv4 and poll until an address is obtained or `timeout_ms` elapses.
fn run_dhcp_v4(timeout_ms: u64) -> Result<DhcpResult, NetworkError> {
    LWIP.lock(|s| {
        let mut netif = s.netif.borrow_mut();

        netif.dhcp_start().map_err(|_| NetworkError::DhcpFailed)?;

        let start = now_ms();
        loop {
            netif.poll();

            if netif.dhcp_has_address() {
                let server_ip = netif.dhcp_server_ip();
                let boot_file_slice = netif.dhcp_boot_file_name();

                if boot_file_slice.is_empty() {
                    return Err(NetworkError::NoBootFile);
                }

                let mut boot_file = [0u8; 128];
                let len = boot_file_slice.len().min(127);
                boot_file[..len].copy_from_slice(&boot_file_slice[..len]);

                return Ok(DhcpResult {
                    server_ip: ServerAddr::V4(server_ip),
                    boot_file,
                    boot_file_len: len,
                });
            }

            if now_ms().wrapping_sub(start) >= timeout_ms {
                break;
            }
        }

        Err(NetworkError::DhcpTimeout)
    })
}

/// Run stateless DHCPv6 (SLAAC for address, DHCPv6 for DNS) and poll until
/// a global IPv6 address is obtained or timeout.
///
/// Since DHCPv6 stateless does not provide a boot file name, the caller
/// must supply a `fallback_server` and `fallback_boot_file` to use.
fn run_dhcp_v6(
    timeout_ms: u64,
    fallback_server: Ipv6Addr,
    fallback_boot_file: &[u8],
) -> Result<DhcpResult, NetworkError> {
    LWIP.lock(|s| {
        let mut netif = s.netif.borrow_mut();

        netif
            .dhcp6_enable_stateless()
            .map_err(|_| NetworkError::Dhcpv6Failed)?;

        let start = now_ms();
        loop {
            netif.poll();

            if netif.has_global_ipv6_address() {
                let mut boot_file = [0u8; 128];
                let len = fallback_boot_file.len().min(127);
                boot_file[..len].copy_from_slice(&fallback_boot_file[..len]);

                return Ok(DhcpResult {
                    server_ip: ServerAddr::V6(fallback_server),
                    boot_file,
                    boot_file_len: len,
                });
            }

            if now_ms().wrapping_sub(start) >= timeout_ms {
                break;
            }
        }

        Err(NetworkError::Dhcpv6Timeout)
    })
}

/// Attempt DHCPv4 first; if it times out, fall back to DHCPv6/SLAAC.
///
/// `timeout_ms` is the maximum wall-clock time (in milliseconds) to wait
/// for each protocol before giving up.
/// `v6_fallback_server` and `v6_fallback_boot_file` are used when
/// DHCPv4 is unavailable (stateless DHCPv6 does not carry boot file info).
pub fn run_dhcp(
    timeout_ms: u64,
    v6_fallback_server: Ipv6Addr,
    v6_fallback_boot_file: &[u8],
) -> Result<DhcpResult, NetworkError> {
    match run_dhcp_v4(timeout_ms) {
        Ok(result) => Ok(result),
        Err(_) => run_dhcp_v6(timeout_ms, v6_fallback_server, v6_fallback_boot_file),
    }
}

// ---------------------------------------------------------------------------
// TFTP
// ---------------------------------------------------------------------------

/// Initialize the TFTP client. Must be called before `start_tftp_get`.
pub fn init_tftp() -> Result<(), NetworkError> {
    LWIP.lock(|s| {
        s.tftp
            .borrow_mut()
            .init(BaremetalTftpOps {
                write: tftp_write_cb,
                error: tftp_error_cb,
                close: Some(tftp_close_notify),
            })
            .map_err(|_| NetworkError::TftpInitFailed)
    })
}

/// Start a TFTP GET for the given file from the given server.
///
/// `filename` must be null-terminated.
pub fn start_tftp_get(server: &ServerAddr, filename: &[u8]) -> Result<(), NetworkError> {
    LWIP.lock(|s| {
        s.chunk_buf_len.set(0);
        s.tftp_complete.set(false);
        s.tftp_has_error.set(false);

        let mut tftp = s.tftp.borrow_mut();
        match server {
            ServerAddr::V4(addr) => tftp
                .get(*addr, filename)
                .map_err(|_| NetworkError::TftpGetFailed),
            ServerAddr::V6(addr) => tftp
                .get_v6(*addr, filename)
                .map_err(|_| NetworkError::TftpGetFailed),
        }
    })
}

/// Poll the TFTP client (call `poll()` for the netif, then check status).
///
/// Returns `true` when the TFTP transfer is complete (success or error).
/// Delegates to the `BaremetalTftpClient` which tracks the `close` callback
/// from lwIP (indicating the last TFTP data block was received).
pub fn tftp_is_complete() -> bool {
    LWIP.lock(|s| s.tftp.borrow().is_complete())
}

/// Returns `true` if the TFTP transfer ended with an error.
pub fn tftp_has_error() -> bool {
    LWIP.lock(|s| s.tftp.borrow().has_error())
}

/// Take buffered TFTP data, copying up to `out.len()` bytes.
///
/// Returns the number of bytes copied. The internal buffer is drained
/// by the amount consumed.
pub fn take_tftp_chunk(out: &mut [u8]) -> usize {
    LWIP.lock(|s| {
        let buf_len = s.chunk_buf_len.get();
        let avail = buf_len.min(out.len());
        let mut buf = s.chunk_buf.borrow_mut();
        out[..avail].copy_from_slice(&buf[..avail]);
        let remaining = buf_len - avail;
        if remaining > 0 {
            buf.copy_within(avail..buf_len, 0);
        }
        s.chunk_buf_len.set(remaining);
        avail
    })
}

/// Returns the number of bytes currently buffered from TFTP.
pub fn tftp_buffered_len() -> usize {
    LWIP.lock(|s| s.chunk_buf_len.get())
}

/// Reset TFTP buffer and counter state between image transfers,
/// without deinitializing the TFTP client (so it can be reused).
pub fn reset_tftp_state() {
    LWIP.lock(|s| {
        s.chunk_buf_len.set(0);
        s.tftp_complete.set(false);
        s.tftp_has_error.set(false);
        s.tftp_write_count.set(0);
        s.tftp_close_count.set(0);
        s.tftp_total_bytes.set(0);
    });
}

/// Clean up TFTP client state (full teardown, requires re-init before reuse).
pub fn cleanup_tftp() {
    LWIP.lock(|s| {
        s.tftp.borrow_mut().cleanup();
        s.chunk_buf_len.set(0);
        s.tftp_complete.set(false);
        s.tftp_has_error.set(false);
        s.tftp_write_count.set(0);
        s.tftp_close_count.set(0);
        s.tftp_total_bytes.set(0);
    });
}

// ---------------------------------------------------------------------------
// TFTP callbacks (called by lwIP)
// ---------------------------------------------------------------------------

fn tftp_write_cb(data: &[u8]) -> bool {
    LWIP.lock(|s| {
        s.tftp_write_count.set(s.tftp_write_count.get() + 1);
        s.tftp_total_bytes
            .set(s.tftp_total_bytes.get() + data.len());
        let buf_len = s.chunk_buf_len.get();
        let space = TFTP_CHUNK_BUF_SIZE - buf_len;
        if data.len() > space {
            s.tftp_has_error.set(true);
            return false;
        }
        let mut buf = s.chunk_buf.borrow_mut();
        buf[buf_len..buf_len + data.len()].copy_from_slice(data);
        s.chunk_buf_len.set(buf_len + data.len());
        true
    })
}

fn tftp_error_cb(_err: i32, _msg: &[u8]) {
    LWIP.lock(|s| {
        s.tftp_has_error.set(true);
        s.tftp_complete.set(true);
    });
}

fn tftp_close_notify() {
    LWIP.lock(|s| {
        s.tftp_close_count.set(s.tftp_close_count.get() + 1);
    });
}

/// Debug info about TFTP state.
pub fn tftp_debug_info() -> (u32, u32, usize) {
    LWIP.lock(|s| {
        (
            s.tftp_write_count.get(),
            s.tftp_close_count.get(),
            s.tftp_total_bytes.get(),
        )
    })
}
