/*++

Licensed under the Apache-2.0 license.

File Name:

    dhcp_test.rs

Abstract:

    Simple DHCP discovery application for the Network Coprocessor.

    This module implements a minimal DHCP DISCOVER sender that broadcasts
    a DHCP discovery packet and waits for a DHCP OFFER response.

--*/

use network_drivers::EthernetDriver;
use network_drivers::{exit_emulator, println, IpAddr, MacAddr};
use network_hil::ethernet::{Ethernet, MacAddress, BROADCAST_MAC, ETH_MAX_FRAME_SIZE};
use zerocopy::byteorder::big_endian::{U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Ref};

// Run the complete DHCP discovery test.
//
// This is the main entry point for the DHCP test application.
// It prints startup messages, runs DHCP discovery, prints results,
// and exits the emulator with an appropriate exit code.
//
// # Arguments
// * `eth` - The Ethernet driver to use for network communication
pub fn run(eth: EthernetDriver) {
    println!();
    println!("=====================================");
    println!("     DHCP discovery Test Started!    ");
    println!("=====================================");
    println!();

    println!("Ethernet driver initialized");

    let mac = eth.mac_address();
    println!("MAC address: {}", MacAddr(&mac));

    println!("Starting DHCP discovery...");
    let mut dhcp = DhcpDiscovery::new(eth);

    // Run DHCP discovery
    // max_attempts: 5, poll_cycles: 5_000_000 per attempt
    let result = dhcp.discover(5, 5_000_000);

    match result {
        DhcpResult::OfferReceived {
            offered_ip,
            server_ip,
        } => {
            println!();
            println!("DHCP OFFER received!");
            println!("  Offered IP: {}", IpAddr(&offered_ip));
            println!("  Server IP:  {}", IpAddr(&server_ip));
            println!();
            println!("DHCP discovery successful!");
            exit_emulator(0x00); // Success
        }
        DhcpResult::Timeout => {
            println!("DHCP discovery timed out");
            exit_emulator(0x02);
        }
        DhcpResult::Error => {
            println!("DHCP discovery error");
            exit_emulator(0x03);
        }
    }
}

// DHCP message opcodes
#[allow(dead_code)]
mod dhcp_op {
    pub const BOOTREQUEST: u8 = 1;
    pub const BOOTREPLY: u8 = 2;
}

// DHCP message types (option 53)
#[allow(dead_code)]
mod dhcp_type {
    pub const DISCOVER: u8 = 1;
    pub const OFFER: u8 = 2;
    pub const REQUEST: u8 = 3;
    pub const ACK: u8 = 5;
    pub const NAK: u8 = 6;
}

// Ethernet type for IPv4
const ETHERTYPE_IPV4: u16 = 0x0800;

// IP protocol number for UDP
const IP_PROTO_UDP: u8 = 17;

// DHCP ports
const DHCP_SERVER_PORT: u16 = 67;
const DHCP_CLIENT_PORT: u16 = 68;

// DHCP magic cookie
const DHCP_MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

// DHCP option codes
#[allow(dead_code)]
mod dhcp_option {
    pub const PAD: u8 = 0;
    pub const SUBNET_MASK: u8 = 1;
    pub const ROUTER: u8 = 3;
    pub const DNS: u8 = 6;
    pub const HOSTNAME: u8 = 12;
    pub const REQUESTED_IP: u8 = 50;
    pub const MESSAGE_TYPE: u8 = 53;
    pub const SERVER_ID: u8 = 54;
    pub const PARAMETER_LIST: u8 = 55;
    pub const END: u8 = 255;
}

// Minimum DHCP payload size (from DHCP start to end, before options padding)
const DHCP_MIN_PAYLOAD: usize = 300;

/// Ethernet frame header (14 bytes)
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Clone, Copy)]
struct EthHeader {
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    ether_type: U16,
}

/// IPv4 header (20 bytes, no options)
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Clone, Copy)]
struct Ipv4Header {
    version_ihl: u8,
    dscp_ecn: u8,
    total_length: U16,
    identification: U16,
    flags_fragment: U16,
    ttl: u8,
    protocol: u8,
    checksum: U16,
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
}

/// UDP header (8 bytes)
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Clone, Copy)]
struct UdpHeader {
    src_port: U16,
    dst_port: U16,
    length: U16,
    checksum: U16,
}

/// Fixed portion of a DHCP message (236 bytes, before magic cookie)
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Clone, Copy)]
struct DhcpFixedFields {
    op: u8,
    htype: u8,
    hlen: u8,
    hops: u8,
    xid: U32,
    secs: U16,
    flags: U16,
    ciaddr: [u8; 4],
    yiaddr: [u8; 4],
    siaddr: [u8; 4],
    giaddr: [u8; 4],
    chaddr: [u8; 16],
    sname: [u8; 64],
    file: [u8; 128],
}

/// Combined header for a DHCP-over-UDP-over-IPv4-over-Ethernet frame.
/// This covers everything up to (but not including) DHCP options.
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Clone, Copy)]
struct DhcpFrame {
    eth: EthHeader,
    ip: Ipv4Header,
    udp: UdpHeader,
    dhcp: DhcpFixedFields,
    magic_cookie: [u8; 4],
}

// Result of DHCP discovery
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpResult {
    // Successfully received DHCP OFFER
    OfferReceived {
        // Offered IP address
        offered_ip: [u8; 4],
        // Server IP address
        server_ip: [u8; 4],
    },
    // Timeout waiting for response
    Timeout,
    // Error occurred
    Error,
}

// DHCP Discovery application
pub struct DhcpDiscovery {
    eth: EthernetDriver,
    xid: u32,
}

impl DhcpDiscovery {
    // Create a new DHCP discovery application
    pub fn new(eth: EthernetDriver) -> Self {
        Self {
            eth,
            xid: 0x12345678, // Transaction ID
        }
    }

    // Run the DHCP discovery process
    //
    // Sends a DHCP DISCOVER and waits for a DHCP OFFER.
    // Returns the result of the discovery.
    pub fn discover(&mut self, max_attempts: u32, poll_cycles: u32) -> DhcpResult {
        for attempt in 0..max_attempts {
            // Send DHCP DISCOVER
            if self.send_discover().is_err() {
                continue;
            }

            // Wait for DHCP OFFER
            for _ in 0..poll_cycles {
                if let Some(result) = self.check_for_offer() {
                    return result;
                }
            }

            // Increment XID for retry
            self.xid = self.xid.wrapping_add(attempt + 1);
        }

        DhcpResult::Timeout
    }

    // Send a DHCP DISCOVER packet
    fn send_discover(&mut self) -> Result<(), ()> {
        let mut frame = [0u8; 342]; // Minimum DHCP packet size
        let mac = self.eth.mac_address();

        let len = self.build_dhcp_discover(&mut frame, mac);

        self.eth.transmit(&frame[..len]).map_err(|_| ())
    }

    // Build a DHCP DISCOVER packet
    fn build_dhcp_discover(&self, frame: &mut [u8], mac: MacAddress) -> usize {
        // Zero-initialize the fixed header portion via zerocopy
        let header_size = core::mem::size_of::<DhcpFrame>();
        let (hdr_bytes, options_buf) = frame.split_at_mut(header_size);
        let mut hdr = DhcpFrame::read_from_bytes(hdr_bytes).unwrap();

        // Ethernet header
        hdr.eth.dst_mac = BROADCAST_MAC;
        hdr.eth.src_mac = mac;
        hdr.eth.ether_type = U16::new(ETHERTYPE_IPV4);

        // IPv4 header (lengths and checksum filled in below)
        hdr.ip.version_ihl = 0x45; // IPv4, IHL=5
        hdr.ip.identification = U16::new(1);
        hdr.ip.ttl = 64;
        hdr.ip.protocol = IP_PROTO_UDP;
        hdr.ip.src_ip = [0, 0, 0, 0];
        hdr.ip.dst_ip = [255, 255, 255, 255];

        // UDP header (length filled in below)
        hdr.udp.src_port = U16::new(DHCP_CLIENT_PORT);
        hdr.udp.dst_port = U16::new(DHCP_SERVER_PORT);

        // DHCP fixed fields
        hdr.dhcp.op = dhcp_op::BOOTREQUEST;
        hdr.dhcp.htype = 1; // Ethernet
        hdr.dhcp.hlen = 6; // MAC length
        hdr.dhcp.xid = U32::new(self.xid);
        hdr.dhcp.flags = U16::new(0x8000); // Broadcast flag

        // Client hardware address (first 6 bytes of the 16-byte chaddr field)
        hdr.dhcp.chaddr[..6].copy_from_slice(&mac);

        // Magic cookie
        hdr.magic_cookie = DHCP_MAGIC_COOKIE;

        // Write DHCP options after the fixed header
        let mut offset = 0;

        // Option 53: DHCP Message Type = DISCOVER
        options_buf[offset] = dhcp_option::MESSAGE_TYPE;
        options_buf[offset + 1] = 1;
        options_buf[offset + 2] = dhcp_type::DISCOVER;
        offset += 3;

        // Option 55: Parameter Request List
        options_buf[offset] = dhcp_option::PARAMETER_LIST;
        options_buf[offset + 1] = 4;
        options_buf[offset + 2] = dhcp_option::SUBNET_MASK;
        options_buf[offset + 3] = dhcp_option::ROUTER;
        options_buf[offset + 4] = dhcp_option::DNS;
        options_buf[offset + 5] = dhcp_option::HOSTNAME;
        offset += 6;

        // Option 255: End
        options_buf[offset] = dhcp_option::END;
        offset += 1;

        // Total frame size: header + options, padded so DHCP payload >= 300 bytes
        let dhcp_payload_len = core::mem::size_of::<DhcpFixedFields>() + 4 + offset; // fixed + cookie + options
        let padding = if dhcp_payload_len < DHCP_MIN_PAYLOAD {
            DHCP_MIN_PAYLOAD - dhcp_payload_len
        } else {
            0
        };
        let total_frame_len = header_size + offset + padding;

        // Fill in IP and UDP lengths
        let ip_total_len = (total_frame_len - core::mem::size_of::<EthHeader>()) as u16;
        let udp_len = (total_frame_len
            - core::mem::size_of::<EthHeader>()
            - core::mem::size_of::<Ipv4Header>()) as u16;

        hdr.ip.total_length = U16::new(ip_total_len);
        hdr.udp.length = U16::new(udp_len);

        // Compute IP header checksum
        hdr.ip.checksum = U16::new(0);
        // Write the header back so we can checksum it
        hdr_bytes.copy_from_slice(hdr.as_bytes());
        let ip_start = core::mem::size_of::<EthHeader>();
        let ip_end = ip_start + core::mem::size_of::<Ipv4Header>();
        let checksum = ip_checksum(&frame[ip_start..ip_end]);
        // Patch checksum into the frame
        let cksum_offset = ip_start + 10; // checksum is at offset 10 in the IP header
        frame[cksum_offset..cksum_offset + 2].copy_from_slice(&checksum.to_be_bytes());

        total_frame_len
    }

    // Check for a DHCP OFFER response
    fn check_for_offer(&mut self) -> Option<DhcpResult> {
        if !self.eth.rx_available() {
            return None;
        }

        let mut buffer = [0u8; ETH_MAX_FRAME_SIZE];
        let len = match self.eth.receive(&mut buffer) {
            Ok(len) => len,
            Err(_) => return None,
        };

        // Parse the response
        self.parse_dhcp_offer(&buffer[..len])
    }

    // Parse a potential DHCP OFFER packet
    fn parse_dhcp_offer(&self, frame: &[u8]) -> Option<DhcpResult> {
        // Try to interpret the frame as a DhcpFrame (fixed header + remaining options)
        let (hdr, options) = Ref::<&[u8], DhcpFrame>::from_prefix(frame).ok()?;

        // Check EtherType is IPv4
        if hdr.eth.ether_type.get() != ETHERTYPE_IPV4 {
            return None;
        }

        // Check IP protocol is UDP
        if hdr.ip.protocol != IP_PROTO_UDP {
            return None;
        }

        // Check UDP ports
        if hdr.udp.src_port.get() != DHCP_SERVER_PORT {
            return None;
        }
        if hdr.udp.dst_port.get() != DHCP_CLIENT_PORT {
            return None;
        }

        // Check DHCP op is BOOTREPLY
        if hdr.dhcp.op != dhcp_op::BOOTREPLY {
            return None;
        }

        // Check transaction ID
        if hdr.dhcp.xid.get() != self.xid {
            return None;
        }

        // Check magic cookie
        if hdr.magic_cookie != DHCP_MAGIC_COOKIE {
            return None;
        }

        // Extract addresses from the struct
        let offered_ip = hdr.dhcp.yiaddr;
        let server_ip = hdr.dhcp.siaddr;

        // Parse DHCP options to find message type
        let mut pos = 0;
        while pos < options.len() {
            let option = options[pos];
            if option == dhcp_option::END {
                break;
            }
            if option == dhcp_option::PAD {
                pos += 1;
                continue;
            }

            if pos + 1 >= options.len() {
                break;
            }
            let len = options[pos + 1] as usize;
            if pos + 2 + len > options.len() {
                break;
            }

            if option == dhcp_option::MESSAGE_TYPE && len >= 1 {
                let msg_type = options[pos + 2];
                if msg_type == dhcp_type::OFFER {
                    return Some(DhcpResult::OfferReceived {
                        offered_ip,
                        server_ip,
                    });
                }
            }

            pos += 2 + len;
        }

        None
    }
}

/// Calculate IP header checksum over a raw byte slice.
fn ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for i in (0..header.len()).step_by(2) {
        let word = if i + 1 < header.len() {
            ((header[i] as u32) << 8) | (header[i + 1] as u32)
        } else {
            (header[i] as u32) << 8
        };
        sum = sum.wrapping_add(word);
    }
    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}
