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
const ETHERTYPE_IPV4: [u8; 2] = [0x08, 0x00];

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
        let mut offset = 0;

        // === Ethernet Header (14 bytes) ===
        // Destination MAC: broadcast
        frame[offset..offset + 6].copy_from_slice(&BROADCAST_MAC);
        offset += 6;
        // Source MAC
        frame[offset..offset + 6].copy_from_slice(&mac);
        offset += 6;
        // EtherType: IPv4
        frame[offset..offset + 2].copy_from_slice(&ETHERTYPE_IPV4);
        offset += 2;

        // === IP Header (20 bytes) ===
        let ip_header_start = offset;
        frame[offset] = 0x45; // Version (4) + IHL (5)
        offset += 1;
        frame[offset] = 0x00; // DSCP + ECN
        offset += 1;
        // Total length (will be filled later)
        let ip_len_offset = offset;
        offset += 2;
        frame[offset..offset + 2].copy_from_slice(&[0x00, 0x01]); // Identification
        offset += 2;
        frame[offset..offset + 2].copy_from_slice(&[0x00, 0x00]); // Flags + Fragment
        offset += 2;
        frame[offset] = 64; // TTL
        offset += 1;
        frame[offset] = IP_PROTO_UDP; // Protocol
        offset += 1;
        // Header checksum (will be filled later)
        let ip_checksum_offset = offset;
        offset += 2;
        // Source IP: 0.0.0.0
        frame[offset..offset + 4].copy_from_slice(&[0, 0, 0, 0]);
        offset += 4;
        // Destination IP: 255.255.255.255
        frame[offset..offset + 4].copy_from_slice(&[255, 255, 255, 255]);
        offset += 4;

        // === UDP Header (8 bytes) ===
        let udp_header_start = offset;
        // Source port: 68 (DHCP client)
        frame[offset..offset + 2].copy_from_slice(&DHCP_CLIENT_PORT.to_be_bytes());
        offset += 2;
        // Destination port: 67 (DHCP server)
        frame[offset..offset + 2].copy_from_slice(&DHCP_SERVER_PORT.to_be_bytes());
        offset += 2;
        // UDP length (will be filled later)
        let udp_len_offset = offset;
        offset += 2;
        // UDP checksum (0 = disabled)
        frame[offset..offset + 2].copy_from_slice(&[0x00, 0x00]);
        offset += 2;

        // === DHCP Message ===
        let dhcp_start = offset;

        // op: BOOTREQUEST
        frame[offset] = dhcp_op::BOOTREQUEST;
        offset += 1;
        // htype: Ethernet
        frame[offset] = 1;
        offset += 1;
        // hlen: MAC address length
        frame[offset] = 6;
        offset += 1;
        // hops
        frame[offset] = 0;
        offset += 1;
        // xid: Transaction ID
        frame[offset..offset + 4].copy_from_slice(&self.xid.to_be_bytes());
        offset += 4;
        // secs: seconds elapsed
        frame[offset..offset + 2].copy_from_slice(&[0x00, 0x00]);
        offset += 2;
        // flags: broadcast
        frame[offset..offset + 2].copy_from_slice(&[0x80, 0x00]);
        offset += 2;
        // ciaddr: client IP (0.0.0.0)
        frame[offset..offset + 4].copy_from_slice(&[0, 0, 0, 0]);
        offset += 4;
        // yiaddr: your IP (0.0.0.0)
        frame[offset..offset + 4].copy_from_slice(&[0, 0, 0, 0]);
        offset += 4;
        // siaddr: server IP (0.0.0.0)
        frame[offset..offset + 4].copy_from_slice(&[0, 0, 0, 0]);
        offset += 4;
        // giaddr: gateway IP (0.0.0.0)
        frame[offset..offset + 4].copy_from_slice(&[0, 0, 0, 0]);
        offset += 4;
        // chaddr: client hardware address (16 bytes, padded)
        frame[offset..offset + 6].copy_from_slice(&mac);
        offset += 16; // chaddr is 16 bytes, rest is zero
                      // sname: server name (64 bytes, zero)
        offset += 64;
        // file: boot file name (128 bytes, zero)
        offset += 128;

        // Magic cookie
        frame[offset..offset + 4].copy_from_slice(&DHCP_MAGIC_COOKIE);
        offset += 4;

        // DHCP Options
        // Option 53: DHCP Message Type = DISCOVER
        frame[offset] = dhcp_option::MESSAGE_TYPE;
        offset += 1;
        frame[offset] = 1; // length
        offset += 1;
        frame[offset] = dhcp_type::DISCOVER;
        offset += 1;

        // Option 55: Parameter Request List
        frame[offset] = dhcp_option::PARAMETER_LIST;
        offset += 1;
        frame[offset] = 4; // length
        offset += 1;
        frame[offset] = dhcp_option::SUBNET_MASK;
        offset += 1;
        frame[offset] = dhcp_option::ROUTER;
        offset += 1;
        frame[offset] = dhcp_option::DNS;
        offset += 1;
        frame[offset] = dhcp_option::HOSTNAME;
        offset += 1;

        // Option 255: End
        frame[offset] = dhcp_option::END;
        offset += 1;

        // Pad to minimum DHCP size (300 bytes from DHCP start)
        let dhcp_len = offset - dhcp_start;
        if dhcp_len < 300 {
            offset += 300 - dhcp_len;
        }

        // Fill in lengths
        let total_len = offset - ip_header_start;
        let udp_len = offset - udp_header_start;

        // IP total length
        frame[ip_len_offset..ip_len_offset + 2].copy_from_slice(&(total_len as u16).to_be_bytes());
        // UDP length
        frame[udp_len_offset..udp_len_offset + 2].copy_from_slice(&(udp_len as u16).to_be_bytes());

        // Calculate IP header checksum
        let checksum = self.ip_checksum(&frame[ip_header_start..ip_header_start + 20]);
        frame[ip_checksum_offset..ip_checksum_offset + 2].copy_from_slice(&checksum.to_be_bytes());

        offset
    }

    // Calculate IP header checksum
    fn ip_checksum(&self, header: &[u8]) -> u16 {
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
        // Minimum size check: Eth(14) + IP(20) + UDP(8) + DHCP(240)
        if frame.len() < 282 {
            return None;
        }

        // Check EtherType is IPv4
        if frame[12..14] != ETHERTYPE_IPV4 {
            return None;
        }

        // Check IP protocol is UDP
        let ip_header_len = ((frame[14] & 0x0F) as usize) * 4;
        if frame[14 + 9] != IP_PROTO_UDP {
            return None;
        }

        let udp_start = 14 + ip_header_len;
        // Check source port is 67 (DHCP server)
        let src_port = u16::from_be_bytes([frame[udp_start], frame[udp_start + 1]]);
        if src_port != DHCP_SERVER_PORT {
            return None;
        }

        // Check destination port is 68 (DHCP client)
        let dst_port = u16::from_be_bytes([frame[udp_start + 2], frame[udp_start + 3]]);
        if dst_port != DHCP_CLIENT_PORT {
            return None;
        }

        let dhcp_start = udp_start + 8;

        // Check DHCP op is BOOTREPLY
        if frame[dhcp_start] != dhcp_op::BOOTREPLY {
            return None;
        }

        // Check transaction ID
        let xid = u32::from_be_bytes([
            frame[dhcp_start + 4],
            frame[dhcp_start + 5],
            frame[dhcp_start + 6],
            frame[dhcp_start + 7],
        ]);
        if xid != self.xid {
            return None;
        }

        // Get offered IP (yiaddr)
        let offered_ip = [
            frame[dhcp_start + 16],
            frame[dhcp_start + 17],
            frame[dhcp_start + 18],
            frame[dhcp_start + 19],
        ];

        // Get server IP (siaddr)
        let server_ip = [
            frame[dhcp_start + 20],
            frame[dhcp_start + 21],
            frame[dhcp_start + 22],
            frame[dhcp_start + 23],
        ];

        // Check magic cookie
        let cookie_offset = dhcp_start + 236;
        if frame[cookie_offset..cookie_offset + 4] != DHCP_MAGIC_COOKIE {
            return None;
        }

        // Parse options to find message type
        let mut options_offset = cookie_offset + 4;
        while options_offset < frame.len() {
            let option = frame[options_offset];
            if option == dhcp_option::END {
                break;
            }
            if option == dhcp_option::PAD {
                options_offset += 1;
                continue;
            }

            if options_offset + 1 >= frame.len() {
                break;
            }
            let len = frame[options_offset + 1] as usize;
            if options_offset + 2 + len > frame.len() {
                break;
            }

            if option == dhcp_option::MESSAGE_TYPE && len >= 1 {
                let msg_type = frame[options_offset + 2];
                if msg_type == dhcp_type::OFFER {
                    return Some(DhcpResult::OfferReceived {
                        offered_ip,
                        server_ip,
                    });
                }
            }

            options_offset += 2 + len;
        }

        None
    }
}
