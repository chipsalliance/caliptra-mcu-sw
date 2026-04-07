// Licensed under the Apache-2.0 license

use anyhow::{bail, Result};

/// This reads a 24-bit OTP memory file (vmem format) data and returns the data as a vector of bytes, as output
/// by caliptra-ss/tools/scripts/fuse_ctrl_script/lib/otp_mem_img.py.
/// This throws away the ECC data bits.
pub fn read_otp_vmem_data(vmem_data: &[u8]) -> Result<Vec<u8>> {
    let mut output = vec![];
    let vmem_str = String::from_utf8_lossy(vmem_data);
    for line in vmem_str.lines() {
        let line = line.trim_start();
        if let Some(line) = line.strip_prefix('@') {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                bail!("Invalid vmem line: {}", line);
            }
            let addr = parts[0].trim();
            let addr = u32::from_str_radix(addr, 16)
                .map_err(|_| anyhow::anyhow!("Invalid address: {}", line))?
                as usize
                * 2;
            let val = parts[1].trim();
            if val.len() > 6 {
                bail!(
                    "Invalid hex value length {} (should be 6): {}",
                    val.len(),
                    line
                );
            }
            let val = u32::from_str_radix(parts[1], 16)
                .map_err(|_| anyhow::anyhow!("Invalid hex value: {}", line))?;
            let val = val.to_be_bytes();
            // ignore ECC byte and leading 0x00
            let a = val[2];
            let b = val[3];
            output.resize(addr + 2, 0x00);
            output[addr] = b;
            output[addr + 1] = a;
        }
    }
    Ok(output)
}

#[allow(unused)]
pub(crate) fn write_otp_vmem_data(bytes: &[u8]) -> Result<String> {
    let mut output = String::new();
    if bytes.len() % 2 != 0 {
        bail!("OTP memory data length must be even, got {}", bytes.len());
    }

    for i in (0..bytes.len()).step_by(2) {
        let a = bytes[i];
        let b = bytes[i + 1];
        let addr = i / 2;
        output.push_str(&format!(
            "@{:06x} {:06x}\n",
            addr,
            to_ecc(u16::from_be_bytes([b, a]))
        ));
    }

    Ok(output)
}

/// Converts a 16-bit raw word to a 22-bit word with ECC bits set.
fn to_ecc(data_i: u16) -> u32 {
    let mut data_o = data_i as u32;
    data_o |= ((data_o & 0x0ad5b).count_ones() & 1) << 16;
    data_o |= ((data_o & 0x0366d).count_ones() & 1) << 17;
    data_o |= ((data_o & 0x0c78e).count_ones() & 1) << 18;
    data_o |= ((data_o & 0x007f0).count_ones() & 1) << 19;
    data_o |= ((data_o & 0x0f800).count_ones() & 1) << 20;
    data_o |= ((data_o & 0x1f_ffff).count_ones() & 1) << 21;
    data_o
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_read_write_vmem() {
        let vmem_data = r#"
//
// OTP MEM file with 2048 x 24bit layout
@000000 000000 // SW_TEST_UNLOCK_PARTITION: CPTRA_SS_MANUF_DEBUG_UNLOCK_TOKEN
@000001 000000 // SW_TEST_UNLOCK_PARTITION: CPTRA_SS_MANUF_DEBUG_UNLOCK_TOKEN

@00000b 07628d // LIFE_CYCLE: LC_STATE
@00000c 17b228 // LIFE_CYCLE: LC_STATE
@00000d 091e71 // LIFE_CYCLE: LC_STATE
@00000e 042d9b // LIFE_CYCLE: LC_STATE
@00000f 2a4d8c // LIFE_CYCLE: LC_STATE
"#;

        let mut expected = [0u8; 32];
        expected[0x16] = 0x8d;
        expected[0x17] = 0x62;
        expected[0x18] = 0x28;
        expected[0x19] = 0xb2;
        expected[0x1a] = 0x71;
        expected[0x1b] = 0x1e;
        expected[0x1c] = 0x9b;
        expected[0x1d] = 0x2d;
        expected[0x1e] = 0x8c;
        expected[0x1f] = 0x4d;

        let read = read_otp_vmem_data(vmem_data.as_bytes()).unwrap();

        let expected_vmem_str = r#"
@000000 000000
@000001 000000
@000002 000000
@000003 000000
@000004 000000
@000005 000000
@000006 000000
@000007 000000
@000008 000000
@000009 000000
@00000a 000000
@00000b 07628d
@00000c 17b228
@00000d 091e71
@00000e 042d9b
@00000f 2a4d8c
"#;

        assert_eq!(
            write_otp_vmem_data(&read).unwrap().trim(),
            expected_vmem_str.trim()
        );

        assert_eq!(read, expected);
    }

    /// Validates the complete CPTRA_CORE_VENDOR_PK_HASH_0 encoding example documented in
    /// docs/src/rom-fuses.md, tracing the 48-byte hash from standard SHA-384 byte order
    /// through OTP memory layout, vmem 16-bit words, and the u32 values written to Caliptra.
    #[test]
    fn test_vendor_pk_hash_doc_example() {
        // SHA-384 output (standard big-endian) as used in docs/src/rom-fuses.md.
        #[rustfmt::skip]
        let hash_standard: [u8; 48] = [
            0xb1, 0x7c, 0xa8, 0x77,  0x66, 0x66, 0x57, 0xcc,
            0xd1, 0x00, 0xe6, 0x92,  0x6c, 0x72, 0x06, 0xb6,
            0x0c, 0x99, 0x5c, 0xb6,  0x89, 0x92, 0xc6, 0xc9,
            0xba, 0xef, 0xce, 0x72,  0x8a, 0xf0, 0x54, 0x41,
            0xde, 0xe1, 0xff, 0x41,  0x5a, 0xdf, 0xc1, 0x87,
            0xe1, 0xe4, 0xed, 0xb4,  0xd3, 0xb2, 0xd9, 0x09,
        ];

        // Layer 1: OTP memory bytes.
        // emulator/periph/src/otp.rs applies swap_endianness (reverses each 4-byte group)
        // before writing to VENDOR_HASHES_MANUF_PARTITION_BYTE_OFFSET = 0x3F8.
        let mut otp_bytes = hash_standard;
        for chunk in otp_bytes.chunks_exact_mut(4) {
            chunk.reverse();
        }
        #[rustfmt::skip]
        let expected_otp_bytes: [u8; 48] = [
            0x77, 0xa8, 0x7c, 0xb1,  0xcc, 0x57, 0x66, 0x66,
            0x92, 0xe6, 0x00, 0xd1,  0xb6, 0x06, 0x72, 0x6c,
            0xb6, 0x5c, 0x99, 0x0c,  0xc9, 0xc6, 0x92, 0x89,
            0x72, 0xce, 0xef, 0xba,  0x41, 0x54, 0xf0, 0x8a,
            0x41, 0xff, 0xe1, 0xde,  0x87, 0xc1, 0xdf, 0x5a,
            0xb4, 0xed, 0xe4, 0xe1,  0x09, 0xd9, 0xb2, 0xd3,
        ];
        assert_eq!(otp_bytes, expected_otp_bytes, "OTP byte layout mismatch");

        // Layer 2: backdoor vmem format.
        // The actual partition starts at OTP byte 0x3F8 (vmem word addr 0x1FC).
        // Build a buffer with the hash at that offset and verify the relevant vmem entries.
        let hash_byte_offset = 0x3F8usize;
        let buf_len = hash_byte_offset + 48;
        let mut otp_buf = vec![0u8; buf_len];
        otp_buf[hash_byte_offset..].copy_from_slice(&otp_bytes);
        let vmem = write_otp_vmem_data(&otp_buf).unwrap();

        // Extract the 16-bit data words (bits [15:0]) from the vmem lines at 0x1FC..0x213.
        // Expected values from docs/src/rom-fuses.md Layer 2 table.
        let expected_vmem_words: &[(&str, u16)] = &[
            ("0001fc", 0xa877),
            ("0001fd", 0xb17c),
            ("0001fe", 0x57cc),
            ("0001ff", 0x6666),
            ("000200", 0xe692),
            ("000201", 0xd100),
            ("000202", 0x06b6),
            ("000203", 0x6c72),
            ("000204", 0x5cb6),
            ("000205", 0x0c99),
            ("000206", 0xc6c9),
            ("000207", 0x8992),
            ("000208", 0xce72),
            ("000209", 0xbaef),
            ("00020a", 0x5441),
            ("00020b", 0x8af0),
            ("00020c", 0xff41),
            ("00020d", 0xdee1),
            ("00020e", 0xc187),
            ("00020f", 0x5adf),
            ("000210", 0xedb4),
            ("000211", 0xe1e4),
            ("000212", 0xd909),
            ("000213", 0xd3b2),
        ];
        for (expected_addr, expected_data) in expected_vmem_words {
            let needle = format!("@{expected_addr} ");
            let line = vmem
                .lines()
                .find(|l| l.starts_with(&needle))
                .unwrap_or_else(|| panic!("vmem entry @{expected_addr} not found"));
            let raw = u32::from_str_radix(line.split_whitespace().nth(1).unwrap(), 16).unwrap();
            let data_bits = (raw & 0xffff) as u16;
            assert_eq!(
                data_bits, *expected_data,
                "vmem @{expected_addr}: data bits {data_bits:#06x} != {expected_data:#06x}"
            );
        }

        // Layer 3 + 4: OTP DAI → MCU ROM → Caliptra fuse registers.
        // rom/src/otp.rs: read_data reads u32 via read_word (LE interpretation of 4 OTP bytes),
        // then to_le_bytes() gives back the original bytes.
        // rom/src/rom.rs: populate_fuses does u32::from_le_bytes then sets fuse_vendor_pk_hash[i].
        #[rustfmt::skip]
        let expected_caliptra_regs: [u32; 12] = [
            0xb17ca877, 0x666657cc, 0xd100e692, 0x6c7206b6,
            0x0c995cb6, 0x8992c6c9, 0xbaefce72, 0x8af05441,
            0xdee1ff41, 0x5adfc187, 0xe1e4edb4, 0xd3b2d909,
        ];
        let caliptra_regs: [u32; 12] = otp_bytes
            .chunks_exact(4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        assert_eq!(
            caliptra_regs, expected_caliptra_regs,
            "Caliptra register values mismatch"
        );

        // Each Caliptra register must equal the corresponding 4 standard hash bytes as a
        // big-endian u32 — this is the invariant the documentation describes.
        for (i, &reg) in caliptra_regs.iter().enumerate() {
            let be_u32 = u32::from_be_bytes(hash_standard[i * 4..(i + 1) * 4].try_into().unwrap());
            assert_eq!(
                reg, be_u32,
                "fuse_vendor_pk_hash[{i}] should equal standard hash bytes[{i}*4..] as big-endian u32"
            );
        }
    }

    /// Validates the PQC key type fuse encoding example documented in docs/src/rom-fuses.md,
    /// tracing vendor_pqc_key_type_0 (OneHotLinearMajorityVote{bits:2,dupe:3}) at OTP byte
    /// offset 0x428 through OTP bytes, vmem, and DAI read for both MLDSA and LMS. FPGA-verified.
    #[test]
    fn test_pqc_key_type_doc_example() {
        // For OneHotLinearMajorityVote { bits: 2, duplication: 3 }:
        //   MLDSA logical value = 1 → onehot = 0b01 → raw = 0x00000007
        //   LMS   logical value = 2 → onehot = 0b11 → raw = 0x0000003F
        let cases: &[(&str, u32, u16)] =
            &[("MLDSA", 0x00000007, 0x0007), ("LMS", 0x0000003F, 0x003f)];

        let hash_byte_offset = 0x428usize;

        for &(label, raw_u32, expected_vmem_data) in cases {
            // Layer 1: OTP bytes are the little-endian representation of the raw u32.
            let otp_bytes = raw_u32.to_le_bytes();

            // Layer 2: vmem at @000214 (byte offset 0x428).
            let buf_len = hash_byte_offset + 4;
            let mut otp_buf = vec![0u8; buf_len];
            otp_buf[hash_byte_offset..].copy_from_slice(&otp_bytes);
            let vmem = write_otp_vmem_data(&otp_buf).unwrap();

            let line = vmem
                .lines()
                .find(|l| l.starts_with("@000214 "))
                .unwrap_or_else(|| panic!("{label}: vmem @000214 not found"));
            let raw_entry =
                u32::from_str_radix(line.split_whitespace().nth(1).unwrap(), 16).unwrap();
            let data_bits = (raw_entry & 0xffff) as u16;
            assert_eq!(
                data_bits, expected_vmem_data,
                "{label}: vmem @000214 data bits {data_bits:#06x} != {expected_vmem_data:#06x}"
            );

            // @000215 must be all-zero data (upper bytes of the u32 are 0x00).
            let line215 = vmem
                .lines()
                .find(|l| l.starts_with("@000215 "))
                .unwrap_or_else(|| panic!("{label}: vmem @000215 not found"));
            let raw215 =
                u32::from_str_radix(line215.split_whitespace().nth(1).unwrap(), 16).unwrap();
            assert_eq!(
                raw215 & 0xffff,
                0,
                "{label}: vmem @000215 data bits should be 0x0000"
            );

            // Layer 3: DAI read yields the same raw u32 (read_word gives the LE-packed u32
            // directly from the two 16-bit OTP words).
            let dai_rdata: u32 = u32::from_le_bytes(otp_bytes);
            assert_eq!(dai_rdata, raw_u32, "{label}: DAI rdata mismatch");
        }
    }
}
