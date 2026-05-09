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
}
