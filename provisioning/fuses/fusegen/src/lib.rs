// Licensed under the Apache-2.0 license

use anyhow::{anyhow, bail, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::fmt::Write;
use std::path::Path;

pub const HEADER_PREFIX: &str = r"/*
Licensed under the Apache-2.0 license.
";

pub const HEADER_SUFFIX: &str = r"
*/
";

pub const SKIP_PARTITIONS: &[&str] = &[
    "SECRET_MANUF_PARTITION",
    "SECRET_PROD_PARTITION_0",
    "SECRET_PROD_PARTITION_1",
    "SECRET_PROD_PARTITION_2",
    "SECRET_PROD_PARTITION_3",
    "LIFE_CYCLE",
];

/// The default Caliptra Subsystem OTP memory map file.
pub const OTP_CTRL_MMAP_DEFAULT_PATH: &str =
    "hw/caliptra-ss/src/fuse_ctrl/data/otp_ctrl_mmap.hjson";

/// Default fuse values for testing provisioning flows.
pub const FUSE_VALUES_DEFAULT_PATH: &str = "provisioning/fuses/test.hjson";

/// Default fuse library for testing provisioning flows.
pub const FUSE_LIB_DEFAULT_PATH: &str = "target/provisioning/fuses/test.rs";

#[derive(Debug, Deserialize)]
pub struct OtpMmap {
    pub partitions: Vec<OtpPartition>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Fields are required for HJSON deserialization
pub struct OtpPartition {
    pub name: String,
    pub size: Option<String>, // bytes
    pub secret: bool,
    pub items: Vec<OtpPartitionItem>,
    pub desc: String,
    pub sw_digest: bool,
    pub hw_digest: bool,
}

#[derive(Debug, Deserialize)]
pub struct OtpPartitionItem {
    pub name: String,
    pub size: String, // bytes
}

#[derive(Debug, PartialEq)]
pub enum FuseValue {
    ByteVec(Vec<u8>),
}

impl FuseValue {
    pub fn from_hjson_value(val: &serde_hjson::Value) -> Result<Self> {
        match val {
            serde_hjson::Value::I64(n) => {
                let n = *n as u64;
                Ok(FuseValue::ByteVec(n.to_le_bytes().to_vec()))
            }
            serde_hjson::Value::U64(n) => Ok(FuseValue::ByteVec(n.to_le_bytes().to_vec())),
            serde_hjson::Value::String(s) => {
                let s = s.trim();
                let s = s.strip_prefix("0x").unwrap_or(s);
                let s = s.trim_end_matches(',');
                let s = s.replace(['_', ' '], "");
                // hex::decode requires an even number of digits.
                let s = if s.len() % 2 != 0 {
                    format!("0{}", s)
                } else {
                    s.to_string()
                };
                let bytes = hex::decode(s)?;
                Ok(FuseValue::ByteVec(bytes))
            }
            serde_hjson::Value::Array(arr) => {
                let bytes: Result<Vec<u8>> = arr
                    .iter()
                    .map(|v| {
                        v.as_u64()
                            .and_then(|n| if n <= 255 { Some(n as u8) } else { None })
                            .ok_or_else(|| anyhow!("Array elements must be bytes (0-255)"))
                    })
                    .collect();
                Ok(FuseValue::ByteVec(bytes?))
            }
            _ => bail!("Unsupported HJSON value type for fuse"),
        }
    }
}

pub fn parse_fuse_values_hjson(path: &Path) -> Result<HashMap<String, FuseValue>> {
    let content = std::fs::read_to_string(path)?;
    let raw_map: HashMap<String, serde_hjson::Value> = serde_hjson::from_str(&content)?;
    let mut result = HashMap::new();
    for (name, val) in raw_map {
        result.insert(name, FuseValue::from_hjson_value(&val)?);
    }
    Ok(result)
}

pub fn validate_fuse_values(otp: &OtpMmap, values: &HashMap<String, FuseValue>) -> Result<()> {
    // Collect all valid fuse item names and their sizes.
    let mut item_map = HashMap::new();
    for partition in &otp.partitions {
        if !SKIP_PARTITIONS.contains(&partition.name.as_str()) {
            for item in &partition.items {
                item_map.insert(item.name.clone(), item.size.parse::<usize>()?);
            }
        }
    }
    // Check if field and value size are valid.
    for (name, val) in values {
        let expected_size = item_map
            .get(name)
            .ok_or_else(|| anyhow!("Fuse field '{}' not found in OTP map", name))?;
        let FuseValue::ByteVec(bytes) = val;
        // Check if the value fits in the fuse field. We allow the value to be
        // larger than the field size if the extra bytes are all zeros. This
        // is necessary because HJSON integers are parsed as 8-byte values
        // (i64/u64). See: https://docs.rs/serde-hjson/latest/serde_hjson/enum.Value.html
        if bytes.len() > *expected_size && bytes[*expected_size..].iter().any(|&b| b != 0) {
            bail!(
                "Value for fuse field '{}' is too large ({} bytes, max {} bytes)",
                name,
                bytes.len(),
                expected_size
            );
        }
    }
    Ok(())
}

pub fn generate_phf_fuse_value_lib(
    otp: &OtpMmap,
    values: &HashMap<String, FuseValue>,
) -> Result<String> {
    let mut output = HEADER_PREFIX.to_string();
    output.push_str(HEADER_SUFFIX);
    output.push_str(
        "\npub static FUSE_VALUES: phf::Map<&'static str, &'static [u8]> = phf::phf_map! {\n",
    );

    // Sort keys for deterministic output
    let mut keys: Vec<&String> = values.keys().collect();
    keys.sort();

    for name in keys {
        let val = values.get(name).unwrap();
        let FuseValue::ByteVec(bytes) = val;

        // Find expected size to pad with zeros if needed
        let mut expected_size = 0;
        'outer: for p in &otp.partitions {
            for item in &p.items {
                if item.name == *name {
                    expected_size = item.size.parse::<usize>()?;
                    break 'outer;
                }
            }
        }

        write!(&mut output, "    \"{}\" => &[", name)?;
        for i in 0..expected_size {
            let byte = bytes.get(i).cloned().unwrap_or(0);
            write!(&mut output, "0x{:02x}, ", byte)?;
        }
        output.push_str("],\n");
    }

    output.push_str("};\n");

    Ok(output)
}

pub fn generate_fuse_values_file(
    otp_mmap_path: &Path,
    otp_values_path: &Path,
    out_lib_path: &Path,
) -> Result<()> {
    let otp_mmap_content = std::fs::read_to_string(otp_mmap_path)?;
    let otp_mmap: OtpMmap = serde_hjson::from_str(&otp_mmap_content)?;
    let otp_values = parse_fuse_values_hjson(otp_values_path)?;
    validate_fuse_values(&otp_mmap, &otp_values)?;

    let lib_content = generate_phf_fuse_value_lib(&otp_mmap, &otp_values)?;
    std::fs::write(out_lib_path, lib_content)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fuse_value_from_number() {
        let val = serde_hjson::Value::U64(0x1234);
        let fuse_val = FuseValue::from_hjson_value(&val).unwrap();
        let FuseValue::ByteVec(bytes) = fuse_val;
        // 0x1234 in little-endian is [0x34, 0x12, 0, 0, 0, 0, 0, 0]
        assert_eq!(bytes[0], 0x34);
        assert_eq!(bytes[1], 0x12);
        assert_eq!(bytes.len(), 8);
    }

    #[test]
    fn test_fuse_value_from_hex_string() {
        // With 0x
        let val = serde_hjson::Value::String("0xDEADBEEF".to_string());
        let fuse_val = FuseValue::from_hjson_value(&val).unwrap();
        assert_eq!(fuse_val, FuseValue::ByteVec(vec![0xDE, 0xAD, 0xBE, 0xEF]));

        // Without 0x
        let val = serde_hjson::Value::String("CAFEBABE".to_string());
        let fuse_val = FuseValue::from_hjson_value(&val).unwrap();
        assert_eq!(fuse_val, FuseValue::ByteVec(vec![0xCA, 0xFE, 0xBA, 0xBE]));

        // With underscores and spaces
        let val = serde_hjson::Value::String("0xDE AD_BE EF".to_string());
        let fuse_val = FuseValue::from_hjson_value(&val).unwrap();
        assert_eq!(fuse_val, FuseValue::ByteVec(vec![0xDE, 0xAD, 0xBE, 0xEF]));

        // With trailing comma (HJSON artifact)
        let val = serde_hjson::Value::String("0x1234,".to_string());
        let fuse_val = FuseValue::from_hjson_value(&val).unwrap();
        assert_eq!(fuse_val, FuseValue::ByteVec(vec![0x12, 0x34]));

        // With odd number of digits
        let val = serde_hjson::Value::String("0x123".to_string());
        let fuse_val = FuseValue::from_hjson_value(&val).unwrap();
        assert_eq!(fuse_val, FuseValue::ByteVec(vec![0x01, 0x23]));
    }

    #[test]
    fn test_fuse_value_from_array() {
        let val = serde_hjson::Value::Array(vec![
            serde_hjson::Value::U64(1),
            serde_hjson::Value::U64(2),
            serde_hjson::Value::U64(3),
            serde_hjson::Value::U64(4),
        ]);
        let fuse_val = FuseValue::from_hjson_value(&val).unwrap();
        assert_eq!(fuse_val, FuseValue::ByteVec(vec![1, 2, 3, 4]));
    }

    #[test]
    fn test_fuse_value_invalid_string() {
        let val = serde_hjson::Value::String("not hex".to_string());
        let res = FuseValue::from_hjson_value(&val);
        assert!(res.is_err());
    }

    #[test]
    fn test_validate_fuse_values() {
        let otp = OtpMmap {
            partitions: vec![OtpPartition {
                name: "P1".to_string(),
                size: Some("4".to_string()),
                secret: false,
                items: vec![OtpPartitionItem {
                    name: "F1".to_string(),
                    size: "4".to_string(),
                }],
                desc: "".to_string(),
                sw_digest: false,
                hw_digest: false,
            }],
        };

        let mut values = HashMap::new();
        values.insert("F1".to_string(), FuseValue::ByteVec(vec![1, 2, 3, 4]));

        assert!(validate_fuse_values(&otp, &values).is_ok());

        // Test missing field
        values.insert("F2".to_string(), FuseValue::ByteVec(vec![1]));
        assert!(validate_fuse_values(&otp, &values).is_err());
        values.remove("F2");

        // Test value too large
        values.insert("F1".to_string(), FuseValue::ByteVec(vec![1, 2, 3, 4, 5]));
        assert!(validate_fuse_values(&otp, &values).is_err());

        // Test value from number (will be 8 bytes) for a 4-byte fuse
        let val = serde_hjson::Value::U64(1);
        values.insert("F1".to_string(), FuseValue::from_hjson_value(&val).unwrap());
        // This should now PASS because the extra 4 bytes are zero
        assert!(validate_fuse_values(&otp, &values).is_ok());

        // Test value from number that is actually too large
        let val = serde_hjson::Value::U64(0x1_0000_0000);
        values.insert("F1".to_string(), FuseValue::from_hjson_value(&val).unwrap());
        assert!(validate_fuse_values(&otp, &values).is_err());
    }

    #[test]
    fn test_generate_phf_library() {
        let otp = OtpMmap {
            partitions: vec![OtpPartition {
                name: "P1".to_string(),
                size: Some("4".to_string()),
                secret: false,
                items: vec![OtpPartitionItem {
                    name: "F1".to_string(),
                    size: "4".to_string(),
                }],
                desc: "".to_string(),
                sw_digest: false,
                hw_digest: false,
            }],
        };

        let mut values_map = HashMap::new();
        values_map.insert("F1".to_string(), FuseValue::ByteVec(vec![0xAA, 0xBB]));

        let lib = generate_phf_fuse_value_lib(&otp, &values_map).unwrap();
        assert!(lib.contains("pub static FUSE_VALUES"));
        assert!(lib.contains("phf::phf_map!"));
        assert!(lib.contains("\"F1\" => &[0xaa, 0xbb, 0x00, 0x00, ]"));
    }
}
