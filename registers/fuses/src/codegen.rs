// Licensed under the Apache-2.0 license.

use crate::schema::{FuseConfig, FuseLayoutPolicy};
use anyhow::Result;
use std::collections::HashMap;

/// Information about an OTP partition item (entry) from otp_ctrl_mmap.hjson.
#[derive(Debug, Clone)]
pub struct PartitionItemInfo {
    pub name: String,
    pub byte_offset: usize,
    pub byte_size: usize,
    pub entry_num: usize,
}

/// Information about an OTP partition from otp_ctrl_mmap.hjson.
#[derive(Debug, Clone)]
pub struct PartitionMmapInfo {
    pub partition_index: usize,
    pub byte_offset: usize,
    pub byte_size: usize,
    pub items: Vec<PartitionItemInfo>,
}

fn layout_to_codegen(layout: &Option<FuseLayoutPolicy>, bits: u32) -> String {
    match layout {
        None | Some(FuseLayoutPolicy::Single) => {
            format!("FuseLayoutType::Single {{ bits: {} }}", bits)
        }
        Some(FuseLayoutPolicy::OneHot) => {
            format!("FuseLayoutType::OneHot {{ bits: {} }}", bits)
        }
        Some(FuseLayoutPolicy::LinearMajorityVote { duplication }) => {
            format!(
                "FuseLayoutType::LinearMajorityVote {{ bits: {}, duplication: {} }}",
                bits, duplication
            )
        }
        Some(FuseLayoutPolicy::OneHotLinearMajorityVote { duplication }) => {
            format!(
                "FuseLayoutType::OneHotLinearMajorityVote {{ bits: {}, duplication: {} }}",
                bits, duplication
            )
        }
        Some(FuseLayoutPolicy::WordMajorityVote { duplication }) => {
            format!(
                "FuseLayoutType::WordMajorityVote {{ bits: {}, duplication: {} }}",
                bits, duplication
            )
        }
    }
}

pub fn generate_fuses(
    spec: &FuseConfig,
    partition_mmap: Option<&HashMap<String, PartitionMmapInfo>>,
) -> Result<String> {
    let mut output = String::new();

    // Header types
    output.push_str(stringify!(
        #[derive(Debug, Clone)]
        pub struct Partition {
            pub num: usize,
            pub name: &'static str,
            pub dot: bool,
        }
        #[derive(Debug, Clone, Copy)]
        pub struct Bytes(pub usize);
        #[derive(Debug, Clone, Copy)]
        pub struct Bits(pub usize);
        #[derive(Debug, Clone)]
        pub struct Fuse {
            pub name: &'static str,
            pub size: Bytes,
        }
        #[derive(Debug, Clone)]
        pub struct FuseField {
            pub name: &'static str,
            pub bits: Bits,
        }
        /// Layout type for interpreting raw fuse bits.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum FuseLayoutType {
            Single { bits: u32 },
            OneHot { bits: u32 },
            LinearMajorityVote { bits: u32, duplication: u32 },
            OneHotLinearMajorityVote { bits: u32, duplication: u32 },
            WordMajorityVote { bits: u32, duplication: u32 },
        }
        /// Entry in the fuse lookup table mapping (partition, entry) to OTP location and layout.
        #[derive(Debug, Clone)]
        pub struct FuseEntryInfo {
            /// Partition number (index into OTP partitions)
            pub partition_num: usize,
            /// Entry number within the partition
            pub entry_num: usize,
            /// Byte offset from start of OTP
            pub byte_offset: usize,
            /// Size in bytes of the raw fuse storage
            pub byte_size: usize,
            /// Field name
            pub name: &'static str,
            /// Layout for interpreting the raw bits
            pub layout: FuseLayoutType,
        }
    ));

    // Partitions
    output.push_str("pub const PARTITIONS: &[Partition] = &[");
    for partition in spec.partitions.as_ref().unwrap_or(&vec![]) {
        output.push_str(&format!(
            "Partition {{ num: {}, name: \"{}\", dot: {} }},",
            partition.num,
            partition.name,
            partition.dot.unwrap_or(false)
        ));
    }
    output.push_str("];");

    // Secret vendor fuses
    output.push_str("pub const SECRET_VENDOR_FUSES: &[Fuse] = &[");
    for fuse in &spec.secret_vendor {
        for (name, size) in fuse {
            output.push_str(&format!(
                "Fuse {{ name: \"{}\", size: Bytes({}) }},",
                name, size
            ));
        }
    }
    output.push_str("];");

    // Non-secret vendor fuses
    output.push_str("pub const NON_SECRET_VENDOR_FUSES: &[Fuse] = &[");
    for fuse in &spec.non_secret_vendor {
        for (name, size) in fuse {
            output.push_str(&format!(
                "Fuse {{ name: \"{}\", size: Bytes({}) }},",
                name, size
            ));
        }
    }
    output.push_str("];");

    // Fuse fields
    output.push_str("pub const FUSE_FIELDS: &[FuseField] = &[");
    for field in &spec.fields {
        output.push_str(&format!(
            "FuseField {{ name: \"{}\", bits: Bits({}) }},",
            field.name, field.bits
        ));
    }
    output.push_str("];");

    // Fuse entry lookup table — entries with partition info
    output.push_str(
        "/// Lookup table mapping (partition_num, entry_num) to OTP addresses and layout.\n",
    );
    output.push_str(
        "/// Only populated for fields that have a partition assignment in fuses.hjson.\n",
    );
    output.push_str("pub const FUSE_ENTRY_TABLE: &[FuseEntryInfo] = &[");
    let partitions = spec.partitions.as_ref();
    for field in &spec.fields {
        if let Some(partition_name) = &field.partition {
            // Look up partition index from fuses.hjson partitions list
            let partition_num = partitions
                .and_then(|ps| ps.iter().find(|p| &p.name == partition_name))
                .map(|p| p.num as usize);

            // Look up from OTP mmap info if available
            let mmap_info = partition_mmap.and_then(|m| m.get(partition_name));

            let (part_idx, byte_offset, byte_size, entry_num) = if let Some(mmap) = mmap_info {
                // Try otp_item first, then fall back to field name
                let lookup_name = field.otp_item.as_deref().unwrap_or(&field.name);
                let item = mmap
                    .items
                    .iter()
                    .find(|i| i.name.eq_ignore_ascii_case(lookup_name));
                if let Some(item) = item {
                    (
                        mmap.partition_index,
                        item.byte_offset,
                        item.byte_size,
                        item.entry_num,
                    )
                } else {
                    // Field not found in OTP mmap items — use partition-level info
                    let byte_size = field.bits.div_ceil(8) as usize;
                    (mmap.partition_index, mmap.byte_offset, byte_size, 0)
                }
            } else {
                // No mmap info — use partition_num from fuses.hjson
                let byte_size = field.bits.div_ceil(8) as usize;
                (partition_num.unwrap_or(0), 0, byte_size, 0)
            };

            let layout_str = layout_to_codegen(&field.layout, field.bits);
            output.push_str(&format!(
                "FuseEntryInfo {{ partition_num: {}, entry_num: {}, byte_offset: 0x{:x}, byte_size: {}, name: \"{}\", layout: {} }},",
                part_idx, entry_num, byte_offset, byte_size, field.name, layout_str
            ));
        }
    }
    output.push_str("];");

    // Named const references to individual entries
    let mut entry_idx = 0usize;
    for field in &spec.fields {
        if field.partition.is_some() {
            let const_name = field.name.to_uppercase();
            output.push_str(&format!(
                "/// Fuse entry for `{}`.\npub const {}: &FuseEntryInfo = &FUSE_ENTRY_TABLE[{}];",
                field.name, const_name, entry_idx
            ));
            entry_idx += 1;
        }
    }

    let tokens = syn::parse_file(&output)?;
    let formatted = prettyplease::unparse(&tokens);

    // Prepend the header comments back since prettyplease strips them
    let result = format!(
        "// Licensed under the Apache-2.0 license.\n// Autogenerated file from fuses.hjson. Do not modify this file.\n\n{}",
        formatted
    );

    Ok(result)
}

#[cfg(test)]
mod tests {
    use crate::schema::parse_fuse_hjson_str;

    use super::*;

    #[test]
    fn test_generate_fuses() {
        let example_hjson = r#"
{
  partitions: [
    {num: 10, name: "device_ownership_transfer", dot: true},
    {num: 11, name: "secret_vendor"},
  ],
  // vendor-specific secret fuses
  secret_vendor: [
    {"example_key1": 48}, // size in bytes
    {"example_key2": 48}, // size in bytes
    {"example_key3": 48}, // size in bytes
    {"example_key4": 48}, // size in bytes
  ],
  // vendor-specific non-secret-fuses
  non_secret_vendor: [
    {"example_key_revocation": 1}
  ],
  // TBD how we allow additional fuses outside of these areas, if this is allowed by OTP
  other_fuses: {},
  // entries to define how many bits are in each field, and potentially other information
  fields: [
    {name: "CPTRA_SS_OWNER_ECC_REVOCATION", bits: 4},
    {name: "example_key_revocation", bits: 4},
  ]
}
"#;

        let config = parse_fuse_hjson_str(example_hjson).unwrap();
        let generated_code = generate_fuses(&config, None).unwrap();

        println!("Generated code:\n{}", generated_code);

        // Verify key structures are present
        assert!(generated_code.contains("pub struct Partition"));
        assert!(generated_code.contains("pub struct FuseEntryInfo"));
        assert!(generated_code.contains("pub enum FuseLayoutType"));
        assert!(generated_code.contains("pub const PARTITIONS:"));
        assert!(generated_code.contains("pub const SECRET_VENDOR_FUSES:"));
        assert!(generated_code.contains("pub const NON_SECRET_VENDOR_FUSES:"));
        assert!(generated_code.contains("pub const FUSE_FIELDS:"));
        assert!(generated_code.contains("pub const FUSE_ENTRY_TABLE:"));
        assert!(generated_code.contains("\"device_ownership_transfer\""));
        assert!(generated_code.contains("\"secret_vendor\""));
        assert!(generated_code.contains("\"example_key1\""));
        assert!(generated_code.contains("\"CPTRA_SS_OWNER_ECC_REVOCATION\""));
    }

    #[test]
    fn test_generate_fuses_with_layout_and_partition() {
        let example_hjson = r#"
{
  partitions: [
    {num: 5, name: "revocations"},
  ],
  secret_vendor: [],
  non_secret_vendor: [],
  other_fuses: {},
  fields: [
    {
      name: "ecc_revocation",
      bits: 4,
      partition: "revocations",
      layout: {type: "LinearMajorityVote", duplication: 3}
    },
    {
      name: "simple_field",
      bits: 32,
      partition: "revocations",
      layout: {type: "Single"}
    },
  ]
}
"#;

        let config = parse_fuse_hjson_str(example_hjson).unwrap();
        let generated_code = generate_fuses(&config, None).unwrap();

        println!("Generated code:\n{}", generated_code);

        assert!(generated_code.contains("FUSE_ENTRY_TABLE"));
        assert!(generated_code.contains("partition_num: 5"));
        assert!(generated_code.contains("LinearMajorityVote"));
        assert!(generated_code.contains("duplication: 3"));
        assert!(generated_code.contains("\"ecc_revocation\""));
        assert!(generated_code.contains("\"simple_field\""));
    }
}
