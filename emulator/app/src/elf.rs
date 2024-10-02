// Licensed under the Apache-2.0 license

use elf::abi::PT_LOAD;
use elf::endian::AnyEndian;
use elf::ElfBytes;
use std::io::{Error, ErrorKind};

/// ELF Executable
#[derive(Default)]
pub struct ElfExecutable {
    load_addr: u32,
    entry_point: u32,
    content: Vec<u8>,
}

pub fn load_into_image(
    image: &mut Vec<u8>,
    image_base_addr: u32,
    section_addr: u32,
    section_data: &[u8],
) -> Result<(), Error> {
    if section_addr < image_base_addr {
        Err(Error::new(ErrorKind::InvalidData, format!("Section address 0x{section_addr:08x} is below image base address 0x{image_base_addr:08x}")))?;
    }
    let section_offset = usize::try_from(section_addr - image_base_addr).unwrap();
    image.resize(
        usize::max(image.len(), section_offset + section_data.len()),
        u8::default(),
    );
    image[section_offset..][..section_data.len()].copy_from_slice(section_data);
    Ok(())
}

impl ElfExecutable {
    /// Create new instance of `ElfExecutable`.
    pub fn new(elf_bytes: &[u8]) -> Result<Self, Error> {
        let mut content = vec![];

        let elf_file = ElfBytes::<AnyEndian>::minimal_parse(elf_bytes).map_err(|e| {
            Error::new(
                ErrorKind::InvalidData,
                format!("Failed to parse ELF file: {:?}", e),
            )
        })?;

        let Some(segments) = elf_file.segments() else {
            Err(Error::new(
                ErrorKind::InvalidData,
                "ELF file has no segments",
            ))?
        };

        let Some(load_addr) = segments
            .iter()
            .filter(|s| s.p_type == PT_LOAD)
            .map(|s| s.p_paddr as u32)
            .min()
        else {
            Err(Error::new(
                ErrorKind::InvalidData,
                "ELF file has no LOAD segments",
            ))?
        };

        for segment in segments {
            if segment.p_type != PT_LOAD {
                continue;
            }
            let segment_data = elf_file
                .segment_data(&segment)
                .map_err(|e| Error::new(ErrorKind::InvalidData, e.to_string()))?;
            if segment_data.is_empty() {
                continue;
            }
            load_into_image(
                &mut content,
                load_addr,
                segment.p_paddr as u32,
                segment_data,
            )?;
        }

        let entry_point = elf_file.ehdr.e_entry as u32;

        Ok(Self {
            load_addr,
            entry_point,
            content,
        })
    }
}

impl ElfExecutable {
    /// Executable load address
    pub fn load_addr(&self) -> u32 {
        self.load_addr
    }

    /// Executable entry point
    pub fn entry_point(&self) -> u32 {
        self.entry_point
    }

    /// Executable content
    pub fn content(&self) -> &Vec<u8> {
        &self.content
    }
}

#[cfg(test)]
mod test {
    use crate::elf::load_into_image;

    #[test]
    fn test_load_into_image() {
        let mut image = Vec::new();
        load_into_image(&mut image, 0x4000_0000, 0x4000_0006, b"hello world").unwrap();
        load_into_image(&mut image, 0x4000_0000, 0x4000_0000, b"abcdef").unwrap();
        load_into_image(&mut image, 0x4000_0000, 0x4000_0011, b"hi").unwrap();
        assert_eq!(&image, b"abcdefhello worldhi");
    }

    #[test]
    fn test_load_into_image_bad_address() {
        let mut image = Vec::new();
        assert_eq!(
            load_into_image(&mut image, 0x4000_0000, 0x3fff_ffff, b"h")
                .unwrap_err()
                .to_string(),
            "Section address 0x3fffffff is below image base address 0x40000000"
        );
    }
}
