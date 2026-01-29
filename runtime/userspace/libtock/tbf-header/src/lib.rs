// Adapted from elf2tab, which is:

// MIT License

// Copyright (c) 2018 Tock Embedded OS

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use std::cmp;
use std::fmt;
use std::io;
use std::io::{Read, Seek, SeekFrom, Write};
use std::mem;
use std::slice;
use std::vec;

#[repr(u16)]
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
pub enum TbfHeaderTypes {
    Main = 1,
    WriteableFlashRegions = 2,
    PackageName = 3,
    PicOption1 = 4,
    FixedAddresses = 5,
    Permissions = 6,
    Persistent = 7,
    KernelVersion = 8,

    Program = 9,

    Credentials = 128,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
pub enum TbfFooterCredentialsType {
    Reserved = 0,
    Rsa3072Key = 1,
    Rsa4096Key = 2,
    SHA256 = 3,
    SHA384 = 4,
    SHA512 = 5,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TbfHeaderTlv {
    pub tipe: TbfHeaderTypes,
    pub length: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct TbfHeaderBase {
    version: u16,
    header_size: u16,
    total_size: u32,
    flags: u32,
    checksum: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct TbfHeaderMain {
    base: TbfHeaderTlv,
    init_fn_offset: u32,
    protected_size: u32,
    minimum_ram_size: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct TbfHeaderProgram {
    base: TbfHeaderTlv,
    init_fn_offset: u32,
    protected_size: u32,
    minimum_ram_size: u32,
    binary_end_offset: u32,
    app_version: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct TbfHeaderWriteableFlashRegion {
    base: TbfHeaderTlv,
    offset: u32,
    size: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct TbfHeaderFixedAddresses {
    base: TbfHeaderTlv,
    start_process_ram: u32,
    start_process_flash: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct TbfHeaderDriverPermission {
    driver_number: u32,
    offset: u32,
    allowed_commands: u64,
}

#[repr(C)]
#[derive(Debug, Clone)]
struct TbfHeaderPermissions {
    base: TbfHeaderTlv,
    length: u16,
    perms: Vec<TbfHeaderDriverPermission>,
}

#[repr(C)]
#[derive(Debug, Clone)]
struct TbfHeaderPersistentAcl {
    base: TbfHeaderTlv,
    write_id: u32,
    read_length: u16,
    read_ids: Vec<u32>,
    access_length: u16,
    access_ids: Vec<u32>,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct TbfHeaderKernelVersion {
    base: TbfHeaderTlv,
    major: u16,
    minor: u16,
}

#[repr(C)]
#[derive(Debug)]
#[allow(dead_code)]
pub struct TbfFooterCredentials {
    pub base: TbfHeaderTlv,
    pub format: TbfFooterCredentialsType,
    pub data: Vec<u8>,
}

#[allow(dead_code)]
impl TbfFooterCredentials {
    pub fn generate(&self) -> io::Result<io::Cursor<vec::Vec<u8>>> {
        let mut header_buf = io::Cursor::new(Vec::new());
        header_buf.write_all(unsafe { as_byte_slice(&self.base) })?;
        header_buf.write_all(unsafe { as_byte_slice(&self.format) })?;
        for b in &self.data {
            header_buf.write_all(unsafe { as_byte_slice(b) })?;
        }
        Ok(header_buf)
    }
}

impl fmt::Display for TbfHeaderBase {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(
            f,
            "
               version: {0:>8} {0:>#10X}
           header_size: {1:>8} {1:>#10X}
            total_size: {2:>8} {2:>#10X}
                 flags: {3:>8} {3:>#10X}",
            self.version, self.header_size, self.total_size, self.flags,
        )
    }
}

impl fmt::Display for TbfHeaderMain {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(
            f,
            "
        init_fn_offset: {0:>8} {0:>#10X}
        protected_size: {1:>8} {1:>#10X}
      minimum_ram_size: {2:>8} {2:>#10X}",
            self.init_fn_offset, self.protected_size, self.minimum_ram_size,
        )
    }
}

impl fmt::Display for TbfHeaderProgram {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(
            f,
            "
        init_fn_offset: {0:>8} {0:>#10X}
        protected_size: {1:>8} {1:>#10X}
      minimum_ram_size: {2:>8} {2:>#10X}
     binary_end_offset: {3:>8} {3:>#10X}
           app_version: {4:>8} {4:>#10X}",
            self.init_fn_offset,
            self.protected_size,
            self.minimum_ram_size,
            self.binary_end_offset,
            self.app_version
        )
    }
}

impl fmt::Display for TbfHeaderWriteableFlashRegion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(
            f,
            "
    flash region:
                offset: {0:>8} {0:>#10X}
                  size: {1:>8} {1:>#10X}",
            self.offset, self.size,
        )
    }
}

impl fmt::Display for TbfHeaderFixedAddresses {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(
            f,
            "
     start_process_ram: {0:>8} {0:>#10X}
   start_process_flash: {1:>8} {1:>#10X}",
            self.start_process_ram, self.start_process_flash,
        )
    }
}

impl fmt::Display for TbfHeaderPermissions {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(
            f,
            "
    driver permissions: {0:>8}
           permissions:   Number   Offset  Allowed Bit Mask",
            self.length,
        )?;

        for perm in &self.perms {
            writeln!(
                f,
                "                      : {0:>#8X} {1:>#8} {2:>#17X}",
                perm.driver_number, perm.offset, perm.allowed_commands,
            )?;
        }
        Ok(())
    }
}

impl fmt::Display for TbfHeaderPersistentAcl {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(
            f,
            "
              write ID: {0:>#19X}",
            self.write_id
        )?;

        if self.read_length > 0 {
            writeln!(f, "              read IDs: {0:>#8}", self.read_length,)?;
            for read_id in &self.read_ids {
                writeln!(f, "                      : {0:>#19X}", read_id,)?;
            }
        }

        if self.access_length > 0 {
            writeln!(f, "            access IDs: {0:>#8}", self.access_length)?;
            for access_id in &self.access_ids {
                writeln!(f, "                      : {0:>#19X}", access_id,)?;
            }
        }

        Ok(())
    }
}

impl fmt::Display for TbfHeaderKernelVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // ^x.y means >= x.y, < (x+1).0
        writeln!(
            f,
            "
        kernel version: ^{}.{}",
            self.major, self.minor
        )
    }
}

const FLAGS_ENABLE: u32 = 0x0000_0001;

#[derive(Debug, Clone)]
pub struct TbfHeader {
    hdr_base: TbfHeaderBase,
    hdr_main: Option<TbfHeaderMain>,
    hdr_program: Option<TbfHeaderProgram>,
    hdr_pkg_name_tlv: Option<TbfHeaderTlv>,
    hdr_wfr: Vec<TbfHeaderWriteableFlashRegion>,
    hdr_fixed_addresses: Option<TbfHeaderFixedAddresses>,
    hdr_permissions: Option<TbfHeaderPermissions>,
    hdr_persistent: Option<TbfHeaderPersistentAcl>,
    hdr_kernel_version: Option<TbfHeaderKernelVersion>,
    package_name: String,
    package_name_pad: usize,
}

#[allow(dead_code)]
impl TbfHeader {
    pub fn new() -> Self {
        Self {
            hdr_base: TbfHeaderBase {
                version: 2, // Current version is 2.
                header_size: 0,
                total_size: 0,
                flags: 0,
                checksum: 0,
            },
            hdr_main: Some(TbfHeaderMain {
                base: TbfHeaderTlv {
                    tipe: TbfHeaderTypes::Main,
                    length: (mem::size_of::<TbfHeaderMain>() - mem::size_of::<TbfHeaderTlv>())
                        as u16,
                },
                init_fn_offset: 0,
                protected_size: 0,
                minimum_ram_size: 0,
            }),
            hdr_program: None,
            hdr_pkg_name_tlv: None,
            hdr_wfr: Vec::new(),
            hdr_fixed_addresses: None,
            hdr_permissions: None,
            hdr_persistent: None,
            hdr_kernel_version: None,
            package_name: String::new(),
            package_name_pad: 0,
        }
    }

    /// Start creating the Tock Binary Format Header. This function expects
    /// a few parameters that should be known very easily. Other values that
    /// we need to create the header (like the location of things in the flash
    /// binary) can be passed in later after we know the size of the header.
    ///
    /// Returns: The length of the header in bytes. The length is guaranteed
    ///          to be a multiple of 4.
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        &mut self,
        minimum_ram_size: u32,
        writeable_flash_regions: usize,
        package_name: String,
        fixed_address_ram: Option<u32>,
        fixed_address_flash: Option<u32>,
        permissions: Vec<(u32, u32)>,
        storage_ids: (Option<u32>, Option<Vec<u32>>, Option<Vec<u32>>),
        kernel_version: Option<(u16, u16)>,
        disabled: bool,
    ) -> usize {
        // Need to calculate lengths ahead of time. Need the base and the
        // program section. For backwards compatibility we include both the main
        // and program header. The program header is preferred, and the
        // intention is for it to replace the main header. However, older Tock
        // kernels we support only recognize the main header, so we include it
        // as well. Newer kernels and other tools should use the program header
        // and ignore the main header.
        let mut header_length = mem::size_of::<TbfHeaderBase>();
        header_length += mem::size_of::<TbfHeaderMain>();
        header_length += mem::size_of::<TbfHeaderProgram>();

        // If we have a package name, add that section.
        self.package_name_pad = if !package_name.is_empty() {
            // Header increases by the TLV and name length.
            header_length += mem::size_of::<TbfHeaderTlv>() + package_name.len();
            // How much padding is needed to ensure we are aligned to 4?
            let pad = amount_alignment_needed(header_length as u32, 4);
            // Header length increases by that padding
            header_length += pad as usize;
            pad as usize
        } else {
            0
        };

        // Add room for the writeable flash regions header TLV.
        header_length += mem::size_of::<TbfHeaderWriteableFlashRegion>() * writeable_flash_regions;

        // Check if we are going to include the fixed address header. If so, we
        // need to make sure we include it in the length. If either address is
        // set we need to include the entire header.
        if fixed_address_ram.is_some() || fixed_address_flash.is_some() {
            header_length += mem::size_of::<TbfHeaderFixedAddresses>();
        }

        // Check to see how many perms we have
        let mut perms: Vec<TbfHeaderDriverPermission> = Vec::new();
        for perm in permissions {
            let offset = perm.1 / 64;
            let allowed_command = 1 << (perm.1 % 64);
            let mut complete = false;

            for p in &mut perms {
                if p.driver_number == perm.0 && p.offset == offset {
                    p.allowed_commands |= allowed_command;
                    complete = true;
                }
            }

            if !complete {
                perms.push(TbfHeaderDriverPermission {
                    driver_number: perm.0,
                    offset: perm.1 / 64,
                    allowed_commands: allowed_command,
                })
            }
        }

        if !perms.is_empty() {
            // base
            header_length += mem::size_of::<TbfHeaderTlv>();
            // length
            header_length += mem::size_of::<u16>();
            // perms
            header_length += mem::size_of::<TbfHeaderDriverPermission>() * perms.len();

            // Header length increases by that padding
            header_length += 2;
        }

        if storage_ids.0.is_some() || storage_ids.1.is_some() || storage_ids.2.is_some() {
            // base
            header_length += mem::size_of::<TbfHeaderTlv>();
            //write_id
            header_length += mem::size_of::<u32>();
            // read_length
            header_length += mem::size_of::<u16>();
            if let Some(read_ids) = &storage_ids.1 {
                // read_ids
                header_length += mem::size_of::<u32>() * read_ids.len();
            }
            // access_length
            header_length += mem::size_of::<u16>();
            if let Some(access_ids) = &storage_ids.2 {
                // access_ids
                header_length += mem::size_of::<u32>() * access_ids.len();
            }
        }

        // Check if we have to include a kernel version header.
        if kernel_version.is_some() {
            header_length += mem::size_of::<TbfHeaderKernelVersion>();
        }

        let mut flags = 0x0000_0000;

        if !disabled {
            flags |= FLAGS_ENABLE
        };

        // Fill in the fields that we can at this point.
        self.hdr_base.header_size = header_length as u16;
        self.hdr_base.flags = flags;
        self.set_minimum_ram_size(minimum_ram_size);

        // If a package name exists, keep track of it and add it to the header.
        self.package_name = package_name;
        if !self.package_name.is_empty() {
            self.hdr_pkg_name_tlv = Some(TbfHeaderTlv {
                tipe: TbfHeaderTypes::PackageName,
                length: self.package_name.len() as u16,
            });
        }

        // If there is an app state region, start setting up that header.
        for _ in 0..writeable_flash_regions {
            self.hdr_wfr.push(TbfHeaderWriteableFlashRegion {
                base: TbfHeaderTlv {
                    tipe: TbfHeaderTypes::WriteableFlashRegions,
                    length: 8,
                },
                offset: 0,
                size: 0,
            });
        }

        // If at least one RAM of flash address is fixed, include the header.
        if fixed_address_ram.is_some() || fixed_address_flash.is_some() {
            self.hdr_fixed_addresses = Some(TbfHeaderFixedAddresses {
                base: TbfHeaderTlv {
                    tipe: TbfHeaderTypes::FixedAddresses,
                    length: 8,
                },
                start_process_ram: fixed_address_ram.unwrap_or(0xFFFFFFFF),
                start_process_flash: fixed_address_flash.unwrap_or(0xFFFFFFFF),
            });
        }

        if !perms.is_empty() {
            self.hdr_permissions = Some(TbfHeaderPermissions {
                base: TbfHeaderTlv {
                    tipe: TbfHeaderTypes::Permissions,
                    length: (perms.len() * mem::size_of::<TbfHeaderDriverPermission>()) as u16 + 2,
                },
                length: perms.len() as u16,
                perms,
            });
        }

        if storage_ids.0.is_some() || storage_ids.1.is_some() || storage_ids.2.is_some() {
            let mut hdr_persistent = TbfHeaderPersistentAcl {
                base: TbfHeaderTlv {
                    tipe: TbfHeaderTypes::Persistent,
                    length: 4 + 2 + 2,
                },
                write_id: 0,
                read_length: 0,
                read_ids: Vec::new(),
                access_length: 0,
                access_ids: Vec::new(),
            };

            if let Some(write_id) = storage_ids.0 {
                hdr_persistent.write_id = write_id;
            }

            if let Some(read_ids) = storage_ids.1 {
                hdr_persistent.base.length += (read_ids.len() as u16) * 4;
                hdr_persistent.read_length = read_ids.len() as u16;
                hdr_persistent.read_ids = read_ids;
            }

            if let Some(access_ids) = storage_ids.2 {
                hdr_persistent.base.length += (access_ids.len() as u16) * 4;
                hdr_persistent.access_length = access_ids.len() as u16;
                hdr_persistent.access_ids = access_ids;
            }

            self.hdr_persistent = Some(hdr_persistent);
        }

        // If the kernel version is set, we have to include the header.
        if let Some((kernel_major, kernel_minor)) = kernel_version {
            self.hdr_kernel_version = Some(TbfHeaderKernelVersion {
                base: TbfHeaderTlv {
                    tipe: TbfHeaderTypes::KernelVersion,
                    length: 4,
                },
                major: kernel_major,
                minor: kernel_minor,
            });
        }

        // Return the length by generating the header and seeing how long it is.
        self.generate()
            .expect("No header was generated")
            .get_ref()
            .len()
    }

    /// Update the header with the correct protected_size. protected_size should
    /// not include the size of the header itself (as defined in the Main TLV
    /// element type).
    pub fn set_protected_size(&mut self, protected_size: u32) {
        if let Some(ref mut main) = self.hdr_main {
            main.protected_size = protected_size;
        }
        if let Some(ref mut program) = self.hdr_program {
            program.protected_size = protected_size;
        }
    }

    /// Update the header with correct size for the entire app binary.
    pub fn set_total_size(&mut self, total_size: u32) {
        self.hdr_base.total_size = total_size;
    }

    /// Update the header with the correct offset for the _start function.
    pub fn set_init_fn_offset(&mut self, init_fn_offset: u32) {
        if let Some(ref mut main) = self.hdr_main {
            main.init_fn_offset = init_fn_offset;
        }
        if let Some(ref mut program) = self.hdr_program {
            program.init_fn_offset = init_fn_offset;
        }
    }

    /// Update the header with the correct minimum RAM size
    pub fn set_minimum_ram_size(&mut self, minimum_ram_size: u32) {
        if let Some(ref mut main) = self.hdr_main {
            main.minimum_ram_size = minimum_ram_size;
        }
        if let Some(ref mut program) = self.hdr_program {
            program.minimum_ram_size = minimum_ram_size;
        }
    }

    /// Update the header with the correct binary end offset. If we did
    /// not have a Program Header, insert one. Note that this is the standard
    /// way to insert a Program Header.
    pub fn set_binary_end_offset(&mut self, binary_end_offset: u32) {
        self.hdr_program = Some(TbfHeaderProgram {
            base: TbfHeaderTlv {
                tipe: TbfHeaderTypes::Program,
                length: (mem::size_of::<TbfHeaderProgram>() - mem::size_of::<TbfHeaderTlv>())
                    as u16,
            },
            init_fn_offset: self.hdr_main.map_or(0, |main| main.init_fn_offset),
            protected_size: self.hdr_main.map_or(0, |main| main.protected_size),
            minimum_ram_size: self.hdr_main.map_or(0, |main| main.minimum_ram_size),
            binary_end_offset,
            app_version: 0,
        });
    }

    pub fn binary_end_offset(&self) -> u32 {
        self.hdr_program
            .map_or(self.hdr_base.total_size, |program| {
                program.binary_end_offset
            })
    }

    pub fn set_app_version(&mut self, version: u32) {
        if let Some(ref mut program) = self.hdr_program {
            program.app_version = version;
        }
    }

    /// Update the header with appstate values if appropriate.
    pub fn set_writeable_flash_region_values(&mut self, offset: u32, size: u32) {
        for wfr in &mut self.hdr_wfr {
            // Find first unused WFR header and use that.
            if wfr.size == 0 {
                wfr.offset = offset;
                wfr.size = size;
                break;
            }
        }
    }

    /// Create the header in binary form.
    pub fn generate(&self) -> io::Result<io::Cursor<vec::Vec<u8>>> {
        let mut header_buf = io::Cursor::new(Vec::new());

        // Write all bytes to an in-memory file for the header.
        header_buf.write_all(unsafe { as_byte_slice(&self.hdr_base) })?;
        header_buf.write_all(unsafe { as_byte_slice(&self.hdr_main) })?;

        if let Some(program) = self.hdr_program {
            header_buf.write_all(unsafe { as_byte_slice(&program) })?;
        }

        if !self.package_name.is_empty() {
            header_buf.write_all(unsafe { as_byte_slice(&self.hdr_pkg_name_tlv) })?;
            header_buf.write_all(self.package_name.as_ref())?;
            do_pad(&mut header_buf, self.package_name_pad)?;
        }

        // Put all writeable flash region header elements in.
        for wfr in &self.hdr_wfr {
            header_buf.write_all(unsafe { as_byte_slice(wfr) })?;
        }

        // If there are fixed addresses, include that TLV.
        if self.hdr_fixed_addresses.is_some() {
            header_buf.write_all(unsafe { as_byte_slice(&self.hdr_fixed_addresses) })?;
        }

        // If there are permissions, include that TLV
        if let Some(hdr_permissions) = &self.hdr_permissions {
            header_buf.write_all(unsafe { as_byte_slice(&hdr_permissions.base) })?;
            header_buf.write_all(unsafe { as_byte_slice(&hdr_permissions.length) })?;
            for perm in &hdr_permissions.perms {
                header_buf.write_all(unsafe { as_byte_slice(perm) })?;
            }
            do_pad(&mut header_buf, 2)?;
        }

        // If there are storage IDs, include that TLV
        if let Some(hdr_persistent) = &self.hdr_persistent {
            header_buf.write_all(unsafe { as_byte_slice(&hdr_persistent.base) })?;
            header_buf.write_all(unsafe { as_byte_slice(&hdr_persistent.write_id) })?;
            header_buf.write_all(unsafe { as_byte_slice(&hdr_persistent.read_length) })?;
            for read_id in &hdr_persistent.read_ids {
                header_buf.write_all(unsafe { as_byte_slice(read_id) })?;
            }
            header_buf.write_all(unsafe { as_byte_slice(&hdr_persistent.access_length) })?;
            for access_id in &hdr_persistent.access_ids {
                header_buf.write_all(unsafe { as_byte_slice(access_id) })?;
            }
        }

        // If the kernel version is set, include that TLV
        if self.hdr_kernel_version.is_some() {
            header_buf.write_all(unsafe { as_byte_slice(&self.hdr_kernel_version) })?;
        }

        let current_length = header_buf.get_ref().len();
        do_pad(
            &mut header_buf,
            amount_alignment_needed(current_length as u32, 4) as usize,
        )?;

        self.inject_checksum(header_buf)
    }

    /// Take a TBF header and calculate the checksum. Then insert that checksum
    /// into the actual binary.
    fn inject_checksum(
        &self,
        mut header_buf: io::Cursor<vec::Vec<u8>>,
    ) -> io::Result<io::Cursor<vec::Vec<u8>>> {
        // Start from the beginning and iterate through the buffer as words.
        header_buf.seek(SeekFrom::Start(0))?;
        let mut wordbuf = [0_u8; 4];
        let mut checksum: u32 = 0;
        loop {
            let count = header_buf.read(&mut wordbuf)?;
            // Combine the bytes back into a word, handling if we don't
            // get a full word.
            let mut word = 0;
            for (i, c) in wordbuf.iter().enumerate().take(count) {
                word |= u32::from(*c) << (8 * i);
            }
            checksum ^= word;
            if count != 4 {
                break;
            }
        }

        // Now we need to insert the checksum into the correct position in the
        // header.
        header_buf.seek(io::SeekFrom::Start(12))?;
        wordbuf[0] = (checksum & 0xFF) as u8;
        wordbuf[1] = ((checksum >> 8) & 0xFF) as u8;
        wordbuf[2] = ((checksum >> 16) & 0xFF) as u8;
        wordbuf[3] = ((checksum >> 24) & 0xFF) as u8;
        header_buf.write_all(&wordbuf)?;
        header_buf.seek(io::SeekFrom::Start(0))?;

        Ok(header_buf)
    }
}

impl Default for TbfHeader {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for TbfHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "TBF Header:")?;
        write!(f, "{}", self.hdr_base)?;
        self.hdr_main.map_or(Ok(()), |hdr| write!(f, "{}", hdr))?;
        self.hdr_program
            .map_or(Ok(()), |hdr| write!(f, "{}", hdr))?;

        for wfr in &self.hdr_wfr {
            write!(f, "{}", wfr)?;
        }
        self.hdr_fixed_addresses
            .map_or(Ok(()), |hdr| write!(f, "{}", hdr))?;
        self.hdr_permissions
            .as_ref()
            .map_or(Ok(()), |hdr| write!(f, "{}", hdr))?;
        self.hdr_persistent
            .as_ref()
            .map_or(Ok(()), |hdr| write!(f, "{}", hdr))?;
        self.hdr_kernel_version
            .map_or(Ok(()), |hdr| write!(f, "{}", hdr))?;
        Ok(())
    }
}

/// Takes a value and rounds it up to be aligned % box_size
pub fn align_to(value: u32, box_size: u32) -> u32 {
    value + ((box_size - (value % box_size)) % box_size)
}

/// Takes a value and rounds it down to be aligned % box_size
#[allow(dead_code)]
pub fn align_down(value: u32, box_size: u32) -> u32 {
    value - (value % box_size)
}

/// How much needs to be added to get a value aligned % 4
pub fn amount_alignment_needed(value: u32, box_size: u32) -> u32 {
    align_to(value, box_size) - value
}

pub fn do_pad<W: io::Write>(output: &mut W, length: usize) -> io::Result<()> {
    let mut pad = length;
    let zero_buf = [0_u8; 512];
    while pad > 0 {
        let amount_to_write = cmp::min(zero_buf.len(), pad);
        pad -= output.write(&zero_buf[..amount_to_write])?;
    }
    Ok(())
}

/// Get a raw buffer for the memory of type `T`.
///
/// # Safety
///
/// This must only be used to write the object to the output file.
pub unsafe fn as_byte_slice<T: Copy>(input: &T) -> &[u8] {
    slice::from_raw_parts(input as *const T as *const u8, mem::size_of::<T>())
}

#[cfg(test)]
mod test {
    use super::{align_to, amount_alignment_needed};

    #[test]
    pub fn keeps_aligned_values() {
        let result = align_to(8, 4);

        assert_eq!(result, 8);
    }

    #[test]
    pub fn aligns_to_the_next_box() {
        let result = align_to(3, 4);

        assert_eq!(result, 4);
    }

    #[test]
    pub fn aligns_to_the_next_box_with_another_box_size() {
        let result = align_to(7, 8);

        assert_eq!(result, 8);
    }

    #[test]
    pub fn computes_distance_to_lattice_point() {
        let result = amount_alignment_needed(7, 8);

        assert_eq!(result, 1);
    }
}
