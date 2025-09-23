// Licensed under the Apache-2.0 license

// CBOR encoding functionality
use super::eat::EatError;

// CBOR encoder with fixed buffer
pub struct CborEncoder<'a> {
    buffer: &'a mut [u8],
    pos: usize,
}

impl<'a> CborEncoder<'a> {
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self { buffer, pos: 0 }
    }

    pub fn len(&self) -> usize {
        self.pos
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.pos == 0
    }

    fn write_byte(&mut self, byte: u8) -> Result<(), EatError> {
        if self.pos >= self.buffer.len() {
            return Err(EatError::BufferTooSmall);
        }
        if let Some(buf_byte) = self.buffer.get_mut(self.pos) {
            *buf_byte = byte;
            self.pos = self.pos.saturating_add(1);
            Ok(())
        } else {
            Err(EatError::BufferTooSmall)
        }
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), EatError> {
        let end_pos = self
            .pos
            .checked_add(bytes.len())
            .ok_or(EatError::BufferTooSmall)?;
        if end_pos > self.buffer.len() {
            return Err(EatError::BufferTooSmall);
        }
        if let Some(buf_slice) = self.buffer.get_mut(self.pos..end_pos) {
            buf_slice.copy_from_slice(bytes);
            self.pos = end_pos;
            Ok(())
        } else {
            Err(EatError::BufferTooSmall)
        }
    }

    // Encode major type + additional info according to CBOR rules
    fn encode_type_value(&mut self, major_type: u8, value: u64) -> Result<(), EatError> {
        let major = major_type << 5;

        if value <= 23 {
            self.write_byte(major | value as u8)?;
        } else if value <= 0xff {
            self.write_byte(major | 24)?;
            self.write_byte(value as u8)?;
        } else if value <= 0xffff {
            self.write_byte(major | 25)?;
            let bytes = (value as u16).to_be_bytes();
            self.write_bytes(&bytes)?;
        } else if value <= 0xffffffff {
            self.write_byte(major | 26)?;
            let bytes = (value as u32).to_be_bytes();
            self.write_bytes(&bytes)?;
        } else {
            self.write_byte(major | 27)?;
            let bytes = value.to_be_bytes();
            self.write_bytes(&bytes)?;
        }
        Ok(())
    }

    // Major type 0: Unsigned integer
    pub fn encode_uint(&mut self, value: u64) -> Result<(), EatError> {
        self.encode_type_value(0, value)
    }

    // Major type 1: Negative integer (-1 - n)
    pub fn encode_nint(&mut self, value: i64) -> Result<(), EatError> {
        if value >= 0 {
            return Err(EatError::InvalidData);
        }
        // Safe arithmetic: for negative value, -1 - value is always positive
        let positive_value = (value.checked_mul(-1).ok_or(EatError::InvalidData)?)
            .checked_sub(1)
            .ok_or(EatError::InvalidData)? as u64;
        self.encode_type_value(1, positive_value)
    }

    // Encode integer (automatically choose positive or negative)
    pub fn encode_int(&mut self, value: i64) -> Result<(), EatError> {
        if value >= 0 {
            self.encode_uint(value as u64)
        } else {
            self.encode_nint(value)
        }
    }

    // Major type 2: Byte string
    pub fn encode_bytes(&mut self, bytes: &[u8]) -> Result<(), EatError> {
        self.encode_type_value(2, bytes.len() as u64)?;
        self.write_bytes(bytes)?;
        Ok(())
    }

    // Major type 3: Text string
    pub fn encode_text(&mut self, text: &str) -> Result<(), EatError> {
        let bytes = text.as_bytes();
        self.encode_type_value(3, bytes.len() as u64)?;
        self.write_bytes(bytes)?;
        Ok(())
    }

    // Major type 4: Array
    pub fn encode_array_header(&mut self, len: u64) -> Result<(), EatError> {
        self.encode_type_value(4, len)
    }

    // Major type 5: Map
    pub fn encode_map_header(&mut self, len: u64) -> Result<(), EatError> {
        self.encode_type_value(5, len)
    }

    // Major type 6: Tag
    pub fn encode_tag(&mut self, tag: u64) -> Result<(), EatError> {
        self.encode_type_value(6, tag)
    }

    // Encode with self-described CBOR tag (55799)
    pub fn encode_self_described_cbor(&mut self) -> Result<(), EatError> {
        self.encode_tag(55799)
    }

    // Encode with CWT tag (61)
    pub fn encode_cwt_tag(&mut self) -> Result<(), EatError> {
        self.encode_tag(61)
    }

    // Encode with COSE_Sign1 tag (18)
    pub fn encode_cose_sign1_tag(&mut self) -> Result<(), EatError> {
        self.encode_tag(18)
    }
}
