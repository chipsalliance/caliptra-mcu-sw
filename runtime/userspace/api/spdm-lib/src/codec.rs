// Licensed under the Apache-2.0 license

use zerocopy::{FromBytes, Immutable, IntoBytes};

pub type CodecResult<T> = Result<T, CodecError>;

#[derive(Debug, PartialEq)]
pub enum CodecError {
    BufferTooSmall,
    ReadError,
    WriteError,
    BufferOverflow,
    BufferUnderflow,
}

pub trait Codec {
    fn encode(&self, buffer: &mut MessageBuf) -> CodecResult<usize>;
    fn decode(data: &mut MessageBuf) -> CodecResult<Self>
    where
        Self: Sized;
}

#[derive(PartialEq)]
pub enum DataKind {
    Header,
    Payload,
}

pub trait CommonCodec: FromBytes + IntoBytes + Immutable {
    const DATA_KIND: DataKind = DataKind::Payload;
}

impl<T> Codec for T
where
    T: CommonCodec,
{
    fn encode(&self, buffer: &mut MessageBuf) -> CodecResult<usize> {
        let len = core::mem::size_of::<T>();
        match T::DATA_KIND {
            DataKind::Header => {
                let len = core::mem::size_of::<Self>();
                buffer.push_data(len)?;
                let header = buffer.data_mut(len)?;
                self.write_to(header).map_err(|_| CodecError::WriteError)?;
                buffer.push_head(len)?;
            }
            DataKind::Payload => {
                buffer.put_data(len)?;

                if buffer.data_len() < len {
                    Err(CodecError::BufferTooSmall)?;
                }
                let payload = buffer.data_mut(len)?;
                self.write_to(payload).map_err(|_| CodecError::WriteError)?;
                buffer.pull_data(len)?;
            }
        }

        Ok(len)
    }

    fn decode(buffer: &mut MessageBuf) -> CodecResult<T> {
        let len = core::mem::size_of::<T>();
        if buffer.data_len() < len {
            Err(CodecError::BufferTooSmall)?;
        }
        let data = buffer.data(len)?;
        let data = T::read_from_bytes(data).map_err(|_| CodecError::ReadError)?;
        buffer.pull_data(len)?;

        if Self::DATA_KIND == DataKind::Header {
            buffer.pull_head(len)?;
        }
        Ok(data)
    }
}

pub fn encode_u8_slice(data: &[u8], buffer: &mut MessageBuf) -> CodecResult<usize> {
    let len = data.len();
    buffer.put_data(len)?;
    let buf = buffer.data_mut(len)?;
    buf.copy_from_slice(data);
    buffer.pull_data(len)?;
    Ok(len)
}

pub fn decode_u8_slice(buffer: &mut MessageBuf, data: &mut [u8]) -> CodecResult<()> {
    let len = data.len();
    if buffer.data_len() < len {
        Err(CodecError::BufferTooSmall)?;
    }
    let src_data = buffer.data(len)?;
    data.copy_from_slice(src_data);
    buffer.pull_data(len)?;
    Ok(())
}

impl Codec for u8 {
    fn encode(&self, buffer: &mut MessageBuf) -> CodecResult<usize> {
        let bytes = [*self];
        encode_u8_slice(&bytes, buffer)
    }
    fn decode(buffer: &mut MessageBuf) -> CodecResult<Self> {
        let mut value = [0u8; 1];
        decode_u8_slice(buffer, &mut value)?;
        Ok(value[0])
    }
}

impl Codec for u16 {
    fn encode(&self, buffer: &mut MessageBuf) -> CodecResult<usize> {
        let bytes = self.to_le_bytes();
        encode_u8_slice(&bytes, buffer)
    }
    fn decode(buffer: &mut MessageBuf) -> CodecResult<Self> {
        let mut value = [0u8; 2];
        decode_u8_slice(buffer, &mut value)?;
        Ok(u16::from_le_bytes(value))
    }
}

impl Codec for u32 {
    fn encode(&self, buffer: &mut MessageBuf) -> CodecResult<usize> {
        let bytes = self.to_le_bytes();
        encode_u8_slice(&bytes, buffer)
    }
    fn decode(buffer: &mut MessageBuf) -> CodecResult<Self> {
        let mut value = [0u8; 4];
        decode_u8_slice(buffer, &mut value)?;
        Ok(u32::from_le_bytes(value))
    }
}

impl<'a> From<&'a mut [u8]> for MessageBuf<'a> {
    fn from(buffer: &'a mut [u8]) -> Self {
        let tail = buffer.len();
        Self {
            buffer,
            head: 0,
            data: 0,
            tail,
        }
    }
}

// Generic message buffer for message encoding and decoding
#[derive(Debug)]
pub struct MessageBuf<'a> {
    /// Message buffer
    buffer: &'a mut [u8],
    /// Headspace of the message buffer
    head: usize,
    /// Start of the payload
    data: usize,
    /// End of the payload. Represents the length of the message
    tail: usize,
}

impl<'a> MessageBuf<'a> {
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self {
            buffer,
            head: 0,
            tail: 0,
            data: 0,
        }
    }

    /// Reserve space for the header at the start of the message buffer
    pub fn reserve(&mut self, header_len: usize) -> CodecResult<()> {
        if self.tail + header_len > self.buffer.len() {
            Err(CodecError::BufferTooSmall)?;
        }
        self.data += header_len;
        self.tail += header_len;
        self.head += header_len;
        Ok(())
    }

    /// Gives the length of the data in the message buffer
    pub fn data_len(&self) -> usize {
        self.tail - self.data
    }

    /// Advances the tail pointer by specified number of bytes.
    /// This is used to add data to the end of the message buffer
    /// example usage
    pub fn put_data(&mut self, len: usize) -> CodecResult<()> {
        if self.tail + len > self.buffer.len() {
            Err(CodecError::BufferTooSmall)?;
        }
        self.tail += len;
        Ok(())
    }

    /// Decrements the data pointer (pushes up) by the specified number of bytes.
    /// This is used to add data to the start of the message buffer (eg. headers)
    /// This also increases the length of the message by the specified number of bytes
    /// example usage
    pub fn push_data(&mut self, len: usize) -> CodecResult<()> {
        if self.data < len {
            Err(CodecError::BufferUnderflow)?;
        }
        self.data -= len;
        Ok(())
    }

    /// Increments the data pointer (pulls down) by specified number of bytes.
    /// This is used to remove data (eg. headers) at the front of the message
    /// after processing it.
    pub fn pull_data(&mut self, len: usize) -> CodecResult<()> {
        if self.data + len > self.tail {
            Err(CodecError::BufferOverflow)?;
        }
        self.data += len;
        Ok(())
    }

    /// Decrements the head pointer (pushes up) by specified number of bytes.
    /// This is used to increase the length of the message buffer
    pub fn push_head(&mut self, len: usize) -> CodecResult<()> {
        if self.head < len {
            Err(CodecError::BufferUnderflow)?;
        }
        self.head -= len;
        Ok(())
    }

    /// Increments the head pointer (pulls down) by specified number of bytes.
    /// This is used to set the headspace of the message buffer while processing
    pub fn pull_head(&mut self, len: usize) -> CodecResult<()> {
        if self.head + len > self.tail || self.head + len > self.data {
            Err(CodecError::BufferOverflow)?;
        }
        self.head += len;
        Ok(())
    }

    // /// Resize buffer length to the specified number of bytes from the data pointer.
    // /// If the new length is greater than the current, the tail is increased (if within capacity).
    // /// If the new length is less, the tail is reduced.
    // pub fn resize(&mut self, len: usize) -> CodecResult<()> {
    //     let new_tail = len;
    //     if new_tail > self.buffer.len() {
    //         Err(CodecError::BufferOverflow)?;
    //     }
    //     if new_tail < self.data {
    //         Err(CodecError::BufferUnderflow)?;
    //     }
    //     self.tail = new_tail;
    //     Ok(())
    // }

    /// Trim buffer length to the specified number of bytes from the data pointer (reduce size).
    /// Equivalent to skb_trim in sk_buff.
    pub fn trim(&mut self, len: usize) -> CodecResult<()> {
        if len < self.data {
            return Err(CodecError::BufferUnderflow);
        }
        if len > self.tail {
            return Err(CodecError::BufferOverflow);
        }
        self.tail = len;
        Ok(())
    }

    /// Expand buffer length by the specified number of bytes from the current tail (increase size).
    /// Equivalent to skb_put in sk_buff.
    pub fn expand(&mut self, len: usize) -> CodecResult<()> {
        let new_tail = self.tail + len;
        if new_tail > self.buffer.len() {
            return Err(CodecError::BufferOverflow);
        }
        self.tail = new_tail;
        Ok(())
    }

    // Returns the data slice in the message buffer of specified length
    pub fn data(&self, len: usize) -> CodecResult<&[u8]> {
        if self.data + len > self.tail {
            Err(CodecError::BufferOverflow)?;
        }
        Ok(&self.buffer[self.data..self.data + len])
    }

    // Returns the mutable data slice in the message buffer of specified length
    pub fn data_mut(&mut self, len: usize) -> CodecResult<&mut [u8]> {
        if self.data + len > self.tail {
            Err(CodecError::BufferOverflow)?;
        }
        Ok(&mut self.buffer[self.data..self.data + len])
    }

    pub fn tailroom(&self) -> usize {
        self.buffer.len().saturating_sub(self.tail)
    }

    /// Returns the total capacity of the message buffer
    pub fn capacity(&self) -> usize {
        self.buffer.len()
    }

    /// Resets the entire message buffer
    pub fn reset(&mut self) {
        self.buffer.fill(0);
        self.data = 0;
        self.tail = 0;
        self.head = 0;
    }

    /// Reset the payload portion of the message buffer
    /// This keeps the headspace intact
    pub fn reset_payload(&mut self) {
        self.tail = self.head;
        self.data = self.head;
    }

    /// Returns the message buffer up to the specified data offset.
    pub fn message_slice(&self, offset: usize) -> CodecResult<&[u8]> {
        if offset < self.head {
            Err(CodecError::BufferUnderflow)?;
        }
        if offset > self.tail {
            Err(CodecError::BufferOverflow)?;
        }
        Ok(&self.buffer[self.head..offset])
    }

    /// For debug purposes
    pub fn total_message(&self) -> &[u8] {
        &self.buffer[..self.tail]
    }

    pub fn data_offset(&self) -> usize {
        self.data
    }

    pub fn msg_len(&self) -> usize {
        self.tail
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    #[test]
    fn test_message_buf() {
        let mut rng = rand::thread_rng();
        let mut buffer = [0u8; 64];

        let msg_len = 48;
        let mut msg = [0u8; 48];
        rng.fill(&mut msg[..msg_len]);

        // header 1 of size 1 byte
        // eg. SPDM message type
        let header1_len = 1;
        let header1 = [0x05];
        msg[0] = 0x05;

        // header 2 of size 2 bytes
        let header2_len = 2;
        let header2 = [0x10, 0x84];

        // header 3 of size 4 bytes
        let header3_len = 4;
        let header3 = [0x0A, 0x0B, 0x0C, 0x0D];

        msg[..1].copy_from_slice(&header1[..]);
        msg[1..3].copy_from_slice(&header2[..]);
        msg[3..7].copy_from_slice(&header3[..]);

        // buffer[..msg_len].copy_from_slice(&msg[..]);

        // Initialize buffer
        let mut msg_buf = MessageBuf::new(&mut buffer);
        assert_eq!(msg_buf.capacity(), 64);
        assert_eq!(msg_buf.tail, 0);
        assert_eq!(msg_buf.data_len(), 0);

        // Set the len to full message length
        assert!(msg_buf.put_data(64).is_ok());
        assert_eq!(msg_buf.tail, 64);
        assert_eq!(msg_buf.data_len(), 64);
        assert_eq!(msg_buf.data(64).unwrap(), &[0; 64]);

        // Receive message of length 48
        let data = msg_buf.data_mut(msg_len);
        assert!(data.is_ok());
        data.unwrap().copy_from_slice(&msg[..msg_len]);
        assert!(msg_buf.trim(msg_len).is_ok());
        assert_eq!(msg_buf.tail, 48);
        assert_eq!(msg_buf.data_len(), 48);
        assert_eq!(msg_buf.data(48).unwrap(), &msg[..msg_len]);

        // Process incoming message

        // Read header 1, process and remove it
        let hdr1 = msg_buf.data(header1_len);
        assert!(hdr1.is_ok());
        assert_eq!(hdr1.unwrap(), &header1[..]);
        assert!(msg_buf.pull_data(header1_len).is_ok());
        assert!(msg_buf.tail == 48);
        assert!(msg_buf.data_len() == 47);
        assert_eq!(msg_buf.data(47).unwrap(), &msg[1..]);

        // Read header 2, process and remove it
        let hdr2 = msg_buf.data(header2_len);
        assert!(hdr2.is_ok());
        assert_eq!(hdr2.unwrap(), &header2[..]);
        assert!(msg_buf.pull_data(2).is_ok());
        assert!(msg_buf.tail == 48);
        assert!(msg_buf.data_len() == 45);
        assert_eq!(msg_buf.data(45).unwrap(), &msg[3..]);

        // Read header 3, process and remove it
        let hdr3 = msg_buf.data(header3_len);
        assert!(hdr3.is_ok());
        assert_eq!(hdr3.unwrap(), &header3[..]);
        assert!(msg_buf.pull_data(4).is_ok());
        assert!(msg_buf.tail == 48);
        assert!(msg_buf.data_len() == 41);
        assert_eq!(msg_buf.data(41).unwrap(), &msg[7..]);

        // Reset the buffer for response
        msg_buf.reset();
        assert!(msg_buf.tail == 0);
        assert!(msg_buf.data_len() == 0);
        assert!(msg_buf.capacity() == 64);
        assert!(msg_buf.msg_len() == 0);

        // Reserve space for header 1,2 and 3
        assert!(msg_buf
            .reserve(header1_len + header2_len + header3_len)
            .is_ok());
        assert!(msg_buf.tail == header1_len + header2_len + header3_len);
        assert!(msg_buf.data_len() == 0);
        assert!(msg_buf.msg_len() == header1_len + header2_len + header3_len);
        assert!(msg_buf.capacity() == 64);

        // Add response payload
        let payload_len = msg_len - header1_len - header2_len - header3_len;
        let payload_offset = header1_len + header2_len + header3_len;

        assert!(msg_buf.put_data(payload_len).is_ok());
        assert!(msg_buf.tail == msg_len);
        assert!(msg_buf.data_len() == payload_len);
        assert!(msg_buf.msg_len() == msg_len);
        assert!(msg_buf.capacity() == 64);

        let data = msg_buf.data_mut(payload_len);
        assert!(data.is_ok());
        data.unwrap().copy_from_slice(&msg[payload_offset..]);

        // Add header3
        assert!(msg_buf.push_data(header3_len).is_ok());
        let rsp_header3 = msg_buf.data_mut(header3_len);
        assert!(rsp_header3.is_ok());
        let rsp_header3 = rsp_header3.unwrap();
        assert!(rsp_header3.len() == header3_len);
        rsp_header3.copy_from_slice(&header3[..]);
        assert!(msg_buf.tail == msg_len);
        assert!(msg_buf.data_len() == payload_len + header3_len);
        assert!(msg_buf.msg_len() == msg_len);

        // Add header2
        assert!(msg_buf.push_data(header2_len).is_ok());
        let rsp_header2 = msg_buf.data_mut(header2_len);
        assert!(rsp_header2.is_ok());
        let rsp_header2 = rsp_header2.unwrap();
        assert!(rsp_header2.len() == header2_len);
        rsp_header2.copy_from_slice(&header2[..]);
        assert!(msg_buf.tail == msg_len);
        assert!(msg_buf.data_len() == payload_len + header2_len + header3_len);
        assert!(msg_buf.msg_len() == msg_len);

        // Add header3
        assert!(msg_buf.push_data(header1_len).is_ok());
        let rsp_header1 = msg_buf.data_mut(header1_len);
        assert!(rsp_header1.is_ok());
        let rsp_header1 = rsp_header1.unwrap();
        assert!(rsp_header1.len() == header1_len);
        rsp_header1.copy_from_slice(&header1[..]);
        assert!(msg_buf.tail == msg_len);
        assert!(msg_buf.data_len() == payload_len + header1_len + header2_len + header3_len);
        assert!(msg_buf.msg_len() == msg_len);

        // Compare the response with the original message
        assert_eq!(msg_buf.data(msg_len).unwrap(), &msg[..]);
    }

    #[test]
    fn test_trim_and_expand_edge_cases() {
        let mut buffer = [0u8; 16];
        let mut msg_buf = MessageBuf::new(&mut buffer);
        // Put some data and move data ptr ahead
        assert!(msg_buf.put_data(8).is_ok());
        assert!(msg_buf.pull_data(8).is_ok());
        assert!(msg_buf.data == 8);
        // Expand to full capacity
        assert!(msg_buf.expand(8).is_ok());
        assert_eq!(msg_buf.tail, 16);
        // Try to expand beyond capacity
        assert!(msg_buf.expand(1).is_err());
        // Trim to valid size
        assert!(msg_buf.trim(10).is_ok());
        assert_eq!(msg_buf.tail, 10);
        // Try to trim below data pointer
        assert!(msg_buf.trim(0).is_err());
        // Try to trim above tail
        assert!(msg_buf.trim(20).is_err());
    }
}
