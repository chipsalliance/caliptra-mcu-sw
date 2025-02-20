// Licensed under the Apache-2.0 license

use core::ops::{Deref, DerefMut};
use thiserror_no_std::Error;

// #[derive(Debug)]
// pub struct MessageBuf<'a> {
//     buffer: &'a mut [u8],
//     transport_hdr_offset: usize,
//     cur_offset: usize,
//     msg_len: usize,
//     max_buf_len: usize,
// }

// impl<'a> Deref for MessageBuf<'a> {
//     type Target = [u8];

//     fn deref(&self) -> &Self::Target {
//         &self.buffer[self.cur_offset..]
//     }
// }

// impl<'a> DerefMut for MessageBuf<'a> {
//     fn deref_mut(&mut self) -> &mut Self::Target {
//         &mut self.buffer[self.cur_offset..]
//     }
// }

// impl<'a> MessageBuf<'a> {
//     pub fn new(buffer: &'a mut [u8], msg_len: usize) -> Option<Self> {
//         let buf_len = buffer.len();

//         if msg_len > buf_len {
//             return None;
//         }

//         Some(Self {
//             buffer,
//             transport_hdr_offset: 0,
//             cur_offset: 0,
//             msg_len,
//             max_buf_len: buf_len,
//         })
//     }

//     pub fn reset(&mut self) {
//         self.cur_offset = 0;
//         self.msg_len = 0;
//         self.buffer.fill(0);
//     }

//     pub fn push_offset(&mut self, offset: usize) -> CodecResult<()> {
//         if self.cur_offset + offset >= self.msg_len {
//             Err(CodecError::BufferOverflow)
//         } else {
//             self.cur_offset += offset;
//             Ok(())
//         }
//     }

//     pub fn set_transport_hdr_offset(&mut self, offset: usize) {
//         self.transport_hdr_offset = offset;
//     }

//     // pub fn pull_offset(&mut self, offset: usize) -> CodecResult<usize> {
//     //     if self.cur_offset < offset {
//     //         Err(CodecError::BufferOverflow)
//     //     } else {
//     //         self.cur_offset -= offset;
//     //         Ok(offset)
//     //     }
//     // }

//     pub fn set_msg_len(&mut self, msg_len: usize) {
//         self.msg_len = msg_len;
//     }

//     pub fn cur_offset(&self) -> usize {
//         self.cur_offset
//     }

//     pub fn reset_offset(&mut self) {
//         self.cur_offset = 0;
//     }

//     pub fn len(&self) -> usize {
//         self.msg_len - self.cur_offset
//     }
// }

pub type CodecResult<T> = Result<T, CodecError>;

#[derive(Error, Debug)]
pub enum CodecError {
    #[error("Buffer too small")]
    BufferTooSmall,
    #[error("Read from buffer bytes error")]
    ReadError,
    #[error("Buffer overflow")]
    BufferOverflow,
    #[error("Buffer underflow")]
    BufferUnderflow,
}

pub trait Codec {
    fn encode(&self, buffer: &mut MessageBuf) -> CodecResult<usize>;
    fn decode(data: &mut MessageBuf) -> CodecResult<Self>
    where
        Self: Sized;
}

// pub trait Codec {
//     fn encode(&self, buffer: &mut [u8]) -> CodecResult<usize>;
//     fn decode(data: &[u8]) -> CodecResult<Self>
//     where
//         Self: Sized;
// }

#[derive(Debug)]
pub struct MessageBuf<'a> {
    // Message buffer
    buffer: &'a mut [u8],
    // Start of the message
    head: usize,
    // Start of the payload
    data: usize,
    // End of the payload
    // Represents the length of the message
    tail: usize,
}

impl<'a> Deref for MessageBuf<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.buffer[self.data..self.tail]
    }
}

impl<'a> DerefMut for MessageBuf<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buffer[self.data..self.tail]
    }
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
            return Err(CodecError::BufferTooSmall);
        }
        self.data += header_len;
        self.tail += header_len;
        Ok(())
    }

    /// Gives the length of the data in the message buffer
    pub fn data_len(&self) -> usize {
        self.tail - self.data
    }

    /// Increments the length of the data in the message buffer
    pub fn put_data(&mut self, len: usize) -> CodecResult<()> {
        if self.tail + len > self.buffer.len() {
            return Err(CodecError::BufferTooSmall);
        }
        self.tail += len;
        Ok(())
    }

    /// Makes space at the front of the message buffer for the header
    /// example usage
    /// ```
    /// msg_buf.push_data(8)?;
    /// let header = msg_buf.data();
    /// header.copy_from_slice(&[1; 8]);
    /// ```
    pub fn push_data(&mut self, len: usize) -> CodecResult<()> {
        if self.data < len {
            return Err(CodecError::BufferUnderflow);
        }
        self.data -= len;
        Ok(())
    }

    /// Removes data at the front of the message buffer to make
    /// space for the header
    /// example usage
    /// ```
    ///
    /// msg_buf.pull(8)?;
    /// let header = msg_buf.data();
    /// ```
    pub fn pull_data(&mut self, len: usize) -> CodecResult<()> {
        if self.data + len > self.tail {
            return Err(CodecError::BufferOverflow);
        }
        self.data += len;
        Ok(())
    }

    /// Remove data from the end of the buffer
    pub fn trim(&mut self, len: usize) -> CodecResult<()> {
        if self.tail < len {
            return Err(CodecError::BufferUnderflow);
        }
        self.tail = self.data + len;

        Ok(())
    }

    pub fn data(&self, len: usize) -> CodecResult<&[u8]> {
        if self.data + len > self.tail {
            return Err(CodecError::BufferOverflow);
        }
        Ok(&self.buffer[self.data..self.data + len])
    }

    pub fn total_data(&self) -> &[u8] {
        &self.buffer[self.data..self.tail]
    }

    pub fn data_mut(&mut self, len: usize) -> CodecResult<&mut [u8]> {
        if self.data + len > self.tail {
            return Err(CodecError::BufferOverflow);
        }
        Ok(&mut self.buffer[self.data..self.data + len])
    }

    // pub fn data_at(&self, offset: usize, len: usize) -> CodecResult<&[u8]> {
    //     if self.data + offset + len > self.tail {
    //         return Err(CodecError::BufferOverflow);
    //     }
    //     Ok(&self.buffer[self.data + offset..self.data + offset + len])
    // }

    pub fn data_at_mut(&mut self, offset: usize, len: usize) -> CodecResult<&mut [u8]> {
        if self.data + offset + len > self.tail {
            return Err(CodecError::BufferOverflow);
        }
        Ok(&mut self.buffer[self.data + offset..self.data + offset + len])
    }

    pub fn len(&self) -> usize {
        self.tail
    }

    pub fn capacity(&self) -> usize {
        self.buffer.len()
    }

    // // length of the data
    // pub fn len(&self) -> usize {
    //     self.tail - self.head
    // }

    // // Increase the length of the data by len bytes
    // pub fn put(&mut self, len: usize) -> CodecResult<()> {
    //     if self.tail + len > self.buffer.len() {
    //         return Err(CodecError::BufferTooSmall);
    //     }
    //     self.tail += len;
    //     Ok(())
    // }

    // // Resize the data to len bytes
    // pub fn resize(&mut self, len: usize) -> CodecResult<()> {
    //     if len > self.buffer.len() {
    //         return Err(CodecError::BufferTooSmall);
    //     }
    //     self.tail = len;
    //     Ok(())
    // }

    // // reserve len bytes of headroom in the buffer
    // // this will move the head and tail pointers.
    // // Use this to reserve space for the header while encoding
    // // payload
    // pub fn reserve(&mut self, len: usize) -> CodecResult<()> {
    //     if self.head + len > self.buffer.len() {
    //         return Err(CodecError::BufferTooSmall);
    //     }
    //     self.head += len;
    //     self.tail += len;
    //     Ok(())
    // }

    // // push data offset by len bytes
    // pub fn push(&mut self, len: usize) -> CodecResult<()> {
    //     if self.head + len > self.tail {
    //         return Err(CodecError::BufferOverflow);
    //     }
    //     self.head += len;
    //     Ok(())
    // }

    // // pull the data offset by len bytes
    // // this will move the head pointer back by len bytes
    // pub fn pull(&mut self, len: usize) -> CodecResult<()> {
    //     if self.head < len {
    //         return Err(CodecError::BufferUnderflow);
    //     }
    //     self.head -= len;
    //     Ok(())
    // }

    // // read data from the head
    // pub fn data(&self, len: usize) -> CodecResult<&[u8]> {
    //     if self.head + len <= self.tail {
    //         Ok(&self.buffer[self.head..self.head + len])
    //     } else {
    //         Err(CodecError::BufferOverflow)
    //     }
    // }

    // pub fn data_offset(&self) -> usize {
    //     self.head
    // }

    // pub fn data_mut(&mut self, len: usize) -> CodecResult<&mut [u8]> {
    //     if self.head + len <= self.tail {
    //         Ok(&mut self.buffer[self.head..self.head + len])
    //     } else {
    //         Err(CodecError::BufferOverflow)
    //     }
    // }

    pub fn reset(&mut self) {
        self.buffer.fill(0);
        self.head = 0;
        self.data = 0;
        self.tail = 0;
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
        let header1_len = 1;
        let header1 = [0x05];
        msg[0] = 0x05; // eg. SPDM message type
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
        assert_eq!(msg_buf.head, 0);
        assert_eq!(msg_buf.tail, 0);
        assert_eq!(msg_buf.data_len(), 0);

        // Set the len to full message length
        assert!(msg_buf.put_data(64).is_ok());
        assert_eq!(msg_buf.head, 0);
        assert_eq!(msg_buf.tail, 64);
        assert_eq!(msg_buf.data_len(), 64);
        assert_eq!(msg_buf.data(64).unwrap(), &[0; 64]);

        // Receive message of length 48
        let data = msg_buf.data_mut(msg_len);
        assert!(data.is_ok());
        data.unwrap().copy_from_slice(&msg[..msg_len]);
        assert!(msg_buf.trim(msg_len).is_ok());
        assert_eq!(msg_buf.head, 0);
        assert_eq!(msg_buf.tail, 48);
        assert_eq!(msg_buf.data_len(), 48);
        assert_eq!(msg_buf.data(48).unwrap(), &msg[..msg_len]);

        // Process incoming message

        // Read header 1, process and remove it
        let hdr1 = msg_buf.data(header1_len);
        assert!(hdr1.is_ok());
        assert_eq!(hdr1.unwrap(), &header1[..]);
        assert!(msg_buf.pull_data(header1_len).is_ok());
        assert!(msg_buf.head == 0);
        assert!(msg_buf.tail == 48);
        assert!(msg_buf.data_len() == 47);
        assert_eq!(msg_buf.data(47).unwrap(), &msg[1..]);

        // Read header 2, process and remove it
        let hdr2 = msg_buf.data(header2_len);
        assert!(hdr2.is_ok());
        assert_eq!(hdr2.unwrap(), &header2[..]);
        assert!(msg_buf.pull_data(2).is_ok());
        assert!(msg_buf.head == 0);
        assert!(msg_buf.tail == 48);
        assert!(msg_buf.data_len() == 45);
        assert_eq!(msg_buf.data(45).unwrap(), &msg[3..]);

        // Read header 3, process and remove it
        let hdr3 = msg_buf.data(header3_len);
        assert!(hdr3.is_ok());
        assert_eq!(hdr3.unwrap(), &header3[..]);
        assert!(msg_buf.pull_data(4).is_ok());
        assert!(msg_buf.head == 0);
        assert!(msg_buf.tail == 48);
        assert!(msg_buf.data_len() == 41);
        assert_eq!(msg_buf.data(41).unwrap(), &msg[7..]);

        // Reset the buffer for response
        msg_buf.reset();
        assert!(msg_buf.head == 0);
        assert!(msg_buf.tail == 0);
        assert!(msg_buf.data_len() == 0);
        assert!(msg_buf.capacity() == 64);
        assert!(msg_buf.len() == 0);

        // Reserve space for header 1,2 and 3
        assert!(msg_buf
            .reserve(header1_len + header2_len + header3_len)
            .is_ok());
        assert!(msg_buf.head == 0);
        assert!(msg_buf.tail == header1_len + header2_len + header3_len);
        assert!(msg_buf.data_len() == 0);
        assert!(msg_buf.len() == header1_len + header2_len + header3_len);
        assert!(msg_buf.capacity() == 64);

        // Add response payload
        let payload_len = msg_len - header1_len - header2_len - header3_len;
        let payload_offset = header1_len + header2_len + header3_len;

        assert!(msg_buf.put_data(payload_len).is_ok());
        assert!(msg_buf.head == 0);
        assert!(msg_buf.tail == msg_len);
        assert!(msg_buf.data_len() == payload_len);
        assert!(msg_buf.len() == msg_len);
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
        assert!(msg_buf.head == 0);
        assert!(msg_buf.tail == msg_len);
        assert!(msg_buf.data_len() == payload_len + header3_len);
        assert!(msg_buf.len() == msg_len);

        // Add header2
        assert!(msg_buf.push_data(header2_len).is_ok());
        let rsp_header2 = msg_buf.data_mut(header2_len);
        assert!(rsp_header2.is_ok());
        let rsp_header2 = rsp_header2.unwrap();
        assert!(rsp_header2.len() == header2_len);
        rsp_header2.copy_from_slice(&header2[..]);
        assert!(msg_buf.head == 0);
        assert!(msg_buf.tail == msg_len);
        assert!(msg_buf.data_len() == payload_len + header2_len + header3_len);
        assert!(msg_buf.len() == msg_len);

        // Add header3
        assert!(msg_buf.push_data(header1_len).is_ok());
        let rsp_header1 = msg_buf.data_mut(header1_len);
        assert!(rsp_header1.is_ok());
        let rsp_header1 = rsp_header1.unwrap();
        assert!(rsp_header1.len() == header1_len);
        rsp_header1.copy_from_slice(&header1[..]);
        assert!(msg_buf.head == 0);
        assert!(msg_buf.tail == msg_len);
        assert!(msg_buf.data_len() == payload_len + header1_len + header2_len + header3_len);
        assert!(msg_buf.len() == msg_len);

        // Compare the response with the original message
        assert_eq!(msg_buf.data(msg_len).unwrap(), &msg[..]);
    }
}
