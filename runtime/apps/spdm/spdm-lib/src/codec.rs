pub struct MessageBuf<'a> {
    buffer: &'a mut [u8],
    head: usize,
    tail: usize,
}

impl<'a> MessageBuf<'a> {
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Some(Self {
            buffer,
            head: 0,
            tail: 0,
        })
    }

    // pub fn push(&mut self, len: usize) -> &mut [u8] {
    //     assert!(self.tail + len <= self.buffer.len());

    //     let start = self.tail;
    //     self.tail += len;
    //     &mut self.buffer[start..self.tail]
    // }

    pub fn put(&mut self, len: usize) {
        assert!(self.tail + len <= self.buffer.len());

        let start = self.tail;
        self.tail += len;
    }

    pub fn data(&self, range: core::ops::Range<usize>) -> &[u8] {
        &self.buffer[range]
    }

    pub fn data_mut(&mut self, range: core::ops::Range<usize>) -> &mut [u8] {
        assert!(range.len() <= self.tail);
        assert!(range.start <= self.tail);
        assert!(range.end <= self.tail);
        &mut self.buffer[range]
    }

    /// Resets the buffer to its initial state
    /// and fills it with zeros.
    /// This is useful for reusing the buffer
    /// without needing to allocate a new one.
    /// It is important to note that this method
    /// will overwrite any existing data in the buffer.
    /// # Examples
    /// ```
    /// let mut buffer = [0u8; 64];
    /// let mut msg_buf = MessageBuf::new(&mut buffer);
    /// msg_buf.reset();
    /// ```
    pub fn reset(&mut self) {
        self.buffer.fill(0);
        self.head = 0;
        self.tail = 0;
    }

    /// Reserves space at the beginning.
    /// This method does not allocate new memory,
    /// but rather ensures that the buffer has enough space
    pub fn reserve(&mut self, len: usize) {
        assert!(self.head + len <= self.buffer.len());
        self.head += len;
    }

    pub fn capacity(&self) -> usize {
        self.buffer.len()
    }

    pub fn len(&self) -> usize {
        self.tail - self.head
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_buf() {
        let mut buffer = [0u8; 64];
        let mut msg_buf = MessageBuf::new(&mut buffer).unwrap();
        assert_eq!(msg_buf.capacity(), 64);
        assert_eq!(msg_buf.head, 0);
        assert_eq!(msg_buf.tail, 0);
        msg_buf.put(60);
        assert_eq!(msg_buf.head, 0);
        assert_eq!(msg_buf.tail, 60);
        assert_eq!(msg_buf.data(0..64).len(), 64);
        msg_buf.reserve(32);
        assert_eq!(msg_buf.head, 32);
        assert_eq!(msg_buf.tail, 64);
        assert_eq!(msg_buf.len(), 32);

        assert_eq!(msg_buf.tail, 1);
        msg_buf.put(1);
        msg_buf.push_offset(1).unwrap();
        assert_eq!(msg_buf.head, 2);
    }
}
