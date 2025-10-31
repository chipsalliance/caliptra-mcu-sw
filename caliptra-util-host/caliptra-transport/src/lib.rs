//! Caliptra Transport Layer
//!
//! Transport abstraction for Caliptra device communication

#![no_std]

/// Transport error enumeration
#[derive(Debug)]
pub enum TransportError {
    IoError(&'static str),
    ConnectionError(&'static str),
    Timeout,
}

/// Transport trait for device communication
pub trait Transport: Send + Sync {
    fn send(&mut self, data: &[u8]) -> Result<(), TransportError>;
    fn receive(&mut self, buffer: &mut [u8]) -> Result<usize, TransportError>;
    fn connect(&mut self) -> Result<(), TransportError>;
    fn disconnect(&mut self) -> Result<(), TransportError>;
}