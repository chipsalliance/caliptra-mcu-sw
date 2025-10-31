//! Session Management
//!
//! Handles device sessions, connection state, and resource management

#![no_std]

use caliptra_osal::time::{Instant, Duration, sleep};
use caliptra_transport::{Transport, TransportError};
use caliptra_commands::packing::{pack_command_request, unpack_command_response, MAX_COMMAND_PACKET_SIZE};
use caliptra_command_types::{CommandRequest, CommandResponse};

/// Session error enumeration
#[derive(Debug, Clone)]
pub enum SessionError {
    /// Session not found
    SessionNotFound(u32),
    
    /// Invalid session state
    InvalidState {
        current: SessionState,
        expected: SessionState,
    },
    
    /// Transport layer error
    TransportError(&'static str),
    
    /// OSAL error
    OsalError(&'static str),
    
    /// Configuration error
    ConfigurationError(&'static str),
    
    /// Authentication error
    AuthenticationError(&'static str),
    
    /// Resource allocation error
    ResourceError(&'static str),
    
    /// Serialization/deserialization error
    SerializationError(&'static str),
    
    /// Maximum retries exceeded
    MaxRetriesExceeded,
    
    /// Internal error
    InternalError(&'static str),
    
    /// Custom error
    Custom(&'static str),
}

/// Session result type
pub type SessionResult<T> = Result<T, SessionError>;

/// Session state enumeration
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Disconnected = 0,
    Connecting = 1,
    Connected = 2,
    Authenticated = 3,
    Error = 4,
}

/// Session configuration
#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub connection_timeout_ms: u32,
    pub command_timeout_ms: u32,
    pub max_retries: u8,
    pub keepalive_interval_ms: u32,
    pub auto_reconnect: bool,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            connection_timeout_ms: 5000,
            command_timeout_ms: 10000,
            max_retries: 3,
            keepalive_interval_ms: 30000,
            auto_reconnect: true,
        }
    }
}

/// Session statistics
#[derive(Debug, Clone, Default)]
pub struct SessionStatistics {
    pub commands_sent: u64,
    pub commands_succeeded: u64,
    pub commands_failed: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub reconnect_count: u32,
    pub last_error_count: u32,
}

/// Session property values
#[derive(Debug, Clone)]
pub enum SessionProperty {
    U32(u32),
    U64(u64),
    Bool(bool),
}

/// Device session context
pub struct CaliptraSession<T: Transport> {
    /// Session ID for tracking
    pub session_id: u32,
    
    /// Current session state
    pub state: SessionState,
    
    /// Transport interface
    pub transport: Option<T>,
    
    /// Session configuration
    pub config: SessionConfig,
    
    /// Session start time
    pub start_time: Instant,
    
    /// Last activity timestamp
    pub last_activity: Instant,
    
    /// Error state information
    pub last_error: Option<SessionError>,
    
    /// Statistics
    pub stats: SessionStatistics,
}

impl<T: Transport> CaliptraSession<T> {
    /// Create a new session with transport
    pub fn new(session_id: u32, transport: T) -> SessionResult<Self> {
        let now = Instant::now();
        
        Ok(Self {
            session_id,
            state: SessionState::Disconnected,
            transport: Some(transport),
            config: SessionConfig::default(),
            start_time: now,
            last_activity: now,
            last_error: None,
            stats: SessionStatistics::default(),
        })
    }
    
    /// Create session with custom configuration
    pub fn with_config(
        session_id: u32,
        transport: T,
        config: SessionConfig,
    ) -> SessionResult<Self> {
        let mut session = Self::new(session_id, transport)?;
        session.config = config;
        Ok(session)
    }
    
    /// Connect to the device
    pub fn connect(&mut self) -> SessionResult<()> {
        if self.state != SessionState::Disconnected {
            return Err(SessionError::InvalidState {
                current: self.state,
                expected: SessionState::Disconnected,
            });
        }
        
        self.state = SessionState::Connecting;
        
        // Connect through transport
        if let Some(transport) = &mut self.transport {
            transport.connect()
                .map_err(|_| SessionError::TransportError("Connection failed"))?;
        } else {
            return Err(SessionError::ConfigurationError("No transport configured"));
        }
            
        self.state = SessionState::Connected;
        self.update_activity()?;
        
        // Perform device identification/handshake
        self.perform_handshake()?;
        
        Ok(())
    }
    
    /// Disconnect from device
    pub fn disconnect(&mut self) -> SessionResult<()> {
        if self.state == SessionState::Disconnected {
            return Ok(());
        }
        
        // Disconnect through transport
        if let Some(transport) = &mut self.transport {
            if let Err(_) = transport.disconnect() {
                self.last_error = Some(SessionError::TransportError("Disconnect failed"));
            }
        }
        
        self.state = SessionState::Disconnected;
        Ok(())
    }
    
    /// Check if session is connected and ready
    pub fn is_ready(&self) -> bool {
        matches!(self.state, SessionState::Connected | SessionState::Authenticated)
    }
    
    /// Update last activity timestamp
    pub fn update_activity(&mut self) -> SessionResult<()> {
        self.last_activity = Instant::now();
        Ok(())
    }
    
    /// Execute a command through the session transport
    pub fn execute_command_raw(&mut self, request_data: &[u8]) -> SessionResult<usize> {
        if !self.is_ready() {
            return Err(SessionError::InvalidState {
                current: self.state,
                expected: SessionState::Connected,
            });
        }
        
        // Update activity
        self.update_activity()?;
        
        // Get transport reference
        let transport = self.transport.as_mut()
            .ok_or(SessionError::ConfigurationError("No transport configured"))?;
            
        // Send request through transport
        transport.send(request_data)
            .map_err(|_| SessionError::TransportError("Send failed"))?;
        
        // Create response buffer
        let mut response_buffer = [0u8; MAX_COMMAND_PACKET_SIZE];
        
        // Receive response through transport
        let received_len = transport.receive(&mut response_buffer)
            .map_err(|_| SessionError::TransportError("Receive failed"))?;
            
        // Update statistics
        self.stats.commands_sent += 1;
        self.stats.bytes_sent += request_data.len() as u64;
        self.stats.bytes_received += received_len as u64;
        
        Ok(received_len)
    }
    
    /// Execute a command through the session transport and return response data
    pub fn execute_command_raw_with_response(&mut self, request_data: &[u8], response_buffer: &mut [u8]) -> SessionResult<usize> {
        if !self.is_ready() {
            return Err(SessionError::InvalidState {
                current: self.state,
                expected: SessionState::Connected,
            });
        }
        
        // Update activity
        self.update_activity()?;
        
        // Get transport reference
        let transport = self.transport.as_mut()
            .ok_or(SessionError::ConfigurationError("No transport configured"))?;
            
        // Send request through transport
        transport.send(request_data)
            .map_err(|_| SessionError::TransportError("Send failed"))?;
        
        // Receive response through transport directly into provided buffer
        let received_len = transport.receive(response_buffer)
            .map_err(|_| SessionError::TransportError("Receive failed"))?;
            
        // Update statistics
        self.stats.commands_sent += 1;
        self.stats.bytes_sent += request_data.len() as u64;
        self.stats.bytes_received += received_len as u64;
        
        Ok(received_len)
    }
    
    /// Execute a structured command through the session
    pub fn execute_command<Req, Resp>(&mut self, command: &Req) -> SessionResult<Resp>
    where
        Req: CommandRequest,
        Resp: CommandResponse,
    {
        // Prepare request buffer
        let mut request_buffer = [0u8; MAX_COMMAND_PACKET_SIZE];
        
        // Pack the command request
        let request_len = pack_command_request(command, &mut request_buffer)
            .map_err(|_| SessionError::SerializationError("Failed to pack command"))?;
            
        // Prepare separate response buffer
        let mut response_buffer = [0u8; MAX_COMMAND_PACKET_SIZE];
        
        // Execute raw command with response buffer
        let response_len = self.execute_command_raw_with_response(&request_buffer[..request_len], &mut response_buffer)?;
        
        // Get response data
        let response_data = &response_buffer[..response_len];
        
        // Unpack the response
        let response = unpack_command_response::<Resp>(response_data)
            .map_err(|_| SessionError::SerializationError("Failed to unpack response"))?;
            
        Ok(response)
    }
    
    /// Get session info
    pub fn get_info(&self) -> SessionInfo {
        SessionInfo {
            session_id: self.session_id,
            state: self.state,
            transport_name: Some("temp_transport"),
            start_time: self.start_time,
            last_activity: self.last_activity,
            stats: self.stats.clone(),
        }
    }
    
    /// Set session property - not implemented in no_std mode
    pub fn set_property(&mut self, _key: &str, _value: SessionProperty) {
        // Properties not supported in no_std mode
    }
    
    /// Get session property - not implemented in no_std mode
    pub fn get_property(&self, _key: &str) -> Option<&SessionProperty> {
        None
    }
    
    /// Perform device handshake and identification
    fn perform_handshake(&mut self) -> SessionResult<()> {
        // This would typically:
        // 1. Send a device identification command
        // 2. Verify device compatibility
        // 3. Establish secure session if needed
        // 4. Cache device capabilities
        
        // For now, just mark as authenticated
        self.state = SessionState::Authenticated;
        Ok(())
    }
    
    /// Handle session errors and recovery
    pub fn handle_error(&mut self, error: SessionError) -> SessionResult<()> {
        self.last_error = Some(error.clone());
        self.stats.last_error_count += 1;
        
        match error {
            SessionError::TransportError(_) if self.config.auto_reconnect => {
                self.attempt_recovery()
            }
            _ => {
                self.state = SessionState::Error;
                Err(error)
            }
        }
    }
    
    /// Attempt session recovery
    fn attempt_recovery(&mut self) -> SessionResult<()> {
        if self.stats.reconnect_count >= 5 {
            return Err(SessionError::MaxRetriesExceeded);
        }
        
        // Disconnect and reconnect
        let _ = self.disconnect();
        
        // Wait before reconnecting
        sleep(Duration::from_secs(1))
            .map_err(|_| SessionError::OsalError("Sleep failed"))?;
        
        self.stats.reconnect_count += 1;
        self.connect()
    }
}

/// Session information structure  
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub session_id: u32,
    pub state: SessionState,
    pub transport_name: Option<&'static str>,
    pub start_time: Instant,
    pub last_activity: Instant,
    pub stats: SessionStatistics,
}

/// Global session manager for multiple sessions - not available in no_std mode
pub struct SessionManager {
    // Placeholder - not implemented in no_std mode  
}

impl SessionManager {
    /// Create new session manager
    pub fn new() -> Self {
        Self {}
    }
    
    /// Create new session - not implemented in no_std mode
    pub fn create_session(&self) -> SessionResult<u32> {
        Err(SessionError::InternalError("SessionManager not available in no_std mode"))
    }
    
    /// Check if session exists - not implemented in no_std mode
    pub fn has_session(&self, _session_id: u32) -> bool {
        false
    }
    
    /// Remove session by ID - not implemented in no_std mode
    pub fn remove_session(&self, _session_id: u32) -> SessionResult<()> {
        Ok(())
    }
}

// Error conversions
impl From<caliptra_osal::error::OsalError> for SessionError {
    fn from(_error: caliptra_osal::error::OsalError) -> Self {
        SessionError::OsalError("OSAL error")
    }
}