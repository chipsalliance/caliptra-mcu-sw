//! Command Executor
//!
//! Core command execution engine that handles serialization, transport, and response parsing

use caliptra_command_types::{
    CaliptraCommandId, CommandRequest, CommandResponse, CommandError, CommandResult
};
use caliptra_osal::time::{sleep, Duration};
use caliptra_session::{CaliptraSession, SessionState, SessionError, SessionResult};
use caliptra_transport::Transport;

/// Command execution context
pub struct CommandExecutor<'a, T: Transport> {
    session: &'a mut CaliptraSession<T>,
}

impl<'a, T: Transport> CommandExecutor<'a, T> {
    /// Create new command executor for session
    pub fn new(session: &'a mut CaliptraSession<T>) -> SessionResult<Self> {
        if !session.is_ready() {
            return Err(SessionError::InvalidState {
                current: session.state,
                expected: SessionState::Connected,
            });
        }
        
        Ok(Self { session })
    }
    
    /// Execute a command request and return parsed response
    pub fn execute_command<Req: CommandRequest>(
        &mut self,
        request: &Req,
    ) -> CommandResult<Req::Response> {
        let command_id = Req::COMMAND_ID;
        
        // Update session activity
        self.session.update_activity()
            .map_err(|_e| CommandError::Custom("Failed to update activity"))?;
        
        // Serialize request
        let request_data = self.serialize_request(request)?;
        
        // Execute with retries
        let mut attempt = 0;
        let max_retries = self.session.config.max_retries;
        
        while attempt < max_retries {
            match self.try_execute_command(command_id, &request_data) {
                Ok(response_data) => {
                    // Parse response
                    let response = Req::Response::from_bytes(&response_data)?;
                    
                    // Update statistics
                    self.session.stats.commands_sent += 1;
                    self.session.stats.commands_succeeded += 1;
                    self.session.stats.bytes_sent += request_data.len() as u64;
                    self.session.stats.bytes_received += response_data.len() as u64;
                    
                    return Ok(response);
                }
                Err(CommandError::InvalidResponse) if attempt < max_retries - 1 => {
                    attempt += 1;
                    
                    // Exponential backoff
                    let delay_ms = 100 * (1 << attempt).min(8); // Cap at 800ms
                    let _ = sleep(Duration::new(0, delay_ms * 1_000_000)); // Convert ms to nanoseconds
                    
                    continue;
                }
                Err(e) => {
                    self.session.stats.commands_sent += 1;
                    self.session.stats.commands_failed += 1;
                    
                    // Handle session-level errors
                    if let CommandError::Custom(ref msg) = e {
                        if msg.contains("transport") || msg.contains("connection") {
                            let session_error = SessionError::TransportError(*msg);
                            let _ = self.session.handle_error(session_error);
                        }
                    }
                    
                    return Err(e);
                }
            }
        }
        
        self.session.stats.commands_failed += 1;
        Err(CommandError::InvalidResponse)
    }
    
    /// Serialize command request to bytes using fixed buffer
    fn serialize_request<Req: CommandRequest>(&self, request: &Req) -> CommandResult<&'static [u8]> {
        // For now, use caliptra-commands packing
        use caliptra_commands::packing::{pack_command_request, MAX_COMMAND_PACKET_SIZE};
        
        // Create packet buffer
        static mut PACKET_BUFFER: [u8; MAX_COMMAND_PACKET_SIZE] = [0; MAX_COMMAND_PACKET_SIZE];
        
        // Pack the request
        unsafe {
            let len = pack_command_request(request, &mut PACKET_BUFFER)?;
            Ok(&PACKET_BUFFER[..len])
        }
    }
    
    /// Execute single command attempt
    fn try_execute_command(
        &mut self,
        _command_id: CaliptraCommandId,
        _request_data: &[u8],
    ) -> CommandResult<&'static [u8]> {
        // For now, return a placeholder response until transport is integrated
        if self.session.transport.is_some() {
            // Transport send/receive would happen here
            // For now, return empty response
            static EMPTY_RESPONSE: [u8; 1] = [0];
            Ok(&EMPTY_RESPONSE)
        } else {
            Err(CommandError::Custom("No transport configured"))
        }
    }
    
    /// Get timeout for specific command type
    fn get_command_timeout(&self, command_id: CaliptraCommandId) -> u32 {
        let base_timeout = self.session.config.command_timeout_ms;
        
        // Adjust timeout based on command type
        match command_id as u32 {
            0x2001..=0x201F => base_timeout * 2, // Hash operations may take longer
            0x4001..=0x402F => base_timeout * 3, // Crypto operations are slower
            0x8001..=0x801F => base_timeout * 4, // Fuse operations are critical and slow
            _ => base_timeout,
        }
    }
    
    /// Validate response packet format
    fn validate_response(&self, response_data: &[u8], command_id: CaliptraCommandId) -> CommandResult<()> {
        if response_data.len() < 8 {
            return Err(CommandError::DeserializationError);
        }
        
        // Check response command ID matches request (if protocol includes echo)
        // This is protocol-specific validation
        
        // Check for common error responses
        // This would be based on the actual Caliptra protocol specification
        
        // For now, just check minimum length
        let expected_min_len = match command_id as u32 {
            0x0001..=0x000F => 8,  // Device info responses
            0x1001..=0x101F => 8,  // Certificate responses (variable length)
            0x2001..=0x201F => 8,  // Hash responses
            0x3001..=0x302F => 8,  // Crypto responses
            0x4001..=0x402F => 8,  // Asymmetric crypto responses
            0x7001..=0x701F => 8,  // Debug responses
            0x8001..=0x801F => 8,  // Fuse responses
            _ => 8,
        };
        
        if response_data.len() < expected_min_len {
            return Err(CommandError::DeserializationError);
        }
        
        Ok(())
    }
    
    /// Execute batch of commands atomically - not available in no_std mode
    pub fn execute_batch<Req: CommandRequest>(
        &mut self,
        _requests: &[Req],
    ) -> CommandResult<()> {
        // Batch execution not available in no_std mode
        Err(CommandError::Unsupported)
    }
}

/// Command execution utilities
impl<'a, T: Transport> CommandExecutor<'a, T> {
    /// Check if command is supported by current session/device
    pub fn is_command_supported(&self, _command_id: CaliptraCommandId) -> bool {
        // This would check against device capabilities cached during handshake
        // For now, assume all commands are supported
        true
    }
    
    /// Get estimated execution time for command
    pub fn estimate_execution_time(&self, command_id: CaliptraCommandId) -> u32 {
        match command_id as u32 {
            0x0001..=0x000F => 100,   // Device info - fast
            0x1001..=0x101F => 500,   // Certificates - moderate
            0x2001..=0x201F => 200,   // Hash operations - fast-moderate
            0x3001..=0x302F => 1000,  // Symmetric crypto - moderate-slow
            0x4001..=0x402F => 2000,  // Asymmetric crypto - slow
            0x7001..=0x701F => 300,   // Debug - moderate
            0x8001..=0x801F => 5000,  // Fuse operations - very slow
            _ => 1000,
        }
    }
}