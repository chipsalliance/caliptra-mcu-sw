use crate::fake::SyscallDriver;
use crate::{DriverInfo, DriverShareRef};
use crate::{RoAllowBuffer, RwAllowBuffer};
use libtock_platform::{CommandReturn, ErrorCode};
use std::cell::RefCell;

pub struct FakeMailboxDriver {
    // Last command received by the driver
    last_command: RefCell<Option<u32>>,

    // Readied responses upon receipt of mailbox commands
    ready_responses: RefCell<Vec<CommandResponse>>,

    // Reference to the RW buffer that will be used to store the response
    // and will be passed to the kernel in the upcall
    response_buffer: RefCell<RwAllowBuffer>,

    // RO Buffer
    read_only_buffer: RefCell<RoAllowBuffer>,

    // Last received command arguments
    last_ro_input: RefCell<Vec<u8>>,

    // Reference to the driver on registration with the kernel
    share_ref: DriverShareRef,
}
#[derive(Clone)]
pub struct CommandResponse {
    pub command_id: u32,
    pub response_data: Vec<u8>,
}

impl Default for FakeMailboxDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeMailboxDriver {
    pub fn new() -> Self {
        Self {
            last_command: RefCell::new(None),
            ready_responses: RefCell::new(Vec::new()),
            response_buffer: Default::default(),
            share_ref: Default::default(),
            read_only_buffer: Default::default(),
            last_ro_input: Default::default(),
        }
    }

    pub fn add_ready_response(&self, command_id: u32, response_data: &[u8]) {
        self.ready_responses.borrow_mut().push(CommandResponse {
            command_id,
            response_data: response_data.to_vec(),
        });
    }

    pub fn get_last_command(&self) -> Option<u32> {
        *self.last_command.borrow()
    }

    pub fn get_last_ro_input(&self) -> Option<Vec<u8>> {
        Some(self.last_ro_input.borrow().clone())
    }
}

impl SyscallDriver for FakeMailboxDriver {
    fn info(&self) -> DriverInfo {
        DriverInfo::new(MAILBOX_DRIVER_NUM)
            .upcall_count(mailbox_subscribe::NUM_SUBSCRIPTIONS as u32)
    }

    fn register(&self, share_ref: DriverShareRef) {
        self.share_ref.replace(share_ref);
    }
    fn command(&self, command_num: u32, arg0: u32, _: u32) -> CommandReturn {
        if command_num != mailbox_cmd::EXECUTE_COMMAND {
            return crate::command_return::failure(ErrorCode::Fail);
        }

        // Simulate storing the executed command
        *self.last_command.borrow_mut() = Some(arg0);

        // Pop a response
        let response = self.ready_responses.borrow()[0].clone();
        if response.command_id == arg0 {
            let response_length = response.response_data.len();
            self.response_buffer.borrow_mut()[..response_length]
                .copy_from_slice(&response.response_data[..response_length]);

            self.share_ref
                .schedule_upcall(
                    mailbox_subscribe::COMMAND_DONE,
                    (response_length as u32, 0, 0),
                )
                .expect("Unable to schedule upcall {}");

            // Remove first element from the ready responses
            self.ready_responses.borrow_mut().remove(0);
            crate::command_return::success()
        } else {
            // Unexpected command
            crate::command_return::failure(ErrorCode::Fail)
        }
    }

    fn allow_readwrite(
        &self,
        allow_num: u32,
        buffer: RwAllowBuffer,
    ) -> Result<RwAllowBuffer, (RwAllowBuffer, ErrorCode)> {
        if allow_num == mailbox_rw_buffer::RESPONSE {
            Ok(self.response_buffer.replace(buffer))
        } else {
            Err((buffer, ErrorCode::Invalid))
        }
    }

    fn allow_readonly(
        &self,
        allow_num: u32,
        buffer: RoAllowBuffer,
    ) -> Result<RoAllowBuffer, (RoAllowBuffer, ErrorCode)> {
        if allow_num == mailbox_ro_buffer::INPUT {
            if !buffer.is_empty() {
                // Buffer len of 0 means unallow, we don't want to replace the buffer in that case
                self.last_ro_input.replace(buffer.to_vec());
            }

            Ok(self.read_only_buffer.replace(buffer))
        } else {
            Err((buffer, ErrorCode::Invalid))
        }
    }
}

// Mailbox constants
pub const MAILBOX_DRIVER_NUM: u32 = 0x8000_0009;

mod mailbox_cmd {
    pub const EXECUTE_COMMAND: u32 = 1;
}

mod mailbox_ro_buffer {
    pub const INPUT: u32 = 0;
}

mod mailbox_rw_buffer {
    pub const RESPONSE: u32 = 0;
}

mod mailbox_subscribe {
    /// Subscription ID for the `COMMAND_DONE` event.
    pub const COMMAND_DONE: u32 = 0;

    pub const NUM_SUBSCRIPTIONS: usize = 1;
}
