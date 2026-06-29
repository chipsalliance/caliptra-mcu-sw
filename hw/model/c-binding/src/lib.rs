// Licensed under the Apache-2.0 license

use caliptra_mcu_hw_model::{DefaultHwModel, InitParams, McuHwModel, McuManager};
use caliptra_ureg::{Mmio, MmioMut};
use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_uint};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::slice;

const INVALID_MODEL_ERROR: &[u8] = b"invalid model\0";

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct caliptra_mcu_model {
    _unused: [u8; 0],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct caliptra_mcu_buffer {
    pub data: *const u8,
    pub len: usize,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct caliptra_mcu_model_init_params {
    /// The contents of the Caliptra ROM.
    pub caliptra_rom: caliptra_mcu_buffer,
    /// Caliptra firmware bundle.
    pub caliptra_firmware: caliptra_mcu_buffer,
    /// SoC manifest.
    pub soc_manifest: caliptra_mcu_buffer,
    /// The contents of the MCU ROM.
    pub mcu_rom: caliptra_mcu_buffer,
    /// The contents of the MCU firmware.
    pub mcu_firmware: caliptra_mcu_buffer,
    /// Initial contents of Caliptra DCCM SRAM.
    pub caliptra_dccm: caliptra_mcu_buffer,
    /// Initial contents of Caliptra ICCM SRAM.
    pub caliptra_iccm: caliptra_mcu_buffer,
    /// Optional initial contents of OTP memory. Set data to NULL to use defaults.
    pub otp_memory: caliptra_mcu_buffer,
    /// Optional initial contents of DOT flash. Set data to NULL to use defaults.
    pub dot_flash_initial_contents: caliptra_mcu_buffer,
    /// Optional initial contents of primary flash. Set data to NULL to use defaults.
    pub primary_flash_initial_contents: caliptra_mcu_buffer,
    /// Optional 48-byte vendor public key hash. Set data to NULL to use defaults.
    pub vendor_pk_hash: caliptra_mcu_buffer,
    /// Optional 32-byte Caliptra obfuscation key. Set data to NULL to use defaults.
    pub optional_obf_key: caliptra_mcu_buffer,
    /// Optional I3C TCP port. Set to 0 to disable.
    pub i3c_port: c_uint,
    pub active_mode: bool,
    pub enable_mcu_uart_log: bool,
    pub flash_boot: bool,
    pub force_fuse_owner_pk_hash: bool,
    pub active_i3c1: bool,
    pub use_strap_secrets: bool,
}

pub const CALIPTRA_MCU_MODEL_STATUS_OK: c_int = 0;
pub const CALIPTRA_MCU_MODEL_STATUS_INVALID_ARGUMENT: c_int = -1;
pub const CALIPTRA_MCU_MODEL_STATUS_INIT_FAILED: c_int = -2;
pub const CALIPTRA_MCU_MODEL_STATUS_OPERATION_FAILED: c_int = -3;
pub const CALIPTRA_MCU_MODEL_STATUS_INVALID_OBF_KEY_SIZE: c_int = -4;
pub const CALIPTRA_MCU_MODEL_STATUS_INVALID_VENDOR_PK_HASH_SIZE: c_int = -5;
pub const CALIPTRA_MCU_MODEL_STATUS_PANICKED: c_int = -6;

pub const CALIPTRA_MCU_MODEL_OBF_KEY_SIZE: usize = 32;
pub const CALIPTRA_MCU_MODEL_VENDOR_PK_HASH_SIZE: usize = 48;

struct ModelHandle {
    model: DefaultHwModel,
    response: Vec<u8>,
    scratch: Vec<u8>,
    last_error: CString,
}

impl ModelHandle {
    fn new(model: DefaultHwModel) -> Self {
        Self {
            model,
            response: Vec::new(),
            scratch: Vec::new(),
            last_error: CString::default(),
        }
    }

    fn clear_error(&mut self) {
        self.last_error = CString::default();
    }

    fn set_error(&mut self, msg: impl ToString) {
        self.last_error = string_to_cstring(msg.to_string());
    }
}

fn string_to_cstring(msg: String) -> CString {
    CString::new(msg).unwrap_or_else(|err| {
        let sanitized: Vec<u8> = err.into_vec().into_iter().filter(|b| *b != 0).collect();
        CString::new(sanitized).unwrap()
    })
}

fn catch_status(f: impl FnOnce() -> c_int) -> c_int {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(status) => status,
        Err(_) => CALIPTRA_MCU_MODEL_STATUS_PANICKED,
    }
}

unsafe fn handle_from_ptr<'a>(
    model: *mut caliptra_mcu_model,
) -> Result<&'a mut ModelHandle, c_int> {
    if model.is_null() {
        Err(CALIPTRA_MCU_MODEL_STATUS_INVALID_ARGUMENT)
    } else {
        Ok(&mut *(model as *mut ModelHandle))
    }
}

unsafe fn slice_from_buffer<'a>(buffer: caliptra_mcu_buffer) -> Result<&'a [u8], c_int> {
    if buffer.data.is_null() {
        if buffer.len == 0 {
            Ok(&[])
        } else {
            Err(CALIPTRA_MCU_MODEL_STATUS_INVALID_ARGUMENT)
        }
    } else {
        Ok(slice::from_raw_parts(buffer.data, buffer.len))
    }
}

unsafe fn optional_slice_from_buffer<'a>(
    buffer: caliptra_mcu_buffer,
) -> Result<Option<&'a [u8]>, c_int> {
    if buffer.data.is_null() {
        if buffer.len == 0 {
            Ok(None)
        } else {
            Err(CALIPTRA_MCU_MODEL_STATUS_INVALID_ARGUMENT)
        }
    } else {
        Ok(Some(slice::from_raw_parts(buffer.data, buffer.len)))
    }
}

unsafe fn optional_vec_from_buffer(buffer: caliptra_mcu_buffer) -> Result<Option<Vec<u8>>, c_int> {
    optional_slice_from_buffer(buffer).map(|slice| slice.map(Vec::from))
}

unsafe fn optional_vendor_pk_hash(
    buffer: caliptra_mcu_buffer,
) -> Result<Option<[u8; CALIPTRA_MCU_MODEL_VENDOR_PK_HASH_SIZE]>, c_int> {
    match optional_slice_from_buffer(buffer)? {
        None => Ok(None),
        Some(data) if data.len() == CALIPTRA_MCU_MODEL_VENDOR_PK_HASH_SIZE => {
            let mut hash = [0u8; CALIPTRA_MCU_MODEL_VENDOR_PK_HASH_SIZE];
            hash.copy_from_slice(data);
            Ok(Some(hash))
        }
        Some(_) => Err(CALIPTRA_MCU_MODEL_STATUS_INVALID_VENDOR_PK_HASH_SIZE),
    }
}

unsafe fn obf_key_from_buffer(buffer: caliptra_mcu_buffer) -> Result<Option<[u32; 8]>, c_int> {
    match optional_slice_from_buffer(buffer)? {
        None => Ok(None),
        Some(data) if data.len() == CALIPTRA_MCU_MODEL_OBF_KEY_SIZE => {
            let mut key = [0u32; 8];
            for (word, bytes) in key.iter_mut().zip(data.chunks_exact(4)) {
                *word = u32::from_le_bytes(bytes.try_into().unwrap());
            }
            Ok(Some(key))
        }
        Some(_) => Err(CALIPTRA_MCU_MODEL_STATUS_INVALID_OBF_KEY_SIZE),
    }
}

fn fill_buffer(buffer: *mut caliptra_mcu_buffer, data: &[u8]) {
    if !buffer.is_null() {
        unsafe {
            *buffer = caliptra_mcu_buffer {
                data: if data.is_empty() {
                    ptr::null()
                } else {
                    data.as_ptr()
                },
                len: data.len(),
            };
        }
    }
}

unsafe fn init_impl(
    params: caliptra_mcu_model_init_params,
    model: *mut *mut caliptra_mcu_model,
) -> c_int {
    if model.is_null() {
        return CALIPTRA_MCU_MODEL_STATUS_INVALID_ARGUMENT;
    }

    let caliptra_rom = match slice_from_buffer(params.caliptra_rom) {
        Ok(data) => data,
        Err(status) => return status,
    };
    let caliptra_firmware = match slice_from_buffer(params.caliptra_firmware) {
        Ok(data) => data,
        Err(status) => return status,
    };
    let soc_manifest = match slice_from_buffer(params.soc_manifest) {
        Ok(data) => data,
        Err(status) => return status,
    };
    let mcu_rom = match slice_from_buffer(params.mcu_rom) {
        Ok(data) => data,
        Err(status) => return status,
    };
    let mcu_firmware = match slice_from_buffer(params.mcu_firmware) {
        Ok(data) => data,
        Err(status) => return status,
    };
    let caliptra_dccm = match slice_from_buffer(params.caliptra_dccm) {
        Ok(data) => data,
        Err(status) => return status,
    };
    let caliptra_iccm = match slice_from_buffer(params.caliptra_iccm) {
        Ok(data) => data,
        Err(status) => return status,
    };
    let otp_memory = match optional_slice_from_buffer(params.otp_memory) {
        Ok(data) => data,
        Err(status) => return status,
    };
    let dot_flash_initial_contents =
        match optional_vec_from_buffer(params.dot_flash_initial_contents) {
            Ok(data) => data,
            Err(status) => return status,
        };
    let primary_flash_initial_contents =
        match optional_vec_from_buffer(params.primary_flash_initial_contents) {
            Ok(data) => data,
            Err(status) => return status,
        };
    let vendor_pk_hash = match optional_vendor_pk_hash(params.vendor_pk_hash) {
        Ok(data) => data,
        Err(status) => return status,
    };
    let cptra_obf_key = match obf_key_from_buffer(params.optional_obf_key) {
        Ok(Some(key)) => key,
        Ok(None) => InitParams::default().cptra_obf_key,
        Err(status) => return status,
    };

    let i3c_port = if params.i3c_port == 0 {
        None
    } else {
        Some(params.i3c_port as u16)
    };

    let result = caliptra_mcu_hw_model::new_unbooted(InitParams {
        caliptra_rom,
        caliptra_firmware,
        soc_manifest,
        mcu_rom,
        mcu_firmware,
        caliptra_dccm,
        caliptra_iccm,
        otp_memory,
        dot_flash_initial_contents,
        primary_flash_initial_contents,
        vendor_pk_hash,
        cptra_obf_key,
        i3c_port,
        active_mode: params.active_mode,
        enable_mcu_uart_log: params.enable_mcu_uart_log,
        flash_boot: params.flash_boot,
        force_fuse_owner_pk_hash: params.force_fuse_owner_pk_hash,
        active_i3c1: params.active_i3c1,
        use_strap_secrets: params.use_strap_secrets,
        ..Default::default()
    });

    match result {
        Ok(hw_model) => {
            *model = Box::into_raw(Box::new(ModelHandle::new(hw_model))) as *mut caliptra_mcu_model;
            CALIPTRA_MCU_MODEL_STATUS_OK
        }
        Err(_) => {
            *model = ptr::null_mut();
            CALIPTRA_MCU_MODEL_STATUS_INIT_FAILED
        }
    }
}

/// Create an unbooted MCU hardware model using default Rust InitParams values for
/// all fields not exposed in caliptra_mcu_model_init_params.
///
/// Buffer pointers may be NULL only when len is 0. Optional buffers are disabled
/// by setting data to NULL and len to 0. The returned model must be destroyed by
/// caliptra_mcu_model_destroy().
///
/// # Safety
/// `model` must be non-NULL. Non-NULL input buffers must point to at least `len`
/// bytes for the duration of this call.
#[no_mangle]
pub unsafe extern "C" fn caliptra_mcu_model_init_default(
    params: caliptra_mcu_model_init_params,
    model: *mut *mut caliptra_mcu_model,
) -> c_int {
    catch_status(|| init_impl(params, model))
}

/// # Safety
/// `model` must be either NULL or a pointer returned by caliptra_mcu_model_init_default.
#[no_mangle]
pub unsafe extern "C" fn caliptra_mcu_model_destroy(model: *mut caliptra_mcu_model) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !model.is_null() {
            drop(Box::from_raw(model as *mut ModelHandle));
        }
    }));
}

/// Return a pointer to a NUL-terminated string describing the last operation
/// error for this model. The pointer remains valid until the next API call on the
/// model or until caliptra_mcu_model_destroy().
///
/// # Safety
/// `model` must be NULL or a pointer returned by caliptra_mcu_model_init_default.
#[no_mangle]
pub unsafe extern "C" fn caliptra_mcu_model_last_error(
    model: *mut caliptra_mcu_model,
) -> *const c_char {
    match handle_from_ptr(model) {
        Ok(handle) => handle.last_error.as_ptr(),
        Err(_) => INVALID_MODEL_ERROR.as_ptr() as *const c_char,
    }
}

/// Boot the MCU model to the point where CPU execution can occur.
///
/// # Safety
/// `model` must be a pointer returned by caliptra_mcu_model_init_default.
#[no_mangle]
pub unsafe extern "C" fn caliptra_mcu_model_boot(model: *mut caliptra_mcu_model) -> c_int {
    catch_status(|| match handle_from_ptr(model) {
        Ok(handle) => match handle.model.boot() {
            Ok(()) => {
                handle.clear_error();
                CALIPTRA_MCU_MODEL_STATUS_OK
            }
            Err(err) => {
                handle.set_error(err);
                CALIPTRA_MCU_MODEL_STATUS_OPERATION_FAILED
            }
        },
        Err(status) => status,
    })
}

/// # Safety
/// `model` must be a pointer returned by caliptra_mcu_model_init_default.
#[no_mangle]
pub unsafe extern "C" fn caliptra_mcu_model_step(model: *mut caliptra_mcu_model) -> c_int {
    catch_status(|| match handle_from_ptr(model) {
        Ok(handle) => {
            handle.model.step();
            handle.clear_error();
            CALIPTRA_MCU_MODEL_STATUS_OK
        }
        Err(status) => status,
    })
}

/// # Safety
/// `model` must be a pointer returned by caliptra_mcu_model_init_default.
#[no_mangle]
pub unsafe extern "C" fn caliptra_mcu_model_ready_for_fw(model: *mut caliptra_mcu_model) -> bool {
    catch_unwind(AssertUnwindSafe(|| match handle_from_ptr(model) {
        Ok(handle) => handle.model.ready_for_fw(),
        Err(_) => false,
    }))
    .unwrap_or(false)
}

/// # Safety
/// `model` must be a pointer returned by caliptra_mcu_model_init_default.
#[no_mangle]
pub unsafe extern "C" fn caliptra_mcu_model_cycle_count(model: *mut caliptra_mcu_model) -> u64 {
    catch_unwind(AssertUnwindSafe(|| match handle_from_ptr(model) {
        Ok(handle) => handle.model.cycle_count(),
        Err(_) => 0,
    }))
    .unwrap_or(0)
}

/// # Safety
/// `model` must be a pointer returned by caliptra_mcu_model_init_default.
#[no_mangle]
pub unsafe extern "C" fn caliptra_mcu_model_exit_requested(model: *mut caliptra_mcu_model) -> bool {
    catch_unwind(AssertUnwindSafe(|| match handle_from_ptr(model) {
        Ok(handle) => handle.model.output().exit_requested(),
        Err(_) => false,
    }))
    .unwrap_or(false)
}

/// Return a borrowed view of all UART output captured so far. The data pointer is
/// invalidated by the next API call that mutably accesses the model.
///
/// # Safety
/// `model` must be a pointer returned by caliptra_mcu_model_init_default.
#[no_mangle]
pub unsafe extern "C" fn caliptra_mcu_model_output_peek(
    model: *mut caliptra_mcu_model,
) -> caliptra_mcu_buffer {
    catch_unwind(AssertUnwindSafe(|| match handle_from_ptr(model) {
        Ok(handle) => {
            let output = handle.model.output().peek();
            caliptra_mcu_buffer {
                data: output.as_ptr(),
                len: output.len(),
            }
        }
        Err(_) => caliptra_mcu_buffer {
            data: ptr::null(),
            len: 0,
        },
    }))
    .unwrap_or(caliptra_mcu_buffer {
        data: ptr::null(),
        len: 0,
    })
}

/// Read a 32-bit word from the MCU/Caliptra SoC-visible MMIO address space.
///
/// # Safety
/// `model` and `data` must be non-NULL.
#[no_mangle]
pub unsafe extern "C" fn caliptra_mcu_model_mmio_read_u32(
    model: *mut caliptra_mcu_model,
    addr: c_uint,
    data: *mut c_uint,
) -> c_int {
    catch_status(|| {
        if data.is_null() {
            return CALIPTRA_MCU_MODEL_STATUS_INVALID_ARGUMENT;
        }
        match handle_from_ptr(model) {
            Ok(handle) => {
                let value = {
                    let mut manager = handle.model.mcu_manager();
                    let mmio = manager.mmio_mut();
                    mmio.read_volatile(addr as *const u32)
                };
                *data = value;
                handle.clear_error();
                CALIPTRA_MCU_MODEL_STATUS_OK
            }
            Err(status) => status,
        }
    })
}

/// Write a 32-bit word to the MCU/Caliptra SoC-visible MMIO address space.
///
/// # Safety
/// `model` must be a pointer returned by caliptra_mcu_model_init_default.
#[no_mangle]
pub unsafe extern "C" fn caliptra_mcu_model_mmio_write_u32(
    model: *mut caliptra_mcu_model,
    addr: c_uint,
    data: c_uint,
) -> c_int {
    catch_status(|| match handle_from_ptr(model) {
        Ok(handle) => {
            {
                let mut manager = handle.model.mcu_manager();
                let mmio = manager.mmio_mut();
                mmio.write_volatile(addr as *mut u32, data);
            }
            handle.clear_error();
            CALIPTRA_MCU_MODEL_STATUS_OK
        }
        Err(status) => status,
    })
}

/// Execute an MCU mailbox command and return a borrowed response buffer. If the
/// command completes without response data, `response` is set to { NULL, 0 }.
/// The response data pointer is invalidated by the next mailbox call or destroy.
///
/// # Safety
/// `model` must be valid. `request.data` must be NULL only if `request.len` is 0.
/// `response` may be NULL if the caller only needs the status code.
#[no_mangle]
pub unsafe extern "C" fn caliptra_mcu_model_mailbox_execute(
    model: *mut caliptra_mcu_model,
    cmd: c_uint,
    request: caliptra_mcu_buffer,
    response: *mut caliptra_mcu_buffer,
) -> c_int {
    catch_status(|| {
        let request = match slice_from_buffer(request) {
            Ok(data) => data,
            Err(status) => return status,
        };
        match handle_from_ptr(model) {
            Ok(handle) => match handle.model.mailbox_execute(cmd, request) {
                Ok(Some(data)) => {
                    handle.response = data;
                    fill_buffer(response, &handle.response);
                    handle.clear_error();
                    CALIPTRA_MCU_MODEL_STATUS_OK
                }
                Ok(None) => {
                    handle.response.clear();
                    fill_buffer(response, &[]);
                    handle.clear_error();
                    CALIPTRA_MCU_MODEL_STATUS_OK
                }
                Err(err) => {
                    handle.set_error(err);
                    CALIPTRA_MCU_MODEL_STATUS_OPERATION_FAILED
                }
            },
            Err(status) => status,
        }
    })
}

/// Execute a Caliptra mailbox command through the SoC mailbox and return a
/// borrowed response buffer. If the command completes without response data,
/// `response` is set to { NULL, 0 }. The response data pointer is invalidated by
/// the next mailbox call or destroy.
///
/// # Safety
/// `model` must be valid. `request.data` must be NULL only if `request.len` is 0.
/// `response` may be NULL if the caller only needs the status code.
#[no_mangle]
pub unsafe extern "C" fn caliptra_mcu_model_caliptra_mailbox_execute(
    model: *mut caliptra_mcu_model,
    cmd: c_uint,
    request: caliptra_mcu_buffer,
    response: *mut caliptra_mcu_buffer,
) -> c_int {
    catch_status(|| {
        let request = match slice_from_buffer(request) {
            Ok(data) => data,
            Err(status) => return status,
        };
        match handle_from_ptr(model) {
            Ok(handle) => match handle.model.caliptra_mailbox_execute(cmd, request) {
                Ok(Some(data)) => {
                    handle.response = data;
                    fill_buffer(response, &handle.response);
                    handle.clear_error();
                    CALIPTRA_MCU_MODEL_STATUS_OK
                }
                Ok(None) => {
                    handle.response.clear();
                    fill_buffer(response, &[]);
                    handle.clear_error();
                    CALIPTRA_MCU_MODEL_STATUS_OK
                }
                Err(err) => {
                    handle.set_error(format!("{err:?}"));
                    CALIPTRA_MCU_MODEL_STATUS_OPERATION_FAILED
                }
            },
            Err(status) => status,
        }
    })
}

/// # Safety
/// `model` must be a pointer returned by caliptra_mcu_model_init_default.
#[no_mangle]
pub unsafe extern "C" fn caliptra_mcu_model_mci_flow_status(
    model: *mut caliptra_mcu_model,
) -> c_uint {
    catch_unwind(AssertUnwindSafe(|| match handle_from_ptr(model) {
        Ok(handle) => handle.model.mci_flow_status(),
        Err(_) => 0,
    }))
    .unwrap_or(0)
}

/// # Safety
/// `model` must be a pointer returned by caliptra_mcu_model_init_default.
#[no_mangle]
pub unsafe extern "C" fn caliptra_mcu_model_mci_boot_checkpoint(
    model: *mut caliptra_mcu_model,
) -> c_uint {
    catch_unwind(AssertUnwindSafe(|| match handle_from_ptr(model) {
        Ok(handle) => handle.model.mci_boot_checkpoint() as c_uint,
        Err(_) => 0,
    }))
    .unwrap_or(0)
}

/// # Safety
/// `model` must be a pointer returned by caliptra_mcu_model_init_default.
#[no_mangle]
pub unsafe extern "C" fn caliptra_mcu_model_warm_reset(model: *mut caliptra_mcu_model) -> c_int {
    catch_status(|| match handle_from_ptr(model) {
        Ok(handle) => {
            handle.model.warm_reset();
            handle.clear_error();
            CALIPTRA_MCU_MODEL_STATUS_OK
        }
        Err(status) => status,
    })
}

/// Return a borrowed copy of DOT flash contents. The data pointer is invalidated
/// by the next caliptra_mcu_model_read_dot_flash() call or destroy.
///
/// # Safety
/// `model` must be a pointer returned by caliptra_mcu_model_init_default.
#[no_mangle]
pub unsafe extern "C" fn caliptra_mcu_model_read_dot_flash(
    model: *mut caliptra_mcu_model,
) -> caliptra_mcu_buffer {
    catch_unwind(AssertUnwindSafe(|| match handle_from_ptr(model) {
        Ok(handle) => {
            handle.scratch = handle.model.read_dot_flash();
            caliptra_mcu_buffer {
                data: if handle.scratch.is_empty() {
                    ptr::null()
                } else {
                    handle.scratch.as_ptr()
                },
                len: handle.scratch.len(),
            }
        }
        Err(_) => caliptra_mcu_buffer {
            data: ptr::null(),
            len: 0,
        },
    }))
    .unwrap_or(caliptra_mcu_buffer {
        data: ptr::null(),
        len: 0,
    })
}

/// Replace DOT flash contents with `data`.
///
/// # Safety
/// `model` must be valid. `data.data` must be NULL only if `data.len` is 0.
#[no_mangle]
pub unsafe extern "C" fn caliptra_mcu_model_write_dot_flash(
    model: *mut caliptra_mcu_model,
    data: caliptra_mcu_buffer,
) -> c_int {
    catch_status(|| {
        let data = match slice_from_buffer(data) {
            Ok(data) => data,
            Err(status) => return status,
        };
        match handle_from_ptr(model) {
            Ok(handle) => match handle.model.write_dot_flash(data) {
                Ok(()) => {
                    handle.clear_error();
                    CALIPTRA_MCU_MODEL_STATUS_OK
                }
                Err(err) => {
                    handle.set_error(err);
                    CALIPTRA_MCU_MODEL_STATUS_OPERATION_FAILED
                }
            },
            Err(status) => status,
        }
    })
}

/// Return a borrowed copy of OTP memory contents. The data pointer is invalidated
/// by the next caliptra_mcu_model_read_otp_memory() call or destroy.
///
/// # Safety
/// `model` must be a pointer returned by caliptra_mcu_model_init_default.
#[no_mangle]
pub unsafe extern "C" fn caliptra_mcu_model_read_otp_memory(
    model: *mut caliptra_mcu_model,
) -> caliptra_mcu_buffer {
    catch_unwind(AssertUnwindSafe(|| match handle_from_ptr(model) {
        Ok(handle) => {
            handle.scratch = handle.model.read_otp_memory();
            caliptra_mcu_buffer {
                data: if handle.scratch.is_empty() {
                    ptr::null()
                } else {
                    handle.scratch.as_ptr()
                },
                len: handle.scratch.len(),
            }
        }
        Err(_) => caliptra_mcu_buffer {
            data: ptr::null(),
            len: 0,
        },
    }))
    .unwrap_or(caliptra_mcu_buffer {
        data: ptr::null(),
        len: 0,
    })
}
