use retour::static_detour;
use winapi::shared::ntdef::{HANDLE, INT, PSTR};

use crate::{hook, pstr_to_string, utils::logging::debug_print};

const CRI_IO_OPEN_ADDR: usize = 0x14047357c;

static_detour! {
    static Cri_Io_Open: unsafe extern "system" fn(PSTR, INT, INT, *mut HANDLE) -> HANDLE;
}

type FnCriIoOpen = unsafe extern "system" fn(PSTR, INT, INT, *mut HANDLE) -> HANDLE;

pub fn hook_impl(
    string_ptr: PSTR,
    file_creation_type: INT,
    desired_access: INT,
    result: *mut HANDLE,
) -> HANDLE {
    let status =
        unsafe { Cri_Io_Open.call(string_ptr, file_creation_type, desired_access, result) };

    debug_print(&format!(
        "[CriIoOpen] string_ptr_value {}, file_creation_type: {file_creation_type}, desired_access, {desired_access}, result: {result:?}",
        unsafe { pstr_to_string(string_ptr) }
    ));

    status
}

pub fn register_hook() -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        hook!(FnCriIoOpen, Cri_Io_Open, CRI_IO_OPEN_ADDR, hook_impl);
    }

    Ok(())
}
