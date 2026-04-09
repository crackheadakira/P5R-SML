use retour::static_detour;
use winapi::shared::ntdef::{HANDLE, INT, PSTR};

use crate::{hook, pstr_to_string, utils::logging::debug_print};

const CRI_IO_EXISTS_ADDR: usize = 0x140473384;

static_detour! {
    static Cri_Io_Exists: unsafe extern "system" fn(PSTR, *mut INT) -> HANDLE;
}

type FnCriIoExists = unsafe extern "system" fn(PSTR, *mut INT) -> HANDLE;

fn hook_impl(string_ptr: PSTR, result: *mut INT) -> HANDLE {
    let response_handle = unsafe { Cri_Io_Exists.call(string_ptr, result) };

    debug_print(&format!(
        "[CriIoExists] string_ptr: {}, result: {result:?}",
        unsafe { pstr_to_string(string_ptr) }
    ));

    response_handle
}

pub fn register_hook() -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        hook!(FnCriIoExists, Cri_Io_Exists, CRI_IO_EXISTS_ADDR, hook_impl);
    }

    Ok(())
}
