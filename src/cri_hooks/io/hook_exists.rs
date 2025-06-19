use retour::static_detour;
use winapi::shared::ntdef::{HANDLE, INT, PSTR};

use crate::{hook, utils::logging::debug_print};

const CRI_IO_EXISTS_ADDR: usize = 0x140473384;

static_detour! {
    static Cri_Io_Exists: unsafe extern "system" fn(PSTR, *mut INT) -> HANDLE;
}

type FnCriIoExists = unsafe extern "system" fn(PSTR, *mut INT) -> HANDLE;

fn hook_impl(string_ptr: PSTR, result: *mut INT) -> HANDLE {
    debug_print("[HOOK] io_exists");
    unsafe { Cri_Io_Exists.call(string_ptr, result) }
}

pub fn register_hook() -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        hook!(FnCriIoExists, Cri_Io_Exists, CRI_IO_EXISTS_ADDR, hook_impl);
    }

    Ok(())
}
