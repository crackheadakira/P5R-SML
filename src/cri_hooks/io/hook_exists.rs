use retour::static_detour;
use std::ffi::CString;
use winapi::shared::ntdef::{HANDLE, INT, PSTR};

use crate::{
    BINDER_COLLECTION, hook, lock_or_log, pstr_to_string,
    scanner::{parse_pattern, scan_main_module},
    utils::logging::debug_print,
};

static_detour! {
    static Cri_Io_Exists: unsafe extern "system" fn(PSTR, *mut INT) -> HANDLE;
}

type FnCriIoExists = unsafe extern "system" fn(PSTR, *mut INT) -> HANDLE;

pub fn hook_impl(string_ptr: PSTR, result: *mut INT) -> HANDLE {
    if string_ptr.is_null() {
        return unsafe { Cri_Io_Exists.call(string_ptr, result) };
    }

    let path_str = unsafe { pstr_to_string(string_ptr) };

    let new_path = {
        let binder_collection = lock_or_log(&BINDER_COLLECTION, "CriIoExists, new_path");
        if let Some(mod_file_arc) = binder_collection.find_mod_file_by_relative_path(&path_str) {
            if let Ok(mod_file) = mod_file_arc.lock() {
                Some(mod_file.absolute_path.clone())
            } else {
                None
            }
        } else {
            None
        }
    };

    if let Some(full_path) = new_path {
        let temp_cstr = CString::new(full_path.to_string_lossy().as_bytes())
            .expect("CString conversion failed");

        debug_print!(
            "[CriIoExists] redirecting {path_str} -> {}",
            full_path.display()
        );

        return unsafe { Cri_Io_Exists.call(temp_cstr.as_ptr() as PSTR, result) };
    }

    unsafe { Cri_Io_Exists.call(string_ptr, result) }
}

pub fn register_hook() -> Result<(), Box<dyn std::error::Error>> {
    let pattern = "48 89 5C 24 18 57 48 81 EC 70 08";

    unsafe {
        let parsed = parse_pattern(pattern);

        if let Some(address) = scan_main_module(&parsed) {
            let addr_usize = address as usize;

            debug_print!("[SCANNER] Found CriIoExists at {:#x}", addr_usize);

            hook!(FnCriIoExists, Cri_Io_Exists, addr_usize, hook_impl);
        } else {
            return Err(format!("Could not find pattern for CriIoExists").into());
        }
    }

    Ok(())
}
