use retour::static_detour;
use std::ffi::CString;
use winapi::shared::ntdef::{HANDLE, INT, PSTR};

use crate::{
    BINDER_COLLECTION, hook, lock_or_log, pstr_to_string,
    scanner::{parse_pattern, scan_main_module},
    utils::logging::debug_print,
};

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
    if string_ptr.is_null() {
        return unsafe { Cri_Io_Open.call(string_ptr, file_creation_type, desired_access, result) };
    }

    let path_str = unsafe { pstr_to_string(string_ptr) };

    let new_path = {
        let binder_collection = lock_or_log(&BINDER_COLLECTION, "CriIoOpen, new_path");
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
            "[CriIoOpen] redirecting {path_str} -> {}",
            full_path.display()
        );

        let status = unsafe {
            Cri_Io_Open.call(
                temp_cstr.as_ptr() as PSTR,
                file_creation_type,
                desired_access,
                result,
            )
        };

        return status;
    }

    // No redirect, call original
    unsafe { Cri_Io_Open.call(string_ptr, file_creation_type, desired_access, result) }
}

pub fn register_hook() -> Result<(), Box<dyn std::error::Error>> {
    let pattern =
        "48 8B C4 48 89 58 10 48 89 68 18 48 89 70 20 57 41 54 41 55 41 56 41 57 48 83 EC 50";

    unsafe {
        let parsed = parse_pattern(pattern);

        if let Some(address) = scan_main_module(&parsed) {
            let addr_usize = address as usize;

            debug_print!("[SCANNER] Found CriIoOpen at {:#x}", addr_usize);

            hook!(FnCriIoOpen, Cri_Io_Open, addr_usize, hook_impl);
        } else {
            return Err(format!("Could not find pattern for CriIoOpen").into());
        }
    }

    Ok(())
}
