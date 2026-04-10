use retour::static_detour;
use std::ffi::CString;
use winapi::shared::ntdef::{HANDLE, INT, PSTR};

use crate::{BINDER_COLLECTION, hook, lock_or_log, pstr_to_string, utils::logging::debug_print};

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

        debug_print(&format!(
            "[CriIoOpen] redirecting {} -> {}",
            path_str,
            full_path.display()
        ));

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
    unsafe {
        hook!(FnCriIoOpen, Cri_Io_Open, CRI_IO_OPEN_ADDR, hook_impl);
    }

    Ok(())
}
