use retour::static_detour;
use std::ffi::CString;
use std::os::windows::raw::HANDLE;

use crate::{
    BINDER_COLLECTION, debug_print, hook,
    utils::{lock_or_log, pstr_to_string},
};

static_detour! {
    static Cri_Io_Exists: unsafe extern "system" fn(*mut u8, *mut i32) -> HANDLE;
}

type FnCriIoExists = unsafe extern "system" fn(*mut u8, *mut i32) -> HANDLE;

pub fn cri_io_exists_hook(string_ptr: *mut u8, result: *mut i32) -> HANDLE {
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

        return unsafe { Cri_Io_Exists.call(temp_cstr.as_ptr() as *mut u8, result) };
    }

    unsafe { Cri_Io_Exists.call(string_ptr, result) }
}

pub fn register_io_exists_hook(memory: &'static [u8]) -> Result<(), Box<dyn std::error::Error>> {
    let pattern = "48 89 5C 24 18 57 48 81 EC 70 08";

    unsafe {
        let signature = crate::scanner::Signature::parse(pattern)?;

        if let Some(address) = crate::scanner::scan_memory(memory, &signature) {
            let addr_usize = address as usize;

            debug_print!("[SCANNER] Found CriIoExists at {:#x}", addr_usize);

            hook!(FnCriIoExists, Cri_Io_Exists, addr_usize, cri_io_exists_hook);
        } else {
            return Err("Could not find pattern for CriIoExists".into());
        }
    }

    Ok(())
}
