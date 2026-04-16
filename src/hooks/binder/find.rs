use retour::static_detour;
use std::{ffi::CString, os::windows::raw::HANDLE};

use crate::{
    BINDER_COLLECTION, debug_print, hook,
    hooks::CriError,
    utils::{lock_or_log, pstr_to_string},
};

static_detour! {
    static Cri_Binder_Find: unsafe extern "system" fn(HANDLE, *mut u8, *mut CriFsBinderFileInfo, *mut i32) -> CriError;
}

type FnCriBinderFind =
    unsafe extern "system" fn(HANDLE, *mut u8, *mut CriFsBinderFileInfo, *mut i32) -> CriError;

#[repr(C)]
pub struct CriFsBinderFileInfo {
    pub file_handle: HANDLE,
    pub path: *mut u8,
    pub offset: i64,
    pub compressed_size: i64,
    pub decompressed_size: i64,
    pub binder_id: HANDLE,
    pub reserved: u32,
}

pub fn cri_binder_find_hook(
    binder_handle: HANDLE,
    path: *mut u8,
    file_info: *mut CriFsBinderFileInfo,
    exist: *mut i32,
) -> CriError {
    unsafe {
        if path.is_null() {
            return Cri_Binder_Find.call(binder_handle, path, file_info, exist);
        }

        let path_str = pstr_to_string(path);
        debug_print!("[CriBinderFind] path: {path_str}");

        let (relative_path, absolute_ptr) = {
            let binder_collection = lock_or_log(&BINDER_COLLECTION, "CriBinderFind, mod_file_arc");

            let Some(mod_file_arc) = binder_collection.find_mod_file_by_relative_path(&path_str)
            else {
                return Cri_Binder_Find.call(binder_handle, path, file_info, exist);
            };

            let mod_file = match mod_file_arc.lock().ok() {
                Some(v) => v,
                None => {
                    return Cri_Binder_Find.call(binder_handle, path, file_info, exist);
                }
            };

            let temp =
                CString::new(mod_file.relative_path.as_bytes()).expect("CString conversion failed");

            debug_print!(
                "[CriBinderFind] {path_str} -> modded file ({:?})",
                mod_file.absolute_path
            );

            (temp, mod_file.absolute_path_cstr.as_ptr())
        };

        let mut new_exist = 0;

        let result = Cri_Binder_Find.call(
            binder_handle,
            relative_path.as_ptr() as *mut u8,
            file_info,
            &mut new_exist,
        );

        if !exist.is_null() {
            *exist = new_exist;
        }

        if !file_info.is_null() {
            (*file_info).path = absolute_ptr as *mut u8;
        }

        result
    }
}

pub fn register_find_hook(memory: &'static [u8]) -> Result<(), Box<dyn std::error::Error>> {
    let pattern =
        "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 40 49 8B F9 49 8B D8 48";

    unsafe {
        let signature = crate::scanner::Signature::parse(pattern)?;

        if let Some(address) = crate::scanner::scan_memory(memory, &signature) {
            let addr_usize = address as usize;

            debug_print!("[SCANNER] Found CriBinderFind at {:#x}", addr_usize);

            hook!(
                FnCriBinderFind,
                Cri_Binder_Find,
                addr_usize,
                cri_binder_find_hook
            );
        } else {
            return Err("Could not find pattern for CriBinderFind".into());
        }
    }

    Ok(())
}
