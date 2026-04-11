use retour::static_detour;
use std::ffi::CString;
use winapi::shared::ntdef::{HANDLE, INT, PSTR};

use crate::{
    BINDER_COLLECTION, cri_hooks::CriError, debug_print, hook, lock_or_log, pstr_to_string,
};

const CRI_BINDER_FIND_ADDR: usize = 0x140461268;

static_detour! {
    static Cri_Binder_Find: unsafe extern "system" fn(HANDLE, PSTR, *mut CriFsBinderFileInfo, *mut INT) -> CriError;
}

type FnCriBinderFind =
    unsafe extern "system" fn(HANDLE, PSTR, *mut CriFsBinderFileInfo, *mut INT) -> CriError;

#[repr(C)]
pub struct CriFsBinderFileInfo {
    pub file_handle: HANDLE,
    pub path: PSTR,
    pub offset: i64,
    pub compressed_size: i64,
    pub decompressed_size: i64,
    pub binder_id: HANDLE,
    pub reserved: u32,
}

pub fn hook_impl(
    binder_handle: HANDLE,
    path: PSTR,
    file_info: *mut CriFsBinderFileInfo,
    exist: *mut INT,
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

        let mut new_exist: INT = 0;

        let result = Cri_Binder_Find.call(
            binder_handle,
            relative_path.as_ptr() as PSTR,
            file_info,
            &mut new_exist,
        );

        if !exist.is_null() {
            *exist = new_exist;
        }

        if !file_info.is_null() {
            (*file_info).path = absolute_ptr as PSTR;
        }

        result
    }
}

pub fn register_hook() -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        hook!(
            FnCriBinderFind,
            Cri_Binder_Find,
            CRI_BINDER_FIND_ADDR,
            hook_impl
        );
    }

    Ok(())
}
