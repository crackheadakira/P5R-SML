use retour::static_detour;
use std::ffi::CString;
use winapi::shared::{
    minwindef::DWORD,
    ntdef::{HANDLE, INT, PSTR},
};

use crate::{
    BINDER_COLLECTION,
    cri_hooks::CriError,
    hook, lock_or_log, pstr_to_string,
    scanner::{parse_pattern, scan_main_module},
    utils::{SafeHandle, logging::debug_print},
};

static_detour! {
    static Cri_Binder_Bind_File: unsafe extern "system" fn(HANDLE, HANDLE, PSTR, HANDLE, INT, *mut DWORD) -> CriError;
}

type FnCriBinderBindFile =
    unsafe extern "system" fn(HANDLE, HANDLE, PSTR, HANDLE, INT, *mut DWORD) -> CriError;

pub fn hook_impl(
    binder_handle: HANDLE,
    src_binder_handle: HANDLE,
    path: PSTR,
    work: HANDLE,
    work_size: INT,
    binder_id: *mut DWORD,
) -> CriError {
    if src_binder_handle.is_null() {
        return unsafe {
            Cri_Binder_Bind_File.call(
                binder_handle,
                src_binder_handle,
                path,
                work,
                work_size,
                binder_id,
            )
        };
    }

    let binder_collection = lock_or_log(&BINDER_COLLECTION, "CriBinderBindFile, src_binder_handle");

    if !binder_collection
        .binder_handles
        .contains(&SafeHandle(src_binder_handle))
    {
        debug_print!("[CriBinderBindFile] Unrecognized src_binder_handle: {src_binder_handle:?}",);
        return unsafe {
            Cri_Binder_Bind_File.call(
                binder_handle,
                src_binder_handle,
                path,
                work,
                work_size,
                binder_id,
            )
        };
    }

    drop(binder_collection);

    let path_str = unsafe { pstr_to_string(path) };

    let redirected_path = {
        let binder_collection =
            lock_or_log(&BINDER_COLLECTION, "CriBinderBindFile, redirected_path");
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

    if let Some(pathbuf) = redirected_path {
        let new_cstr =
            CString::new(pathbuf.to_string_lossy().as_bytes()).expect("CString conversion failed");

        debug_print!(
            "[CriBinderBindFiles] Replacing {path_str} -> {}",
            pathbuf.display()
        );

        return unsafe {
            Cri_Binder_Bind_File.call(
                binder_handle,
                src_binder_handle,
                new_cstr.as_ptr() as PSTR,
                work,
                work_size,
                binder_id,
            )
        };
    }

    unsafe {
        Cri_Binder_Bind_File.call(
            binder_handle,
            src_binder_handle,
            path,
            work,
            work_size,
            binder_id,
        )
    }
}

pub fn register_hook() -> Result<(), Box<dyn std::error::Error>> {
    let pattern =
        "48 83 EC 48 48 8B 44 24 78 48 89 44 24 30 8B 44 24 70 89 44 24 28 4C 89 4C 24 20 41 B9";

    unsafe {
        let parsed = parse_pattern(pattern);

        if let Some(address) = scan_main_module(&parsed) {
            let addr_usize = address as usize;

            debug_print!("[SCANNER] Found CriBinderBindFile at {:#x}", addr_usize);

            hook!(
                FnCriBinderBindFile,
                Cri_Binder_Bind_File,
                addr_usize,
                hook_impl
            );
        } else {
            return Err(format!("Could not find pattern for CriBinderBindFile").into());
        }
    }

    Ok(())
}
