use retour::static_detour;
use std::{ffi::CString, os::windows::raw::HANDLE};

use crate::{
    BINDER_COLLECTION, debug_print, hook,
    hooks::CriError,
    utils::{lock_or_log, pstr_to_string},
    vfs::SafeHandle,
};

static_detour! {
    static Cri_Binder_Bind_Files: unsafe extern "system" fn(HANDLE, HANDLE, *mut u8, HANDLE, i32, *mut u32) -> CriError;
}

type FnCriBinderBindFiles =
    unsafe extern "system" fn(HANDLE, HANDLE, *mut u8, HANDLE, i32, *mut u32) -> CriError;

pub fn cri_binder_bind_files_hook(
    binder_handle: HANDLE,
    src_binder_handle: HANDLE,
    path: *mut u8,
    work: HANDLE,
    work_size: i32,
    binder_id: *mut u32,
) -> CriError {
    let path_str = unsafe { pstr_to_string(path) };

    if src_binder_handle.is_null() {
        return unsafe {
            Cri_Binder_Bind_Files.call(
                binder_handle,
                src_binder_handle,
                path,
                work,
                work_size,
                binder_id,
            )
        };
    }

    let binder_collection =
        lock_or_log(&BINDER_COLLECTION, "CriBinderBindFiles, src_binder_handle");

    if !binder_collection
        .binder_handles
        .contains(&SafeHandle(src_binder_handle))
    {
        debug_print!("[CriBinderBindFiles] Unrecognized src_binder_handle: {src_binder_handle:?}",);
        return unsafe {
            Cri_Binder_Bind_Files.call(
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

    let redirected_path = {
        let binder_collection =
            lock_or_log(&BINDER_COLLECTION, "CriBinderBindFiles, redirected_path");
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
            Cri_Binder_Bind_Files.call(
                binder_handle,
                src_binder_handle,
                new_cstr.as_ptr() as *mut u8,
                work,
                work_size,
                binder_id,
            )
        };
    }

    unsafe {
        Cri_Binder_Bind_Files.call(
            binder_handle,
            src_binder_handle,
            path,
            work,
            work_size,
            binder_id,
        )
    }
}

pub fn register_bind_files_hook(memory: &'static [u8]) -> Result<(), Box<dyn std::error::Error>> {
    let pattern =
        "48 83 EC 48 48 8B 44 24 78 48 89 44 24 30 8B 44 24 70 89 44 24 28 4C 89 4C 24 20 41 83";

    unsafe {
        let signature = crate::scanner::Signature::parse(pattern)?;

        if let Some(address) = crate::scanner::scan_memory(memory, &signature) {
            let addr_usize = address as usize;

            debug_print!("[SCANNER] Found CriBinderBindFiles at {:#x}", addr_usize);

            hook!(
                FnCriBinderBindFiles,
                Cri_Binder_Bind_Files,
                addr_usize,
                cri_binder_bind_files_hook
            );
        } else {
            return Err("Could not find pattern for CriBinderBindFiles".into());
        }
    }

    Ok(())
}
