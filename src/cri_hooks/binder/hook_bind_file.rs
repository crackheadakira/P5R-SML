use retour::static_detour;
use winapi::shared::{
    minwindef::DWORD,
    ntdef::{HANDLE, INT, NULL, PSTR},
};

use crate::{
    BINDER_COLLECTION, cri_hooks::CriStatus, hook, pstr_to_string, utils::logging::debug_print,
};

const CRI_BINDER_BIND_FILE_ADDR: usize = 0x140460b6c;

static_detour! {
    static Cri_Binder_Bind_File: unsafe extern "system" fn(HANDLE, HANDLE, PSTR, HANDLE, INT, *mut DWORD) -> CriStatus;
}

type FnCriBinderBindFile =
    unsafe extern "system" fn(HANDLE, HANDLE, PSTR, HANDLE, INT, *mut DWORD) -> CriStatus;

pub fn hook_impl(
    binder_handle: HANDLE,
    src_binder_handle: HANDLE,
    path: PSTR,
    work: HANDLE,
    work_size: INT,
    binder_id: *mut DWORD,
) -> CriStatus {
    debug_print(&format!(
        "[HOOK] bind_file, binder_handle {binder_handle:?}, src_binder_handle: {src_binder_handle:?}, path: {path:?}, work: {work:?}, work_size: {work_size}"
    ));

    let requested_path = unsafe { pstr_to_string(path) };

    let binder_collection = BINDER_COLLECTION.lock().expect("Mutex was poisoned");

    if let Some(mod_file_arc) = binder_collection
        .mod_files
        .values()
        .find_map(|mod_file_arc| {
            let mod_file = mod_file_arc.lock().ok()?;
            if mod_file.relative_path.to_string_lossy() == requested_path {
                Some(mod_file_arc.clone())
            } else {
                None
            }
        })
    {
        let mod_file = mod_file_arc.lock().unwrap();

        // If game hasn't allocated buffer (work_size == 0), just return your binder_id:
        if work_size == 0 {
            unsafe {
                *binder_id = mod_file.binder_id;
            }
            debug_print(&format!(
                "[HOOK] bind_file with work_size=0, returning binder_id {} for {requested_path}",
                mod_file.binder_id
            ));
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

        // If game provided buffer, copy your pre-allocated data into it:
        if let (Some(mod_buf_ptr), Some(mod_buf_size)) = (mod_file.work_handle, mod_file.work_size)
        {
            if (mod_buf_size as usize) > (work_size as usize) {
                debug_print(&format!(
                    "[HOOK] Buffer too small: mod_buf_size {mod_buf_size} > work_size {work_size}",
                ));
                return CriStatus::Failure;
            }

            if work.is_null() {
                debug_print("[HOOK] bind_file called with null work buffer");
                return CriStatus::Failure;
            }

            unsafe {
                std::ptr::copy_nonoverlapping(
                    mod_buf_ptr.0 as *const u8,
                    work as *mut u8,
                    mod_buf_size as usize,
                );

                *binder_id = mod_file.binder_id;
            }

            debug_print(&format!(
                "[HOOK] Copied pre-allocated mod data for {} into game buffer",
                requested_path
            ));
            return CriStatus::Success;
        } else {
            debug_print("[HOOK] Missing work_handle or work_size on mod file");
        }
    }

    debug_print(&format!(
        "[HOOK] No mod file override found for {}, falling back to original",
        requested_path
    ));

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
    unsafe {
        hook!(
            FnCriBinderBindFile,
            Cri_Binder_Bind_File,
            CRI_BINDER_BIND_FILE_ADDR,
            hook_impl
        );
    }

    Ok(())
}
