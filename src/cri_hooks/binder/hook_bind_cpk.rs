use std::path::PathBuf;

use retour::static_detour;
use winapi::shared::{
    minwindef::DWORD,
    ntdef::{HANDLE, INT, PSTR},
};

use crate::{
    BINDER_COLLECTION, CpkBinding,
    cri_hooks::CriError,
    hook, paths_to_cstring,
    utils::{RawAllocator, SafeHandle, logging::debug_print},
};

const CRI_BINDER_BIND_CPK_ADDR: usize = 0x140460954;

static_detour! {
    static Cri_Binder_Bind_Cpk: unsafe extern "system" fn(HANDLE, HANDLE, PSTR, HANDLE, INT, *mut DWORD) -> CriError;
}

type FnCriBinderBindCpk =
    unsafe extern "system" fn(HANDLE, HANDLE, PSTR, HANDLE, INT, *mut DWORD) -> CriError;

pub fn hook_impl(
    binder_handle: HANDLE,
    src_binder_handle: HANDLE,
    path: PSTR,
    work: HANDLE,
    work_size: INT,
    binder_id: *mut DWORD,
) -> CriError {
    debug_print("[HOOK] bind_cpk");

    unsafe {
        Cri_Binder_Bind_Cpk.call(
            binder_handle,
            src_binder_handle,
            path,
            work,
            work_size,
            binder_id,
        )
    }
}

// https://github.com/Sewer56/CriFs.V2.Hook.ReloadedII/blob/8a20e34d7a4a1da1a12ede432a7494040d80f960/CriFs.V2.Hook/Hooks/CpkBinder.cs#L219
fn custom_bind_folder(binder_handle: HANDLE, priority: i32) -> u32 {
    let mut size: INT = 0;
    let binder_collection = BINDER_COLLECTION.lock().expect("Mutex was poisoned");

    debug_print("[HOOK BIND FOLDER] Binding mod files");

    let paths_vec: Vec<PathBuf> = binder_collection
        .mod_files
        .values()
        .filter_map(|mod_file_arc| {
            mod_file_arc
                .lock()
                .ok()
                .map(|mod_file| mod_file.file_path.clone())
        })
        .collect();

    let file_list =
        paths_to_cstring(&paths_vec).expect("Error converting mod file list into CString");

    let err = super::hook_get_size_for_bind_files::hook_impl(
        binder_handle,
        file_list.as_ptr() as PSTR,
        &mut size,
    );

    if err != CriError::Success {
        debug_print("[HOOK BIND FOLDER] Could not get get size for bind mod files");
        return 0;
    }

    debug_print(&format!("[HOOK BIND FOLDER] File size calculated: {size}"));

    if let Some(mut alloc) = RawAllocator::new(size as usize) {
        let start = std::time::Instant::now();
        let mut binder_id: DWORD = 0;
        let err = super::hook_bind_files::hook_impl(
            binder_handle,
            std::ptr::null_mut(),
            file_list.as_ptr() as PSTR,
            alloc.as_ptr().0,
            size,
            &mut binder_id,
        );

        if err != CriError::Success {
            debug_print(&format!(
                "[HOOK BIND FOLDER] Binding files failed with {err:?}"
            ));
            alloc.dispose();

            return 0;
        };

        debug_print(&format!(
            "[HOOK BIND FOLDER] Binder id: {binder_id}, handle: {binder_handle:?}"
        ));

        // keep looping until finished
        drop(binder_collection);
        let mut status: INT = 0;
        loop {
            super::hook_get_status::hook_impl(binder_id, &mut status);

            match status {
                2 => {
                    // complete
                    super::hook_set_priority::hook_impl(binder_id, priority);
                    debug_print(&format!(
                        "[HOOK BIND FOLDER] Took {}ms, bound files: {paths_vec:?}",
                        start.elapsed().as_millis()
                    ));

                    let mut binder_collection =
                        BINDER_COLLECTION.lock().expect("Mutex was poisoned");

                    for mod_file_arc in binder_collection.mod_files.values() {
                        if let Ok(mut mod_file) = mod_file_arc.lock() {
                            if paths_vec.contains(&mod_file.file_path) {
                                mod_file.binder_id = binder_id;
                                mod_file.handle = Some(SafeHandle(binder_handle));
                            }
                        } else {
                            debug_print(
                                "[HOOK] Failed to lock mod_file mutex for updating binder_id/handle",
                            );
                        }
                    }

                    let new_binding = CpkBinding::new(alloc, binder_id);
                    binder_collection.bindings.push(new_binding);

                    drop(binder_collection);

                    return binder_id;
                }
                6 => {
                    // error
                    debug_print("[HOOK BIND FOLDER] Binding failed");

                    super::hook_unbind::hook_impl(binder_id);
                    alloc.dispose();

                    return 0;
                }
                _ => (),
            }
        }
    }

    0
}

pub fn register_hook() -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        hook!(
            FnCriBinderBindCpk,
            Cri_Binder_Bind_Cpk,
            CRI_BINDER_BIND_CPK_ADDR,
            hook_impl
        );
    }

    Ok(())
}
