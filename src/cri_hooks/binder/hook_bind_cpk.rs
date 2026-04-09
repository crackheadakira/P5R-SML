use std::{collections::HashSet, path::PathBuf};

use retour::static_detour;
use winapi::shared::{
    minwindef::DWORD,
    ntdef::{HANDLE, INT, PSTR},
};

use crate::{
    BINDER_COLLECTION, CpkBinding,
    cri_hooks::CriStatus,
    hook, paths_to_cstring, pstr_to_string,
    utils::{RawAllocator, SafeHandle, logging::debug_print},
};

const CRI_BINDER_BIND_CPK_ADDR: usize = 0x140460954;

static_detour! {
    static Cri_Binder_Bind_Cpk: unsafe extern "system" fn(HANDLE, HANDLE, PSTR, HANDLE, INT, *mut DWORD) -> CriStatus;
}

type FnCriBinderBindCpk =
    unsafe extern "system" fn(HANDLE, HANDLE, PSTR, HANDLE, INT, *mut DWORD) -> CriStatus;

pub fn hook_impl(
    binder_handle: HANDLE,
    src_binder_handle: HANDLE,
    path: PSTR,
    work: HANDLE,
    work_size: INT,
    binder_id: *mut DWORD,
) -> CriStatus {
    let status = unsafe {
        Cri_Binder_Bind_Cpk.call(
            binder_handle,
            src_binder_handle,
            path,
            work,
            work_size,
            binder_id,
        )
    };

    debug_print(&format!(
        "[CriBinderBindCpk] binder_handle: {binder_handle:?}, src_binder_handle: {src_binder_handle:?}, path: {}, work: {work:?}, work_size: {work_size}, binder_id: {}",
        unsafe { pstr_to_string(path) },
        unsafe { *binder_id }
    ));

    status
}

// https://github.com/Sewer56/CriFs.V2.Hook.ReloadedII/blob/8a20e34d7a4a1da1a12ede432a7494040d80f960/CriFs.V2.Hook/Hooks/CpkBinder.cs#L219
fn custom_bind_folder(binder_handle: HANDLE, priority: i32) -> u32 {
    let mut size: INT = 0;
    debug_print(&format!(
        "[HOOK BIND FOLDER] Binding mod files, binder_handle: {binder_handle:?}, priority: {priority}"
    ));

    let paths_vec: Vec<PathBuf> = {
        let binder_collection = BINDER_COLLECTION.lock().expect("Mutex was poisoned");

        binder_collection
            .mod_files
            .values()
            .filter_map(|mod_file_arc| {
                mod_file_arc
                    .lock()
                    .ok()
                    .map(|mod_file| mod_file.absolute_path.clone())
            })
            .collect()
    };

    let file_list =
        paths_to_cstring(&paths_vec).expect("Error converting mod file list into CString");

    let err = super::hook_get_size_for_bind_files::hook_impl(
        binder_handle,
        file_list.as_ptr() as PSTR,
        &mut size,
    );

    if err != CriStatus::Success {
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

        if err != CriStatus::Success {
            debug_print(&format!(
                "[HOOK BIND FOLDER] Binding files failed with {err:?}"
            ));
            alloc.dispose();

            return 0;
        };

        debug_print(&format!(
            "[HOOK BIND FOLDER] Bound files with id: {binder_id}, handle: {binder_handle:?}"
        ));

        if wait_for_bind_complete(binder_id).is_some() {
            super::hook_set_priority::hook_impl(binder_id, priority);
            debug_print(&format!(
                "[HOOK BIND FOLDER] Took {}ms, bound files: {paths_vec:?}",
                start.elapsed().as_millis()
            ));

            let mut binder_collection = BINDER_COLLECTION.lock().expect("Mutex was poisoned");

            let paths_set: HashSet<_> = paths_vec.into_iter().collect();
            for mod_file_arc in binder_collection.mod_files.values() {
                if let Ok(mut mod_file) = mod_file_arc.lock() {
                    if paths_set.contains(&mod_file.absolute_path) {
                        mod_file.binder_id = binder_id;
                        mod_file.handle = Some(SafeHandle(binder_handle));
                        mod_file.is_bound = true;
                        mod_file.work_size = Some(size);
                        mod_file.work_handle = Some(alloc.as_ptr());

                        debug_print(&format!(
                            "[HOOK] Bound mod file: {}\n  binder_id: {}\n  work_size: {}\n  work_handle: {:?}",
                            mod_file.absolute_path.display(),
                            binder_id,
                            size,
                            alloc.as_ptr().0
                        ));
                    }
                } else {
                    debug_print(
                        "[HOOK] Failed to lock mod_file mutex for updating binder_id/handle",
                    );
                }
            }

            let new_binding = CpkBinding::new(alloc, binder_id, true);
            binder_collection.bindings.push(new_binding);

            drop(binder_collection);

            return binder_id;
        } else {
            debug_print("[HOOK BIND FOLDER] Binding failed");

            super::hook_unbind::hook_impl(binder_id);
            alloc.dispose();

            return 0;
        }
    }

    0
}

fn wait_for_bind_complete(binder_id: DWORD) -> Option<()> {
    let mut status = 0;
    loop {
        super::hook_get_status::hook_impl(binder_id, &mut status);
        match status {
            2 => return Some(()), // completed
            6 => return None,     // failed
            _ => continue,
        }
    }
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
