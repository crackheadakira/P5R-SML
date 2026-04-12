use std::{
    collections::HashSet,
    ffi::CString,
    sync::{Arc, Mutex},
};

use retour::static_detour;
use winapi::shared::{
    minwindef::DWORD,
    ntdef::{HANDLE, INT, PSTR},
};

use crate::{
    BINDER_COLLECTION, CpkBinding,
    bindings::ModFile,
    cri_hooks::{CriBinderStatus, CriError},
    hook, lock_or_log, pstr_to_string,
    scanner::{parse_pattern, scan_main_module},
    utils::{RawAllocator, SafeHandle, logging::debug_print},
};

static_detour! {
    static Cri_Binder_Bind_Cpk: unsafe extern "system" fn(HANDLE, HANDLE, PSTR, HANDLE, INT, *mut DWORD) -> CriError;
}

type FnCriBinderBindCpk =
    unsafe extern "system" fn(HANDLE, HANDLE, PSTR, HANDLE, INT, *mut DWORD) -> CriError;

pub fn cri_binder_bind_cpk_hook(
    binder_handle: HANDLE,
    src_binder_handle: HANDLE,
    path: PSTR,
    work: HANDLE,
    work_size: INT,
    binder_id: *mut DWORD,
) -> CriError {
    debug_print!(
        "[CriBinderBindCpk] binder_handle: {binder_handle:?}, src_binder_handle: {src_binder_handle:?}, path: {}, work: {work:?}, work_size: {work_size}",
        unsafe { pstr_to_string(path) },
    );

    let should_bind = {
        let mut binder_collection = lock_or_log(&BINDER_COLLECTION, "CriBinderBindCpk");
        binder_collection
            .binder_handles
            .insert(SafeHandle(binder_handle))
    };

    if should_bind {
        debug_print!("[CriBinderBindCpk] Setting up binds for handle {binder_handle:?}");

        custom_bind_folder(binder_handle, i32::MAX);
    }

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
fn custom_bind_folder(binder_handle: HANDLE, priority: i32) {
    debug_print!(
        "[CriBinderBindCpkFolder] Binding mod files, binder_handle: {binder_handle:?}, priority: {priority}"
    );

    let file_list: Vec<String> = {
        let binder_collection = lock_or_log(&BINDER_COLLECTION, "HookBindFolder, File List");

        binder_collection
            .mod_files
            .values()
            .filter_map(|mod_file_arc| {
                mod_file_arc
                    .lock()
                    .ok()
                    .map(|mod_file| mod_file.relative_path.clone())
            })
            .collect()
    };

    let mut size = 0;
    let file_list_str =
        CString::new(file_list.join("\n")).expect("Error converting mod file list into CString");

    let status = super::hook_get_size_for_bind_files::cri_binder_get_size_for_bind_files_hook(
        binder_handle,
        file_list_str.as_ptr() as PSTR,
        &mut size,
    );

    if status != CriError::Success {
        debug_print!(
            "[CriBinderBindCpkFolder] Could not get get size for bind mod files, status: {status:?}"
        );
        return;
    }

    debug_print!("[CriBinderBindCpkFolder] File size calculated: {size}");

    let Some(mut alloc) = RawAllocator::new(size as usize) else {
        return;
    };

    let start = std::time::Instant::now();

    let mut binder_id = 0;

    let status = super::hook_bind_files::hook_impl(
        binder_handle,
        std::ptr::null_mut(),
        file_list_str.as_ptr() as PSTR,
        alloc.as_ptr().0,
        size,
        &mut binder_id,
    );

    if status != CriError::Success {
        debug_print!("[CriBinderBindCpkFolder] Binding files failed with {status:?}");

        alloc.dispose();

        return;
    };

    debug_print!(
        "[CriBinderBindCpkFolder] Bound files with binder_id: {binder_id}, handle: {binder_handle:?}"
    );

    let mut status = CriBinderStatus::None.into();
    loop {
        super::hook_get_status::hook_impl(binder_id, &mut status);

        match status.into() {
            CriBinderStatus::Complete => {
                super::hook_set_priority::hook_impl(binder_id, priority);

                debug_print!(
                    "[CriBinderBindCpkFolder] Took {}ms, bound files: {file_list:?}",
                    start.elapsed().as_millis()
                );

                let binder_updates: Vec<(Arc<Mutex<ModFile>>, u32, SafeHandle, i32)> = {
                    let binder_collection =
                        lock_or_log(&BINDER_COLLECTION, "HookBindFolder, Binder Updates");
                    let paths_set: HashSet<_> = file_list.iter().cloned().collect();

                    binder_collection
                        .mod_files
                        .values()
                        .filter_map(|mod_file_arc| {
                            if let Ok(mod_file) = mod_file_arc.lock() {
                                if paths_set.contains(mod_file.relative_path.as_str()) {
                                    Some((
                                        mod_file_arc.clone(),
                                        binder_id,
                                        SafeHandle(binder_handle),
                                        size,
                                    ))
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        })
                        .collect()
                };

                for (mod_file_arc, binder_id, handle, work_size) in binder_updates {
                    if let Ok(mut mod_file) = mod_file_arc.lock() {
                        mod_file.binder_id = binder_id;
                        mod_file.handle = Some(handle);
                        mod_file.is_bound = true;
                        mod_file.work_size = Some(work_size);
                        mod_file.work_handle = Some(alloc.as_ptr());

                        debug_print!(
                            "[CriBinderBindCpkFolder] Bound mod file: {}\n  binder_id: {}\n  work_size: {}\n  work_handle: {:?}",
                            mod_file.absolute_path.display(),
                            binder_id,
                            work_size,
                            alloc.as_ptr().0
                        );
                    } else {
                        debug_print!(
                            "[CriBinderBindCpkFolder] Failed to lock mod_file mutex for updating binder_id/handle",
                        );
                    }
                }

                {
                    let mut binder_collection =
                        lock_or_log(&BINDER_COLLECTION, "HookBindFolder, CPK Binding");
                    let new_binding = CpkBinding::new(alloc, binder_id, true);
                    binder_collection.bindings.push(new_binding);
                }

                return;
            }
            CriBinderStatus::Error => {
                debug_print!("[CriBinderBindCpkFolder] Binding {binder_id} failed");

                super::hook_unbind::hook_impl(binder_id);
                alloc.dispose();

                return;
            }
            _ => (),
        }
    }
}

pub fn register_hook() -> Result<(), Box<dyn std::error::Error>> {
    let pattern = "48 83 EC 48 48 8B 44 24 78 C7 44 24 30 01 00 00 00 48 89 44 24 28 8B";

    unsafe {
        let parsed = parse_pattern(pattern);

        if let Some(address) = scan_main_module(&parsed) {
            let addr_usize = address as usize;

            debug_print!("[SCANNER] Found CriBinderBindCpk at {:#x}", addr_usize);

            hook!(
                FnCriBinderBindCpk,
                Cri_Binder_Bind_Cpk,
                addr_usize,
                cri_binder_bind_cpk_hook
            );
        } else {
            return Err(format!("Could not find pattern for CriBinderBindCpk").into());
        }
    }

    Ok(())
}
