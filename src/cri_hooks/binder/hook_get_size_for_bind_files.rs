use crate::{
    cri_hooks::CriError,
    hook, pstr_to_string,
    scanner::{parse_pattern, scan_main_module},
    utils::logging::debug_print,
};
use retour::static_detour;
use std::os::windows::raw::HANDLE;

static_detour! {
    static Cri_Binder_Get_Size_For_Bind_Files: unsafe extern "system" fn(HANDLE, *mut u8, *mut i32) -> CriError;
}

type FnCriBinderGetSizeForBindFiles =
    unsafe extern "system" fn(HANDLE, *mut u8, *mut i32) -> CriError;

pub fn cri_binder_get_size_for_bind_files_hook(
    src_binder_handle: HANDLE,
    path: *mut u8,
    work_size: *mut i32,
) -> CriError {
    let status =
        unsafe { Cri_Binder_Get_Size_For_Bind_Files.call(src_binder_handle, path, work_size) };

    debug_print!(
        "[CriBinderGetSizeForBindFiles] path: {}, work_size: {}, cri_status: {status:?}",
        unsafe { pstr_to_string(path) },
        unsafe { *work_size }
    );

    status
}

pub fn register_hook() -> Result<(), Box<dyn std::error::Error>> {
    let pattern = "48 89 5C 24 08 48 89 74 24 20 57 48 81 EC 50";

    unsafe {
        let parsed = parse_pattern(pattern);

        if let Some(address) = scan_main_module(&parsed) {
            let addr_usize = address as usize;

            debug_print!(
                "[SCANNER] Found CriBinderGetSizeForBindFiles at {:#x}",
                addr_usize
            );

            hook!(
                FnCriBinderGetSizeForBindFiles,
                Cri_Binder_Get_Size_For_Bind_Files,
                addr_usize,
                cri_binder_get_size_for_bind_files_hook
            );
        } else {
            return Err("Could not find pattern for CriBinderGetSizeForBindFiles".into());
        }
    }

    Ok(())
}
