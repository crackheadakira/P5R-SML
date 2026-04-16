use crate::{debug_print, hook, hooks::CriError, utils::pstr_to_string};
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

pub fn register_get_size_for_bind_files_hook(
    memory: &'static [u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let pattern = "48 89 5C 24 08 48 89 74 24 20 57 48 81 EC 50";

    unsafe {
        let signature = crate::scanner::Signature::parse(pattern)?;

        if let Some(address) = crate::scanner::scan_memory(memory, &signature) {
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
