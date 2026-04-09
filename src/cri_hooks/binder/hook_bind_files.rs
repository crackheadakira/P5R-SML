use retour::static_detour;
use winapi::shared::{
    minwindef::DWORD,
    ntdef::{HANDLE, INT, PSTR},
};

use crate::{cri_hooks::CriStatus, hook, utils::logging::debug_print};

const CRI_BINDER_BIND_FILES_ADDR: usize = 0x140460b98;

static_detour! {
    static Cri_Binder_Bind_Files: unsafe extern "system" fn(HANDLE, HANDLE, PSTR, HANDLE, INT, *mut DWORD) -> CriStatus;
}

type FnCriBinderBindFiles =
    unsafe extern "system" fn(HANDLE, HANDLE, PSTR, HANDLE, INT, *mut DWORD) -> CriStatus;

pub fn hook_impl(
    binder_handle: HANDLE,
    src_binder_handle: HANDLE,
    path: PSTR,
    work: HANDLE,
    work_size: INT,
    binder_id: *mut DWORD,
) -> CriStatus {
    debug_print("[HOOK] bind_files");

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

pub fn register_hook() -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        hook!(
            FnCriBinderBindFiles,
            Cri_Binder_Bind_Files,
            CRI_BINDER_BIND_FILES_ADDR,
            hook_impl
        );
    }

    Ok(())
}
