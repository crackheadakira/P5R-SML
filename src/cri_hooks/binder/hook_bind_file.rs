use retour::static_detour;
use winapi::shared::{
    minwindef::DWORD,
    ntdef::{HANDLE, INT, PSTR},
};

use crate::{cri_hooks::CriError, hook, utils::logging::debug_print};

const CRI_BINDER_BIND_FILE_ADDR: usize = 0x140460b6c;

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
    debug_print("[HOOK] bind_file");

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
