use crate::{cri_hooks::CriError, hook, pstr_to_string, utils::logging::debug_print};
use retour::static_detour;
use winapi::shared::ntdef::{HANDLE, INT, PSTR};

const CRI_BINDER_GET_SIZE_FOR_BIND_FILES_ADDR: usize = 0x140462854;

static_detour! {
    static Cri_Binder_Get_Size_For_Bind_Files: unsafe extern "system" fn(HANDLE, PSTR, *mut INT) -> CriError;
}

type FnCriBinderGetSizeForBindFiles = unsafe extern "system" fn(HANDLE, PSTR, *mut INT) -> CriError;

pub fn cri_binder_get_size_for_bind_files_hook(
    src_binder_handle: HANDLE,
    path: PSTR,
    work_size: *mut INT,
) -> CriError {
    let status =
        unsafe { Cri_Binder_Get_Size_For_Bind_Files.call(src_binder_handle, path, work_size) };

    debug_print(&format!(
        "[CriBinderGetSizeForBindFiles] path: {}, work_size: {}, cri_status: {status:?}",
        unsafe { pstr_to_string(path) },
        unsafe { *work_size }
    ));

    status
}

pub fn register_hook() -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        hook!(
            FnCriBinderGetSizeForBindFiles,
            Cri_Binder_Get_Size_For_Bind_Files,
            CRI_BINDER_GET_SIZE_FOR_BIND_FILES_ADDR,
            cri_binder_get_size_for_bind_files_hook
        );
    }

    Ok(())
}
