use crate::{cri_hooks::CriStatus, hook, utils::logging::debug_print};
use retour::static_detour;
use winapi::shared::ntdef::{HANDLE, INT, PSTR};

const CRI_BINDER_GET_SIZE_FOR_BIND_FILES_ADDR: usize = 0x140462854;

static_detour! {
    static Cri_Binder_Get_Size_For_Bind_Files: unsafe extern "system" fn(HANDLE, PSTR, *mut INT) -> CriStatus;
}

type FnCriBinderGetSizeForBindFiles =
    unsafe extern "system" fn(HANDLE, PSTR, *mut INT) -> CriStatus;

pub fn hook_impl(src_binder_handle: HANDLE, path: PSTR, work_size: *mut INT) -> CriStatus {
    let status =
        unsafe { Cri_Binder_Get_Size_For_Bind_Files.call(src_binder_handle, path, work_size) };

    debug_print(&format!(
        "[HOOK] get_size_for_bind_files, path: {path:?}, work_size: {work_size:?}, cri_status: {status:?}"
    ));

    status
}

pub fn register_hook() -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        hook!(
            FnCriBinderGetSizeForBindFiles,
            Cri_Binder_Get_Size_For_Bind_Files,
            CRI_BINDER_GET_SIZE_FOR_BIND_FILES_ADDR,
            hook_impl
        );
    }

    Ok(())
}
