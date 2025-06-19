use retour::static_detour;
use winapi::shared::{minwindef::DWORD, ntdef::INT};

use crate::{cri_hooks::CriError, hook, utils::logging::debug_print};

const CRI_BINDER_GET_STATUS: usize = 0x14046260c;

static_detour! {
    static Cri_Binder_Get_Status: unsafe extern "system" fn(DWORD, *mut INT) -> CriError;
}

type FnCriBinderGetStatus = unsafe extern "system" fn(DWORD, *mut INT) -> CriError;

pub fn hook_impl(binder_id: DWORD, status: *mut INT) -> CriError {
    debug_print("[HOOK] get_status");
    unsafe { Cri_Binder_Get_Status.call(binder_id, status) }
}

pub fn register_hook() -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        hook!(
            FnCriBinderGetStatus,
            Cri_Binder_Get_Status,
            CRI_BINDER_GET_STATUS,
            hook_impl
        );
    }

    Ok(())
}
