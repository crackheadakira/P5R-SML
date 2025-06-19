use retour::static_detour;
use winapi::shared::{minwindef::DWORD, ntdef::INT};

use crate::{cri_hooks::CriError, hook, utils::logging::debug_print};

const CRI_BINDER_SET_PRIORITY_ADDR: usize = 0x140462f5c;

static_detour! {
    static Cri_Binder_Set_Priority: unsafe extern "system" fn(DWORD, INT) -> CriError;
}
type FnCriBinderSetPriority = unsafe extern "system" fn(DWORD, INT) -> CriError;

pub fn hook_impl(binder_id: DWORD, priority: INT) -> CriError {
    debug_print("[HOOK] set_priority called");
    unsafe { Cri_Binder_Set_Priority.call(binder_id, priority) }
}

pub fn register_hook() -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        hook!(
            FnCriBinderSetPriority,
            Cri_Binder_Set_Priority,
            CRI_BINDER_SET_PRIORITY_ADDR,
            hook_impl
        );
    }

    Ok(())
}
