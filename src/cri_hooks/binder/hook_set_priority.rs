use retour::static_detour;
use winapi::shared::{minwindef::DWORD, ntdef::INT};

use crate::{
    cri_hooks::CriError,
    hook,
    scanner::{parse_pattern, scan_main_module},
    utils::logging::debug_print,
};

static_detour! {
    static Cri_Binder_Set_Priority: unsafe extern "system" fn(DWORD, INT) -> CriError;
}
type FnCriBinderSetPriority = unsafe extern "system" fn(DWORD, INT) -> CriError;

pub fn hook_impl(binder_id: DWORD, priority: INT) -> CriError {
    debug_print!("[CriBinderSetPriority] binder_id: {binder_id}, priority: {priority}");
    unsafe { Cri_Binder_Set_Priority.call(binder_id, priority) }
}

pub fn register_hook() -> Result<(), Box<dyn std::error::Error>> {
    let pattern = "48 89 5C 24 08 57 48 83 EC 20 8B FA E8 ?? ?? ?? ?? 48 8B D8 48 85 C0 75 18";

    unsafe {
        let parsed = parse_pattern(pattern);

        if let Some(address) = scan_main_module(&parsed) {
            let addr_usize = address as usize;

            debug_print!("[SCANNER] Found CriBinderSetPriority at {:#x}", addr_usize);

            hook!(
                FnCriBinderSetPriority,
                Cri_Binder_Set_Priority,
                addr_usize,
                hook_impl
            );
        } else {
            return Err(format!("Could not find pattern for CriBinderSetPriority").into());
        }
    }

    Ok(())
}
