use retour::static_detour;

use crate::{
    debug_print, hook,
    hooks::CriError,
    scanner::{parse_pattern, scan_main_module},
};

static_detour! {
    static Cri_Binder_Set_Priority: unsafe extern "system" fn(u32, i32) -> CriError;
}
type FnCriBinderSetPriority = unsafe extern "system" fn(u32, i32) -> CriError;

pub fn cri_binder_set_priority_hook(binder_id: u32, priority: i32) -> CriError {
    debug_print!("[CriBinderSetPriority] binder_id: {binder_id}, priority: {priority}");
    unsafe { Cri_Binder_Set_Priority.call(binder_id, priority) }
}

pub fn register_set_priority_hook() -> Result<(), Box<dyn std::error::Error>> {
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
                cri_binder_set_priority_hook
            );
        } else {
            return Err("Could not find pattern for CriBinderSetPriority".into());
        }
    }

    Ok(())
}
