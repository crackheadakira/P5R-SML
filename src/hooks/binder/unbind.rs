use retour::static_detour;

use crate::{
    debug_print, hook,
    hooks::CriError,
    scanner::{parse_pattern, scan_main_module},
};

static_detour! {
    static Cri_Binder_Unbind: unsafe extern "system" fn(u32) -> CriError;
}

type FnCriBinderUnbind = unsafe extern "system" fn(u32) -> CriError;

pub fn cri_binder_unbind_hook(binder_id: u32) -> CriError {
    debug_print!("[CriBinderUnbind] binder_id: {binder_id:?}");

    unsafe { Cri_Binder_Unbind.call(binder_id) }
}

pub fn register_unbind_hook() -> Result<(), Box<dyn std::error::Error>> {
    let pattern = "48 89 5C 24 08 57 48 83 EC 20 8B F9 E8 ?? ?? ?? ?? 48 8B D8";

    unsafe {
        let parsed = parse_pattern(pattern);

        if let Some(address) = scan_main_module(&parsed) {
            let addr_usize = address as usize;

            debug_print!("[SCANNER] Found CriBinderUnbind at {:#x}", addr_usize);

            hook!(
                FnCriBinderUnbind,
                Cri_Binder_Unbind,
                addr_usize,
                cri_binder_unbind_hook
            );
        } else {
            return Err("Could not find pattern for CriBinderUnbind".into());
        }
    }

    Ok(())
}
