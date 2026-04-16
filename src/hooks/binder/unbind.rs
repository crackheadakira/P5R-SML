use retour::static_detour;

use crate::{debug_print, hook, hooks::CriError, utils::lock_or_log};

static_detour! {
    static Cri_Binder_Unbind: unsafe extern "system" fn(u32) -> CriError;
}

type FnCriBinderUnbind = unsafe extern "system" fn(u32) -> CriError;

pub fn cri_binder_unbind_hook(binder_id: u32) -> CriError {
    let result = unsafe { Cri_Binder_Unbind.call(binder_id) };
    debug_print!("[CriBinderUnbind] binder_id: {binder_id:?}");

    if result == CriError::Success {
        let mut binder_collection = lock_or_log(&crate::vfs::BINDER_COLLECTION, "CriBinder_Unbind");

        binder_collection.bindings.retain(|binding| {
            if binding.bind_id == binder_id {
                crate::debug_print!("[VFS] Dropping binding ID {} (Memory Freed)", binder_id);
                false // Removes from Vec, triggering Drop
            } else {
                true
            }
        });
    }

    result
}

pub fn register_unbind_hook(memory: &'static [u8]) -> Result<(), Box<dyn std::error::Error>> {
    let pattern = "48 89 5C 24 08 57 48 83 EC 20 8B F9 E8 ?? ?? ?? ?? 48 8B D8";

    unsafe {
        let signature = crate::scanner::Signature::parse(pattern)?;

        if let Some(address) = crate::scanner::scan_memory(memory, &signature) {
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
