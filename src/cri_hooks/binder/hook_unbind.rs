use retour::static_detour;
use winapi::shared::minwindef::DWORD;

use crate::{BINDER_COLLECTION, cri_hooks::CriStatus, hook, utils::logging::debug_print};

const CRI_UNBIND_ADDR: usize = 0x14046315c;

static_detour! {
    static Cri_Binder_Unbind: unsafe extern "system" fn(DWORD) -> CriStatus;
}

type FnCriBinderUnbind = unsafe extern "system" fn(DWORD) -> CriStatus;

pub fn hook_impl(binder_id: DWORD) -> CriStatus {
    let mut binder_collection = BINDER_COLLECTION.lock().expect("Mutex was poisoned");
    for mod_file_arc in binder_collection.mod_files.values() {
        if let Ok(mut mod_file) = mod_file_arc.lock() {
            if mod_file.binder_id == binder_id {
                mod_file.is_bound = false; // mark unbound
                debug_print(&format!(
                    "[HOOK] Unbound mod file: {}",
                    mod_file.relative_path.display()
                ));
            }
        }
    }

    if let Some(pos) = binder_collection
        .bindings
        .iter()
        .position(|b| b.bind_id == binder_id)
    {
        binder_collection.bindings.remove(pos);
        debug_print("[HOOK] Removed CpkBinding from bindings list");
    }

    unsafe { Cri_Binder_Unbind.call(binder_id) }
}

pub fn register_hook() -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        hook!(
            FnCriBinderUnbind,
            Cri_Binder_Unbind,
            CRI_UNBIND_ADDR,
            hook_impl
        );
    }

    Ok(())
}
