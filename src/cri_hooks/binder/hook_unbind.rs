use retour::static_detour;
use winapi::shared::minwindef::DWORD;

use crate::{cri_hooks::CriError, hook, utils::logging::debug_print};

const CRI_UNBIND_ADDR: usize = 0x14046315c;

static_detour! {
    static Cri_Binder_Unbind: unsafe extern "system" fn(DWORD) -> CriError;
}

type FnCriBinderUnbind = unsafe extern "system" fn(DWORD) -> CriError;

pub fn hook_impl(binder_id: DWORD) -> CriError {
    debug_print!("[CriBinderUnbind] binder_id: {binder_id:?}");

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
