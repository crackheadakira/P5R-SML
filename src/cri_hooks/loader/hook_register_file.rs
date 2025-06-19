use retour::static_detour;
use winapi::shared::ntdef::{HANDLE, INT, PSTR};

use crate::{hook, utils::logging::debug_print};

const CRI_LOADER_REGISTER_FILE_ADDR: usize = 0x1404674e4;

static_detour! {
    static CriLoader_Register_File: unsafe extern "system" fn(HANDLE, HANDLE, PSTR, INT, HANDLE) -> HANDLE;
}

type FnCriLoaderRegisterFile =
    unsafe extern "system" fn(HANDLE, HANDLE, PSTR, INT, HANDLE) -> HANDLE;

pub fn register_hook() -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        hook!(
            FnCriLoaderRegisterFile,
            CriLoader_Register_File,
            CRI_LOADER_REGISTER_FILE_ADDR,
            hook_impl
        );
    }

    Ok(())
}

fn hook_impl(loader: HANDLE, binder: HANDLE, path: PSTR, file_id: INT, zero: HANDLE) -> HANDLE {
    debug_print("[HOOK] register_file");
    unsafe { CriLoader_Register_File.call(loader, binder, path, file_id, zero) }
}
