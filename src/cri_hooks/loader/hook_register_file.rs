use retour::static_detour;
use winapi::shared::ntdef::{HANDLE, INT, PSTR};

use crate::{
    BINDER_COLLECTION, hook, lock_or_log, pstr_to_string,
    scanner::{parse_pattern, scan_main_module},
    spd::hook_spd_tick::ORIGINAL_CALLBACKS,
    utils::logging::debug_print,
};

static_detour! {
    static CriLoader_Register_File: unsafe extern "system" fn(HANDLE, HANDLE, PSTR, INT, HANDLE) -> HANDLE;
}

type FnCriLoaderRegisterFile =
    unsafe extern "system" fn(HANDLE, HANDLE, PSTR, INT, HANDLE) -> HANDLE;

pub fn register_hook() -> Result<(), Box<dyn std::error::Error>> {
    let pattern = "48 8B C4 48 89 58 08 48 89 70 10 4C";

    unsafe {
        let parsed = parse_pattern(pattern);

        if let Some(address) = scan_main_module(&parsed) {
            let addr_usize = address as usize;

            debug_print!("[SCANNER] Found CriLoaderRegisterFile at {:#x}", addr_usize);

            hook!(
                FnCriLoaderRegisterFile,
                CriLoader_Register_File,
                addr_usize,
                cri_loader_register_file_hook
            );
        } else {
            return Err(format!("Could not find pattern for CriLoaderRegisterFile").into());
        }
    }

    Ok(())
}

/// Registers a file before loading it.
///
/// ## Arguments
///
/// * `loader`: The handle to the CriFs Loader.
/// * `binder`: The handle to the CriFs Binder.
/// * `path`: Pointer to a string with the file path. This path is relative and is usually ANSI.
/// * `fileId`: The ID of the file within the archive (CPK). -1 if not using ID.
/// * `zero`: Unknown, usually zero.
///
/// # Safety
/// This function is called from the game and must preserve the original ABI.
fn cri_loader_register_file_hook(
    loader: HANDLE,
    binder: HANDLE,
    path: PSTR,
    file_id: INT,
    zero: HANDLE,
) -> HANDLE {
    debug_print!(
        "[CriLoaderRegisterFile] loader: {loader:?}, binder: {binder:?}, path: {}, file_id: {file_id}",
        unsafe { pstr_to_string(path) }
    );

    if file_id != -1 {
        return unsafe { CriLoader_Register_File.call(loader, binder, path, file_id, zero) };
    }

    let path_string = unsafe { pstr_to_string(path) };

    let redirected_path = {
        let binders = lock_or_log(&BINDER_COLLECTION, "CriLoaderRegisterFile, redirected_path");

        binders
            .find_mod_file_by_relative_path(&path_string)
            .map(|mod_file| mod_file.lock().unwrap().absolute_path_cstr.clone())
    };

    if let Some(path) = redirected_path {
        debug_print!("[CriLoaderRegisterFile] redirecting {path_string:?} to {path:?}",);

        return unsafe {
            CriLoader_Register_File.call(loader, binder, path.as_ptr() as PSTR, file_id, zero)
        };
    }

    let result = unsafe { CriLoader_Register_File.call(loader, binder, path, file_id, zero) };

    ORIGINAL_CALLBACKS
        .write()
        .unwrap()
        .insert(loader as usize, 0);

    result
}
