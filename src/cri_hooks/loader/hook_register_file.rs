use std::ffi::CString;

use retour::static_detour;
use winapi::shared::ntdef::{HANDLE, INT, PSTR};

use crate::{BINDER_COLLECTION, hook, pstr_to_string, utils::logging::debug_print};

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
            cri_loader_register_file_hook
        );
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
    debug_print(&format!(
        "[CriLoaderRegisterFile] loader: {loader:?}, binder: {binder:?}, path: {}, file_id: {file_id}",
        unsafe { pstr_to_string(path) }
    ));

    if file_id != -1 {
        return unsafe { CriLoader_Register_File.call(loader, binder, path, file_id, zero) };
    }

    let path_string = unsafe { pstr_to_string(path) };

    let redirected_path = {
        let binders = BINDER_COLLECTION.lock().unwrap();
        if let Some(mod_file_arc) = binders.find_mod_file_by_relative_path(&path_string) {
            if let Ok(mod_file) = mod_file_arc.lock() {
                // Only clone the absolute path
                Some(mod_file.absolute_path.clone())
            } else {
                None
            }
        } else {
            None
        }
    };

    if let Some(pathbuf) = redirected_path {
        let redirected_cstr =
            CString::new(pathbuf.to_string_lossy().as_bytes()).expect("CString conversion failed");

        debug_print(&format!(
            "[CriLoaderRegisterFile] redirecting {path_string:?} to {}",
            pathbuf.display()
        ));

        return unsafe {
            CriLoader_Register_File.call(
                loader,
                binder,
                redirected_cstr.as_ptr() as PSTR,
                file_id,
                zero,
            )
        };
    }

    unsafe { CriLoader_Register_File.call(loader, binder, path, file_id, zero) }
}
