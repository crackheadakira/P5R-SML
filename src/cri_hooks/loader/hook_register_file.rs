use retour::static_detour;
use winapi::shared::ntdef::{HANDLE, INT, PSTR};

use crate::{
    BINDER_COLLECTION, bindings::BinderCollection, hook, pstr_to_string,
    utils::logging::debug_print,
};

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
    let requested_path = unsafe { pstr_to_string(path) };
    debug_print(&format!(
        "[HOOK] register_file, path: {requested_path}, file_id: {file_id}, binder: {binder:?}"
    ));

    if file_id != -1 {
        return unsafe { CriLoader_Register_File.call(loader, binder, path, file_id, zero) };
    }

    let binder_collection = BINDER_COLLECTION.lock().expect("Mutex poisoned");

    let requested_path_sanitized = requested_path.replace('\\', "/").to_lowercase();

    let mod_file_arc_opt = binder_collection.mod_files.values().find(|mod_file_arc| {
        if let Ok(mod_file) = mod_file_arc.lock() {
            mod_file.relative_path.to_string_lossy().to_lowercase() == requested_path_sanitized
        } else {
            false
        }
    });

    if let Some(mod_file_arc) = mod_file_arc_opt {
        if let Ok(mod_file) = mod_file_arc.lock() {
            // Convert mod path to CString safely
            if let Ok(mod_path_cstr) =
                std::ffi::CString::new(mod_file.absolute_path.to_string_lossy().as_bytes())
            {
                debug_print(&format!(
                    "[HOOK] register_file redirecting {} -> {}",
                    requested_path,
                    mod_file.absolute_path.display()
                ));

                return unsafe {
                    CriLoader_Register_File.call(
                        loader,
                        binder,
                        mod_path_cstr.as_ptr() as PSTR,
                        file_id,
                        zero,
                    )
                };
            } else {
                debug_print("[HOOK] Failed to convert mod path to CString, using original path");
            }
        }
    } else {
        debug_print(&format!(
            "[HOOK] No mod override found for {}, falling back to original",
            requested_path
        ));
    }

    unsafe { CriLoader_Register_File.call(loader, binder, path, file_id, zero) }
}
