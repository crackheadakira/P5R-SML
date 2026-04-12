#![feature(stmt_expr_attributes)]

use std::ffi::c_void;
use windows::{
    Win32::{
        Foundation::HINSTANCE,
        System::{
            LibraryLoader::DisableThreadLibraryCalls, SystemServices::DLL_PROCESS_ATTACH,
            Threading::GetCurrentProcessId,
        },
    },
    core::BOOL,
};

use crate::{
    hooks::initialize_dynamic_hooks,
    utils::{error_message_box, get_base_dir},
    vfs::BINDER_COLLECTION,
};

mod formats;
mod hooks;
mod scanner;
mod utils;
mod vfs;

pub use crate::_debug_print_impl as debug_print;

/// # Safety
/// This is the main entry of the .DLL file
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllMain(
    _hinst_dll: HINSTANCE,
    fdw_reason: u32,
    _lpv_reserved: *const c_void,
) -> BOOL {
    if fdw_reason == DLL_PROCESS_ATTACH {
        if let Err(e) = unsafe { DisableThreadLibraryCalls(_hinst_dll.into()) } {
            error_message_box(&format!("Hook Error: {e}"), "P5R SML");
            return false.into();
        }

        if let Err(e) = install_hooks() {
            error_message_box(&format!("Hook Error: {e}"), "P5R SML");
            return false.into();
        }

        std::thread::spawn(|| {
            if let Err(e) = initialize_loader() {
                error_message_box(&format!("Mod Loading Error: {e}"), "P5R SML");
            }
        });
    }

    true.into()
}

fn initialize_loader() -> Result<(), Box<dyn std::error::Error>> {
    let pid = unsafe { GetCurrentProcessId() };
    debug_print!("[P5R SML] version.dll proxy active (PID: {pid})");

    let base_directory = get_base_dir();
    let mods_directory = base_directory.join("mods");

    if !mods_directory.exists() {
        std::fs::create_dir_all(&mods_directory).ok();
    }

    {
        let mut binders = utils::lock_or_log(&BINDER_COLLECTION, "DllMain");
        binders.load_mod_folder(&mods_directory);
    }

    if let Ok(entries) = std::fs::read_dir(&mods_directory) {
        for entry in entries.flatten() {
            let mod_path = entry.path();
            if mod_path.is_dir() {
                formats::spd::on_mod_loading(&mod_path);
                formats::pac::on_mod_loading(&mod_path);
            }
        }
    }

    debug_print!("[P5R SML] Mod initialization complete.");
    Ok(())
}

// Installs the detours
pub fn install_hooks() -> Result<(), Box<dyn std::error::Error>> {
    hooks::binder::register_all_binder_hooks()?;
    hooks::io::register_all_io_hooks()?;
    hooks::loader::register_all_loader_hooks()?;

    initialize_dynamic_hooks()?;

    debug_print!("[P5R SML] All hooks installed successfully");

    Ok(())
}
