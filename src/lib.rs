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

/// # Safety
/// This is the main entry of the .DLL file
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllMain(
    _hinst_dll: HINSTANCE,
    fdw_reason: u32,
    _lpv_reserved: *const c_void,
) -> BOOL {
    if fdw_reason == DLL_PROCESS_ATTACH {
        if let Err(e) = install_hooks() {
            error_message_box(&format!("Hook Install Error: {e}"), "P5R SML");
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
    let memory = scanner::get_main_module_memory().ok_or("Failed to get module memory bounds")?;

    hooks::binder::register_all_binder_hooks(memory)?;
    hooks::io::register_all_io_hooks(memory)?;
    hooks::loader::register_all_loader_hooks(memory)?;

    initialize_dynamic_hooks(memory)?;

    debug_print!("[P5R SML] All hooks installed successfully");

    Ok(())
}

#[cfg(target_env = "gnu")]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DirectInput8Create(
    h_inst: *mut c_void,
    dw_version: u32,
    riid: *const c_void,
    out_ptr: *mut *mut c_void,
    outer: *mut c_void,
) -> i32 {
    use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
    use windows::core::PCSTR;

    type FnDirectInput8Create = unsafe extern "system" fn(
        *mut c_void,
        u32,
        *const c_void,
        *mut *mut c_void,
        *mut c_void,
    ) -> i32;

    static REAL_FUNC: std::sync::OnceLock<FnDirectInput8Create> = std::sync::OnceLock::new();

    let func = REAL_FUNC.get_or_init(|| {
        let system_path = "C:\\Windows\\System32\\dinput8.dll\0";
        let h_module = unsafe { LoadLibraryA(PCSTR(system_path.as_ptr())) }
            .expect("Failed to load system dinput8.dll");

        let proc_name = "DirectInput8Create\0";
        let addr = unsafe { GetProcAddress(h_module, PCSTR(proc_name.as_ptr())) }
            .expect("Could not find DirectInput8Create in system dinput8.dll");

        unsafe { std::mem::transmute(addr) }
    });

    unsafe { func(h_inst, dw_version, riid, out_ptr, outer) }
}
