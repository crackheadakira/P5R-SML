use crate::bindings::BinderCollection;
use crate::utils::logging::{debug_print, error_message_box};
use crate::utils::{RawAllocator, SafeHandle, get_base_dir};
use once_cell::sync::Lazy;
use std::ffi::CStr;
use std::sync::Mutex;
use winapi::shared::minwindef::{BOOL, DWORD, HINSTANCE, LPVOID, TRUE};
use winapi::um::processthreadsapi::GetCurrentProcessId;
use winapi::um::winnt::DLL_PROCESS_ATTACH;

mod bindings;
mod cri_hooks;
mod spd;
mod utils;

pub static BINDER_COLLECTION: Lazy<Mutex<BinderCollection>> =
    Lazy::new(|| Mutex::new(BinderCollection::new()));

/// # Safety
/// This is the main entry of the .DLL file
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllMain(
    _hinst_dll: HINSTANCE,
    fdw_reason: DWORD,
    _lpv_reserved: LPVOID,
) -> BOOL {
    if fdw_reason == DLL_PROCESS_ATTACH {
        // 1. Immediately disable thread calls to save performance
        unsafe {
            winapi::um::libloaderapi::DisableThreadLibraryCalls(_hinst_dll);
        }

        // 2. SPAWN A THREAD.
        // We exit DllMain as fast as possible so the game can continue loading its own DLLs.
        std::thread::spawn(|| {
            if let Err(e) = initialize_loader() {
                error_message_box(
                    &format!("Initialization Error: {e}"),
                    "P5R Simple Mod Loader",
                );
            }
        });
    }

    TRUE // winapi TRUE is just 1
}

fn initialize_loader() -> Result<(), Box<dyn std::error::Error>> {
    let pid = unsafe { GetCurrentProcessId() };
    debug_print!("[P5R SML] version.dll proxy active (PID: {pid})");

    // Install hooks
    install_hooks()?;
    debug_print!("[P5R SML] All hooks installed successfully");

    // Get mod files
    let base_directory = get_base_dir();
    let mods_directory = base_directory.join("mods");

    // Ensure directory exists
    if !mods_directory.exists() {
        std::fs::create_dir_all(&mods_directory).ok();
    }

    // Load Binders
    {
        let mut binders = lock_or_log(&BINDER_COLLECTION, "DllMain");
        binders.load_mod_folder(&mods_directory);
    }

    // Load SPDs
    if let Ok(entries) = std::fs::read_dir(&mods_directory) {
        for entry in entries.flatten() {
            let mod_path = entry.path();
            if mod_path.is_dir() {
                spd::on_mod_loading(&mod_path);
            }
        }
    }

    debug_print!("[P5R SML] Mod initialization complete.");
    Ok(())
}

pub struct CpkBinding {
    alloc: RawAllocator,
    pub bind_id: u32,
    pub is_bound: bool,
}

impl CpkBinding {
    pub fn new(alloc: RawAllocator, bind_id: u32, is_bound: bool) -> Self {
        Self {
            alloc,
            bind_id,
            is_bound,
        }
    }

    pub fn work_mem_ptr(&self) -> SafeHandle {
        self.alloc.as_ptr()
    }
}

impl Drop for CpkBinding {
    fn drop(&mut self) {
        self.alloc.dispose();
    }
}

// Installs the detours
pub fn install_hooks() -> Result<(), Box<dyn std::error::Error>> {
    cri_hooks::loader::hook_register_file::register_hook()?;

    cri_hooks::binder::hook_bind_cpk::register_hook()?;
    cri_hooks::binder::hook_bind_file::register_hook()?;
    cri_hooks::binder::hook_bind_files::register_hook()?;
    cri_hooks::binder::hook_unbind::register_hook()?;
    cri_hooks::binder::hook_find::register_hook()?;

    cri_hooks::binder::hook_get_size_for_bind_files::register_hook()?;
    cri_hooks::binder::hook_get_status::register_hook()?;
    cri_hooks::binder::hook_set_priority::register_hook()?;

    cri_hooks::io::hook_open::register_hook()?;
    cri_hooks::io::hook_exists::register_hook()?;

    // spd::hook_spd_load::register_hook()?;
    spd::hook_spd_tick::register_hook()?;

    Ok(())
}

pub unsafe fn pstr_to_string(pstr: *const i8) -> String {
    if pstr.is_null() {
        return String::new();
    }
    let cstr = unsafe { CStr::from_ptr(pstr) };
    cstr.to_string_lossy().into_owned()
}

pub fn lock_or_log<'a, T>(mutex: &'a Mutex<T>, context: &str) -> std::sync::MutexGuard<'a, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            debug_print!("[MUTEX POISONED] {context} mutex was poisoned");
            poisoned.into_inner()
        }
    }
}
