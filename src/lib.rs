use crate::bindings::BinderCollection;
use crate::utils::logging::{debug_print, error_message_box};
use crate::utils::{RawAllocator, SafeHandle, get_base_dir};
use once_cell::sync::Lazy;
use std::ffi::{CStr, CString};
use std::path::PathBuf;
use std::sync::Mutex;
use winapi::shared::minwindef::HINSTANCE;
use winapi::shared::minwindef::{BOOL, DWORD, LPVOID};
use winapi::um::processthreadsapi::GetCurrentProcessId;
use winapi::um::winnt::DLL_PROCESS_ATTACH;

mod bindings;
mod cri_hooks;
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
    if fdw_reason != DLL_PROCESS_ATTACH {
        return BOOL::from(true);
    }

    unsafe {
        winapi::um::libloaderapi::DisableThreadLibraryCalls(_hinst_dll);

        if let Err(e) = install_hooks() {
            error_message_box(&format!("{e}"), "Persona 5 Mod Loader");
            return BOOL::from(false);
        }
    }

    let pid = unsafe { GetCurrentProcessId() };
    debug_print(&format!("[P5 SML] Injected into process with PID: {pid}"));
    debug_print("[P5 SML] Hooks installed successfully");

    // get mod files
    let base_directory = get_base_dir();
    let mods_directory = base_directory.join("mods");

    let mut binders = BINDER_COLLECTION.lock().expect("Mutex was poisoned");
    binders.load_mod_folder(&mods_directory);

    BOOL::from(true)
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

    cri_hooks::binder::hook_get_size_for_bind_files::register_hook()?;
    cri_hooks::binder::hook_get_status::register_hook()?;
    cri_hooks::binder::hook_set_priority::register_hook()?;

    cri_hooks::io::hook_open::register_hook()?;
    cri_hooks::io::hook_exists::register_hook()?;

    Ok(())
}

pub unsafe fn pstr_to_string(pstr: *const i8) -> String {
    if pstr.is_null() {
        return String::new();
    }
    let cstr = unsafe { CStr::from_ptr(pstr) };
    cstr.to_string_lossy().into_owned()
}
