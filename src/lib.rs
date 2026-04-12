#![feature(stmt_expr_attributes)]

use crate::bindings::BinderCollection;
use crate::scanner::{parse_pattern, patch_memory, scan_main_module};
use crate::utils::logging::{debug_print, error_message_box};
use crate::utils::{RawAllocator, SafeHandle, get_base_dir};
use once_cell::sync::Lazy;
use serde::Deserialize;
use std::ffi::CStr;
use std::sync::Mutex;
use winapi::shared::minwindef::{BOOL, DWORD, FALSE, HINSTANCE, LPVOID, TRUE};
use winapi::um::processthreadsapi::GetCurrentProcessId;
use winapi::um::winnt::DLL_PROCESS_ATTACH;

mod bindings;
mod cri_hooks;
mod pac;
pub mod scanner;
mod spd;
mod utils;
pub mod vfs;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetGame {
    P5R,
    P4G,
    Unknown,
}

pub static CURRENT_GAME: Lazy<TargetGame> = Lazy::new(|| unsafe {
    if winapi::um::libloaderapi::GetModuleHandleA(b"P5R.exe\0".as_ptr() as *const i8)
        != std::ptr::null_mut()
    {
        TargetGame::P5R
    } else if winapi::um::libloaderapi::GetModuleHandleA(b"P4G.exe\0".as_ptr() as *const i8)
        != std::ptr::null_mut()
    {
        TargetGame::P4G
    } else {
        TargetGame::Unknown
    }
});

pub static BINDER_COLLECTION: Lazy<Mutex<BinderCollection>> =
    Lazy::new(|| Mutex::new(BinderCollection::new()));

#[derive(Deserialize)]
struct Config {
    hooks: Vec<HookConfig>,
}

#[derive(Deserialize)]
struct HookConfig {
    name: String,
    pattern: String,
    offset: isize,
    #[serde(rename = "type")]
    hook_type: String,
    patch_bytes: Option<String>,
}

pub fn initialize_dynamic_hooks() -> Result<(), Box<dyn std::error::Error>> {
    let base_dir = crate::utils::get_base_dir();
    let config_path = base_dir.join("SML_Hooks.json");

    let json_str = std::fs::read_to_string(&config_path)?;

    let config: Config = serde_json::from_str(&json_str)?;

    for hook_def in config.hooks {
        let pattern = parse_pattern(&hook_def.pattern);

        unsafe {
            if let Some(found_addr) = scan_main_module(&pattern) {
                let target_addr = found_addr.offset(hook_def.offset);

                debug_print!("[SCANNER] Found {} at {:?}", hook_def.name, target_addr);

                match hook_def.hook_type.as_str() {
                    "BytePatch" => {
                        if let Some(bytes_str) = &hook_def.patch_bytes {
                            let bytes_to_write: Vec<u8> = bytes_str
                                .split_whitespace()
                                .filter_map(|b| u8::from_str_radix(b, 16).ok())
                                .collect();

                            patch_memory(target_addr, &bytes_to_write);
                        }
                    }
                    _ => debug_print!("[SCANNER] Unknown hook type: {}", hook_def.hook_type),
                }
            } else {
                debug_print!(
                    "[SCANNER] ERROR: Could not find pattern for {}",
                    hook_def.name
                );
            }
        }
    }

    Ok(())
}

/// # Safety
/// This is the main entry of the .DLL file
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllMain(
    _hinst_dll: HINSTANCE,
    fdw_reason: DWORD,
    _lpv_reserved: LPVOID,
) -> BOOL {
    if fdw_reason == DLL_PROCESS_ATTACH {
        unsafe {
            winapi::um::libloaderapi::DisableThreadLibraryCalls(_hinst_dll);
        }

        if let Err(e) = install_hooks() {
            error_message_box(&format!("Hook Error: {e}"), "P5R SML");
            return FALSE;
        }

        std::thread::spawn(|| {
            if let Err(e) = initialize_loader() {
                error_message_box(&format!("Mod Loading Error: {e}"), "P5R SML");
            }
        });
    }

    TRUE
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
        let mut binders = lock_or_log(&BINDER_COLLECTION, "DllMain");
        binders.load_mod_folder(&mods_directory);
    }

    if let Ok(entries) = std::fs::read_dir(&mods_directory) {
        for entry in entries.flatten() {
            let mod_path = entry.path();
            if mod_path.is_dir() {
                spd::on_mod_loading(&mod_path);
                pac::on_mod_loading(&mod_path);
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

    initialize_dynamic_hooks()?;

    debug_print!("[P5R SML] All hooks installed successfully");

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
