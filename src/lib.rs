#![feature(stmt_expr_attributes)]

use crate::bindings::BinderCollection;
use crate::scanner::{parse_pattern, patch_memory, scan_main_module};
use crate::utils::logging::{debug_print, error_message_box};
use crate::utils::{RawAllocator, SafeHandle, get_base_dir};
use once_cell::sync::Lazy;
use serde::Deserialize;
use std::ffi::{CStr, c_void};
use std::sync::Mutex;
use windows::Win32::Foundation::HINSTANCE;
use windows::Win32::System::LibraryLoader::{DisableThreadLibraryCalls, GetModuleHandleA};
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows::Win32::System::Threading::GetCurrentProcessId;
use windows::core::{BOOL, PCSTR, PSTR};

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
    if GetModuleHandleA(PCSTR(c"P5R.exe".as_ptr() as *const u8)).is_ok() {
        TargetGame::P5R
    } else if GetModuleHandleA(PCSTR(c"P4G.exe".as_ptr() as *const u8)).is_ok() {
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

pub trait AsRawI8Ptr {
    fn as_raw_i8_ptr(&self) -> *const i8;
}

impl AsRawI8Ptr for PSTR {
    fn as_raw_i8_ptr(&self) -> *const i8 {
        self.as_ptr() as _
    }
}

impl AsRawI8Ptr for PCSTR {
    fn as_raw_i8_ptr(&self) -> *const i8 {
        self.as_ptr() as _
    }
}

impl AsRawI8Ptr for *const i8 {
    fn as_raw_i8_ptr(&self) -> *const i8 {
        *self
    }
}

impl AsRawI8Ptr for *mut i8 {
    fn as_raw_i8_ptr(&self) -> *const i8 {
        *self as _
    }
}

impl AsRawI8Ptr for *mut u8 {
    fn as_raw_i8_ptr(&self) -> *const i8 {
        *self as _
    }
}

pub unsafe fn pstr_to_string<T: AsRawI8Ptr>(ptr: T) -> String {
    let raw_ptr = ptr.as_raw_i8_ptr();
    if raw_ptr.is_null() {
        return String::new();
    }

    unsafe { CStr::from_ptr(raw_ptr).to_string_lossy().into_owned() }
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
