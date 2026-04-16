pub mod binder;
pub mod io;
pub mod loader;

pub use binder::CriBinderStatus;
use serde::Deserialize;

use crate::{debug_print, scanner::patch_memory};

#[macro_export]
macro_rules! hook {
    ($fn_type:ty, $detour:ident, $addr:expr, $handler:ident) => {
        let fn_ptr: $fn_type = std::mem::transmute($addr);
        $detour.initialize(fn_ptr, $handler)?.enable()?;
        debug_print!(concat!("[P5R SML] ", stringify!($detour), " enabled"));
    };
}

#[repr(i32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CriError {
    /// Succeeded.
    Success = 0,

    /// General failure.
    Failure = -1,

    /// Invalid argument.
    InvalidParameter = -2,

    /// Failed to allocate memory.
    FailedToAllocateMemory = -3,

    /// Parallel execution of thread-unsafe function.
    UnsafeFunctionCall = -4,

    /// Function not implemented.
    FunctionNotImplemented = -5,

    /// Library not initialized.
    LibraryNotInitialized = -6,

    /// Invalid INT was passed as CriStatus
    Unknown = -7,
}

impl From<i32> for CriError {
    fn from(value: i32) -> Self {
        match value {
            0 => CriError::Success,
            -1 => CriError::Failure,
            -2 => CriError::InvalidParameter,
            -3 => CriError::FailedToAllocateMemory,
            -4 => CriError::UnsafeFunctionCall,
            -5 => CriError::FunctionNotImplemented,
            -6 => CriError::LibraryNotInitialized,
            _ => CriError::Unknown,
        }
    }
}

impl From<CriError> for i32 {
    fn from(err: CriError) -> Self {
        err as i32
    }
}

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

pub fn initialize_dynamic_hooks(memory: &'static [u8]) -> Result<(), Box<dyn std::error::Error>> {
    let base_dir = crate::utils::get_base_dir();
    let config_path = base_dir.join("SML_Hooks.json");

    let json_str = std::fs::read_to_string(&config_path)?;

    let config: Config = serde_json::from_str(&json_str)?;

    for hook_def in config.hooks {
        let signature = crate::scanner::Signature::parse(&hook_def.pattern)?;

        unsafe {
            if let Some(found_addr) = crate::scanner::scan_memory(memory, &signature) {
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
