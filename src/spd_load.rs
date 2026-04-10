use retour::static_detour;
use winapi::shared::ntdef::{INT, PSTR};

use crate::{hook, pstr_to_string, utils::logging::debug_print};

use super::spd::patch_spd_bytes;

const SPD_LOAD_ADDR: usize = 0x152ce1610;

static_detour! {
    static Spd_Load: unsafe extern "system" fn(PSTR, *mut u8, INT) -> INT;
}

type FnSpdLoad = unsafe extern "system" fn(PSTR, *mut u8, INT) -> INT;

/// Intercepts the SPD load function.
///
/// ## Arguments
/// * `path`  - Relative path of the SPD being loaded, e.g. `"title/title_logo.spd"`.
/// * `bytes` - Pointer to the raw SPD bytes already loaded from the CPK into game memory.
/// * `size`  - Size of the buffer in bytes.
fn hook_impl(path: PSTR, bytes: *mut u8, size: INT) -> INT {
    if path.is_null() || bytes.is_null() || size <= 0 {
        return unsafe { Spd_Load.call(path, bytes, size) };
    }

    let path_str = unsafe { pstr_to_string(path) };

    let normalised = path_str
        .replace('\\', "/")
        .to_ascii_lowercase()
        .trim_start_matches('/')
        .to_string();

    let buf = unsafe { std::slice::from_raw_parts_mut(bytes, size as usize) };

    // Verify SPR0 magic
    if buf.len() >= 4 && &buf[0..4] == b"SPR0" {
        if let Some(n_patched) = patch_spd_bytes(&normalised, buf) {
            debug_print(&format!(
                "[SpdLoad] Patched {n_patched} sprite(s) in '{path_str}'"
            ));
        }
    }

    unsafe { Spd_Load.call(path, bytes, size) }
}

pub fn register_hook() -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        hook!(FnSpdLoad, Spd_Load, SPD_LOAD_ADDR, hook_impl);
    }
    Ok(())
}
