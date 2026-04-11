use std::collections::HashMap;
use std::sync::RwLock;

use once_cell::sync::Lazy;
use retour::static_detour;
use winapi::shared::ntdef::HANDLE;

use crate::spd::SPD_MODS;
use crate::spd::spd_builder::{SpdModFiles, build_patched_spd};
use crate::{hook, lock_or_log, utils::logging::debug_print};

const CRI_LOADER_TICK_ADDR: usize = 0x140467930;
const GAME_ALLOC_ADDR: usize = 0x14017bc70;

const USERDATA_SIZE_OFFSET: usize = 0x88;
const USERDATA_PTR_OFFSET: usize = 0x98;

static_detour! {
    static Cri_Loader_Tick: unsafe extern "system" fn(HANDLE) -> u8;
}

type FnCriLoaderTick = unsafe extern "system" fn(HANDLE) -> u8;
type FnGameAlloc = unsafe extern "system" fn(usize) -> *mut u8;
type FnCompletionCallback = unsafe extern "system" fn(usize, HANDLE);

pub static ORIGINAL_CALLBACKS: Lazy<RwLock<HashMap<usize, FnCompletionCallback>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

fn game_alloc(size: usize) -> *mut u8 {
    unsafe {
        let f: FnGameAlloc = std::mem::transmute(GAME_ALLOC_ADDR);
        f(size)
    }
}

unsafe extern "system" fn intercepted_callback(userdata: usize, loader: HANDLE) {
    unsafe {
        let base = loader as *mut u8;
        let inner = *(base.add(0x108) as *const usize) as *mut u8;

        let orig_cb = {
            let mut lock = ORIGINAL_CALLBACKS.write().unwrap();
            match lock.remove(&(loader as usize)) {
                Some(cb) => cb,
                None => return,
            }
        };

        let orig_buf = *(inner.add(0x78) as *const usize) as *mut u8;
        let orig_size = *(inner.add(0x6c) as *const i32) as usize;
        let outer_buf_ptr = base.add(0x1c8) as *mut u64;
        let orig_outer_buf = *outer_buf_ptr;

        if orig_buf.is_null() || orig_size < 4 {
            return orig_cb(userdata, loader);
        }
        if std::slice::from_raw_parts(orig_buf, 4) != b"SPR0" {
            return orig_cb(userdata, loader);
        }

        let path_ptr = *(inner.add(0x148) as *const usize) as *const i8;
        if path_ptr.is_null() {
            return orig_cb(userdata, loader);
        }

        let path_str = crate::pstr_to_string(path_ptr);
        let key = std::path::Path::new(&path_str)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(&path_str)
            .to_ascii_lowercase();

        if !key.ends_with(".spd") {
            return orig_cb(userdata, loader);
        }

        let has_mod = {
            let mods = lock_or_log(&SPD_MODS, "SpdTick, has_mod");
            mods.contains_key(&key)
        };
        if !has_mod {
            return orig_cb(userdata, loader);
        }

        let original = std::slice::from_raw_parts(orig_buf as *const u8, orig_size);
        let mod_files = {
            let mods = lock_or_log(&SPD_MODS, "SpdTick, mod_files");
            match mods.get(&key) {
                Some(m) => SpdModFiles {
                    dds_files: m.dds_files.clone(),
                    spdspr_files: m.spdspr_files.clone(),
                },
                None => return orig_cb(userdata, loader),
            }
        };

        if let Some(patched) = build_patched_spd(original, &mod_files) {
            // 1. Allocate using the game's allocator for 16-byte alignment and safe async freeing
            let new_buf = game_alloc(patched.len());
            if new_buf.is_null() {
                debug_print!("[SpdTick] game_alloc failed for {key}");
                return orig_cb(userdata, loader);
            }

            std::ptr::copy_nonoverlapping(patched.as_ptr(), new_buf, patched.len());
            let new_ptr = new_buf as u64;
            let new_size = patched.len();

            let old_ptr_val = orig_buf as u64;
            let old_sz32 = orig_size as u32;

            *(inner.add(0x78) as *mut u64) = new_ptr;
            *(inner.add(0x80) as *mut u64) = new_ptr;
            *(inner.add(0x6c) as *mut i32) = new_size as i32;
            *outer_buf_ptr = new_ptr;

            if userdata != 0 {
                let gpu_size_loc = (userdata + USERDATA_SIZE_OFFSET) as *mut u32;
                let gpu_ptr_loc = (userdata + USERDATA_PTR_OFFSET) as *mut u64;

                if *gpu_size_loc == old_sz32 && *gpu_ptr_loc == old_ptr_val {
                    *gpu_size_loc = new_size as u32;
                    *gpu_ptr_loc = new_ptr;
                    debug_print!("[SpdTick] Performed struct swap for {key}");
                } else {
                    debug_print!(
                        "[SpdTick] WARNING: Shadow offsets did not match expected values for {key}"
                    );
                }
            }

            debug_print!(
                "[SpdTick] Firing callback with game_alloc buffer ({orig_size} -> {new_size})"
            );

            orig_cb(userdata, loader);

            *(inner.add(0x78) as *mut u64) = old_ptr_val;
            *(inner.add(0x80) as *mut u64) = old_ptr_val;
            *(inner.add(0x6c) as *mut i32) = orig_size as i32;
            *outer_buf_ptr = orig_outer_buf;

            debug_print!("[SpdTick] Restored CRI pointers. Texture replacement complete for {key}",);
            return;
        }

        orig_cb(userdata, loader);
    }
}

fn hook_impl(loader: HANDLE) -> u8 {
    let base = loader as *mut u8;

    unsafe {
        let cb_ptr = base.add(0x158) as *mut FnCompletionCallback;
        let current_cb = *cb_ptr;

        if (current_cb as usize) != 0
            && (current_cb as usize) != (intercepted_callback as *const () as usize)
        {
            ORIGINAL_CALLBACKS
                .write()
                .unwrap()
                .insert(loader as usize, current_cb);
            *cb_ptr = intercepted_callback;
        }
    }

    // Call the original game tick
    unsafe { Cri_Loader_Tick.call(loader) }
}

pub fn register_hook() -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        hook!(
            FnCriLoaderTick,
            Cri_Loader_Tick,
            CRI_LOADER_TICK_ADDR,
            hook_impl
        );
    }
    Ok(())
}
