use std::os::windows::raw::HANDLE;

use crate::{
    pac::PAC_MODS,
    pstr_to_string,
    spd::{SPD_MODS, hook_spd_tick::game_alloc, spd_builder::build_patched_spd},
    utils::logging::debug_print,
};

const USERDATA_SIZE_OFFSET: usize = 0x88;
const USERDATA_PTR_OFFSET: usize = 0x98;

pub unsafe fn apply_vfs_patches(loader: HANDLE, userdata: usize) {
    let base = loader as *mut u8;
    let inner = unsafe { *(base.add(0x108) as *const usize) } as *mut u8;

    if inner.is_null() {
        return;
    }

    let orig_buf = unsafe { *(inner.add(0x78) as *const usize) } as *mut u8;
    let orig_size = unsafe { *(inner.add(0x6c) as *const i32) } as usize;

    if orig_buf.is_null() || orig_size < 4 {
        return;
    }

    let path_ptr = unsafe { *(inner.add(0x148) as *const usize) } as *const i8;
    if path_ptr.is_null() {
        return;
    }

    let path_str = unsafe { pstr_to_string(path_ptr) };
    let normalized_path = path_str.replace('\\', "/");
    let key = std::path::Path::new(&normalized_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(&normalized_path)
        .to_ascii_lowercase();

    let extension = std::path::Path::new(&key)
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("");

    match extension {
        "spd" => patch_spd(&key, orig_buf, orig_size, userdata),
        "pac" | "pak" | "bin" => patch_pac(&key, orig_buf, orig_size, userdata, base, inner),
        _ => {}
    }
}

#[inline(always)]
fn patch_spd(key: &str, orig_buf: *mut u8, orig_size: usize, userdata: usize) {
    if unsafe { std::slice::from_raw_parts(orig_buf, 4) } != b"SPR0" {
        return;
    }

    let mods_lock = SPD_MODS.read().unwrap();
    let Some(mods) = mods_lock.get(key) else {
        return;
    };

    let original = unsafe { std::slice::from_raw_parts(orig_buf, orig_size) };
    let Some(patched) = build_patched_spd(original, mods) else {
        return;
    };

    let new_buf = game_alloc(patched.len());
    if new_buf.is_null() {
        return;
    }

    unsafe { std::ptr::copy_nonoverlapping(patched.as_ptr(), new_buf, patched.len()) };

    let gpu_size_loc = (userdata + USERDATA_SIZE_OFFSET) as *mut u32;
    let gpu_ptr_loc = (userdata + USERDATA_PTR_OFFSET) as *mut u64;

    unsafe {
        *gpu_size_loc = patched.len() as u32;
        *gpu_ptr_loc = new_buf as u64;
    }

    debug_print!("[SML] Patched SPD: {key}");
}

#[inline(always)]
fn patch_pac(
    key: &str,
    orig_buf: *mut u8,
    orig_size: usize,
    userdata: usize,
    base: *mut u8,
    inner: *mut u8,
) {
    let mods_lock = PAC_MODS.read().unwrap();
    let Some(mods) = mods_lock.get(key) else {
        return;
    };

    let original = unsafe { std::slice::from_raw_parts(orig_buf, orig_size) };
    let Some(patched) = crate::pac::pac_builder::build_patched_pac(original, mods) else {
        return;
    };

    if patched.len() <= orig_size {
        unsafe {
            std::ptr::copy_nonoverlapping(patched.as_ptr(), orig_buf, patched.len());
            *(inner.add(0x6c) as *mut i32) = patched.len() as i32;
        }

        debug_print!(
            "[SML] Direct overwrite successful for PAC: {} ({} -> {} bytes)",
            key,
            orig_size,
            patched.len()
        );
        return;
    }

    // This branch is untested in-game

    let new_buf = game_alloc(patched.len());
    if new_buf.is_null() {
        return;
    }

    unsafe { std::ptr::copy_nonoverlapping(patched.as_ptr(), new_buf, patched.len()) };

    let old_ptr = orig_buf as u64;
    let new_ptr = new_buf as u64;
    let old_size = orig_size as u32;
    let new_size = patched.len() as u32;

    unsafe {
        *(inner.add(0x78) as *mut u64) = new_ptr;
        *(inner.add(0x80) as *mut u64) = new_ptr;
        *(inner.add(0x6c) as *mut i32) = new_size as i32;

        let outer_buf_ptr = base.add(0x1c8) as *mut u64;
        *outer_buf_ptr = new_ptr;
    }

    if userdata != 0 {
        for offset in (0..0x150).step_by(8) {
            let loc = (userdata + offset) as *mut u64;

            unsafe {
                if *loc == old_ptr {
                    *loc = new_ptr;
                }
            }
        }
        for offset in (0..0x150).step_by(4) {
            let loc = (userdata + offset) as *mut u32;

            unsafe {
                if *loc == old_size {
                    *loc = new_size;
                }
            }
        }
    }

    debug_print!("[SML] Patched PAC (Reallocated): {}", key);
}
