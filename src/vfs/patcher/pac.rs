use std::{collections::HashMap, sync::RwLock};

use once_cell::sync::Lazy;

use crate::{
    debug_print,
    formats::pac::{PacModFiles, builder::build_patched_pac},
    vfs::game_alloc,
};

pub static PAC_MODS: Lazy<RwLock<HashMap<String, PacModFiles>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

#[inline(always)]
pub(super) fn patch_pac(
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
    let Some(patched) = build_patched_pac(original, mods) else {
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
