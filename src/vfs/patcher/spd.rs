use std::{collections::HashMap, sync::RwLock};

use once_cell::sync::Lazy;

use crate::{
    debug_print,
    formats::spd::{SpdModFile, builder::build_patched_spd},
    vfs::game_alloc,
};

pub static SPD_MODS: Lazy<RwLock<HashMap<String, SpdModFile>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

const USERDATA_SIZE_OFFSET: usize = 0x88;
const USERDATA_PTR_OFFSET: usize = 0x98;

#[inline(always)]
pub(super) fn patch_spd(key: &str, orig_buf: *mut u8, orig_size: usize, userdata: usize) {
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
