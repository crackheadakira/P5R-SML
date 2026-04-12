use std::os::windows::raw::HANDLE;

use crate::{
    utils::pstr_to_string,
    vfs::{pac::patch_pac, spd::patch_spd},
};

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
