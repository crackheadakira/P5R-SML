use std::ffi::c_void;

use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Memory::{
    PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, VirtualProtect,
};
use windows::Win32::System::ProcessStatus::{GetModuleInformation, MODULEINFO};
use windows::Win32::System::Threading::GetCurrentProcess;

use crate::utils::logging::debug_print;

/// Converts "E8 ?? ?? 48" into [Some(0xE8), None, None, Some(0x48)]
pub fn parse_pattern(signature: &str) -> Vec<Option<u8>> {
    signature
        .split_whitespace()
        .map(|byte_str| {
            if byte_str == "??" || byte_str == "?" {
                None
            } else {
                u8::from_str_radix(byte_str, 16).ok()
            }
        })
        .collect()
}

pub unsafe fn scan_main_module(pattern: &[Option<u8>]) -> Option<*mut u8> {
    let module = unsafe { GetModuleHandleW(None).ok() }?;

    let mut module_info = MODULEINFO::default();
    let process = unsafe { GetCurrentProcess() };

    (unsafe {
        GetModuleInformation(
            process,
            module,
            &mut module_info,
            std::mem::size_of::<MODULEINFO>() as u32,
        )
        .ok()
    })?;

    let base_addr = module_info.lpBaseOfDll as *const u8;
    let size = module_info.SizeOfImage as usize;

    let memory_slice = unsafe { std::slice::from_raw_parts(base_addr, size) };

    for i in 0..(size - pattern.len()) {
        let mut found = true;
        for (j, &sig_byte) in pattern.iter().enumerate() {
            if let Some(b) = sig_byte
                && memory_slice[i + j] != b
            {
                found = false;
                break;
            }
        }

        if found {
            return Some(unsafe { base_addr.add(i) } as *mut u8);
        }
    }

    None
}

pub unsafe fn patch_memory(target_addr: *mut u8, patch_bytes: &[u8]) {
    let mut old_protect = PAGE_PROTECTION_FLAGS(0);
    let size = patch_bytes.len();

    if unsafe {
        VirtualProtect(
            target_addr as *const c_void,
            size,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )
        .is_ok()
    } {
        unsafe { std::ptr::copy_nonoverlapping(patch_bytes.as_ptr(), target_addr, size) };

        let mut dummy = PAGE_PROTECTION_FLAGS(0);
        let _ =
            unsafe { VirtualProtect(target_addr as *const c_void, size, old_protect, &mut dummy) };

        debug_print!(
            "[SCANNER] Successfully wrote {} bytes at {:?}",
            size,
            target_addr
        );
    } else {
        debug_print!(
            "[SCANNER] ERROR: Failed to unprotect memory at {:?}",
            target_addr
        );
    }
}
