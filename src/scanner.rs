use std::ffi::c_void;

use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Memory::{
    PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, VirtualProtect,
};
use windows::Win32::System::ProcessStatus::{GetModuleInformation, MODULEINFO};
use windows::Win32::System::Threading::GetCurrentProcess;

use crate::debug_print;

pub struct Signature {
    pub pattern: Vec<u8>,
    pub mask: Vec<bool>,
    pub first_byte_idx: usize,
    pub first_byte_val: u8,
}

impl Signature {
    pub fn parse(signature: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mut pattern = Vec::new();
        let mut mask = Vec::new();

        for byte_str in signature.split_whitespace() {
            if byte_str == "??" || byte_str == "?" {
                pattern.push(0);
                mask.push(false);
            } else {
                pattern.push(u8::from_str_radix(byte_str, 16).unwrap_or(0));
                mask.push(true);
            }
        }

        let mut first_byte_idx = 0;
        let mut first_byte_val = 0;
        let mut found = false;

        for i in 0..pattern.len() {
            if mask[i] {
                first_byte_idx = i;
                first_byte_val = pattern[i];
                found = true;
                break;
            }
        }

        if !found {
            debug_print!("[SCANNER] Signature contains only wildcards");
            return Err("[SCANNER] Signature contains only wildcards".into());
        }

        Ok(Self {
            pattern,
            mask,
            first_byte_idx,
            first_byte_val,
        })
    }
}

#[inline(always)]
fn is_match(data: &[u8], pattern: &[u8], mask: &[bool]) -> bool {
    for i in 0..pattern.len() {
        if mask[i] && data[i] != pattern[i] {
            return false;
        }
    }
    true
}

pub fn get_main_module_memory() -> Option<&'static [u8]> {
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

    Some(unsafe { std::slice::from_raw_parts(base_addr, size) })
}

pub unsafe fn scan_memory(memory: &[u8], signature: &Signature) -> Option<*mut u8> {
    let size = memory.len();
    let pat_len = signature.pattern.len();

    if size < pat_len {
        return None;
    }

    let search_limit = size - pat_len;
    let mut current_pos = 0;

    while current_pos <= search_limit {
        let remaining_mem = &memory[current_pos..];

        if let Some(hit) = remaining_mem
            .iter()
            .position(|&b| b == signature.first_byte_val)
        {
            let start_index = current_pos + hit;

            if start_index < signature.first_byte_idx {
                current_pos += hit + 1;
                continue;
            }

            let match_start = start_index - signature.first_byte_idx;

            if match_start + pat_len > size {
                break;
            }

            if is_match(&memory[match_start..], &signature.pattern, &signature.mask) {
                return Some(unsafe { memory.as_ptr().add(match_start) } as *mut u8);
            }

            current_pos += hit + 1;
        } else {
            break;
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

        debug_print!("[SCANNER] Successfully wrote {size} bytes at {target_addr:?}");
    } else {
        debug_print!("[SCANNER] ERROR: Failed to unprotect memory at {target_addr:?}");
    }
}
