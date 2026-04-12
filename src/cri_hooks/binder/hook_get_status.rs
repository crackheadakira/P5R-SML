use std::fmt;

use retour::static_detour;

use crate::{
    hook,
    scanner::{parse_pattern, scan_main_module},
    utils::logging::debug_print,
};

static_detour! {
    static Cri_Binder_Get_Status: unsafe extern "system" fn(u32, *mut i32) -> CriBinderStatus;
}

type FnCriBinderGetStatus = unsafe extern "system" fn(u32, *mut i32) -> CriBinderStatus;

#[repr(i32)]
#[derive(Debug)]
pub enum CriBinderStatus {
    None,
    Analyze,
    Complete,
    Unbind,
    Removed,
    Invalid,
    Error,

    Unknown,
}

impl From<i32> for CriBinderStatus {
    fn from(value: i32) -> Self {
        match value {
            0 => CriBinderStatus::None,
            1 => CriBinderStatus::Analyze,
            2 => CriBinderStatus::Complete,
            3 => CriBinderStatus::Unbind,
            4 => CriBinderStatus::Removed,
            5 => CriBinderStatus::Invalid,
            6 => CriBinderStatus::Error,
            _ => CriBinderStatus::Unknown,
        }
    }
}

impl From<CriBinderStatus> for i32 {
    fn from(err: CriBinderStatus) -> Self {
        err as i32
    }
}

impl fmt::Display for CriBinderStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            CriBinderStatus::None => "None",
            CriBinderStatus::Analyze => "Analyze",
            CriBinderStatus::Complete => "Complete",
            CriBinderStatus::Unbind => "Unbind",
            CriBinderStatus::Removed => "Removed",
            CriBinderStatus::Invalid => "Invalid",
            CriBinderStatus::Error => "Error",
            CriBinderStatus::Unknown => "Unknown",
        };
        write!(f, "{}", s)
    }
}

pub fn hook_impl(binder_id: u32, status: *mut i32) -> CriBinderStatus {
    let res = unsafe { Cri_Binder_Get_Status.call(binder_id, status) };

    debug_print!(
        "[CriBinderGetStatus] binder_id {binder_id:?}, status {}, call_result: {res:?}",
        unsafe { *status }
    );

    res
}

pub fn register_hook() -> Result<(), Box<dyn std::error::Error>> {
    let pattern = "48 89 5C 24 08 57 48 83 EC 20 48 8B DA 8B F9 85";

    unsafe {
        let parsed = parse_pattern(pattern);

        if let Some(address) = scan_main_module(&parsed) {
            let addr_usize = address as usize;

            debug_print!("[SCANNER] Found CriBinderGetStatus at {:#x}", addr_usize);

            hook!(
                FnCriBinderGetStatus,
                Cri_Binder_Get_Status,
                addr_usize,
                hook_impl
            );
        } else {
            return Err("Could not find pattern for CriBinderGetStatus".into());
        }
    }

    Ok(())
}
