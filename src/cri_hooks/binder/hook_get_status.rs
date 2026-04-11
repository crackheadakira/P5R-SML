use std::fmt;

use retour::static_detour;
use winapi::shared::{minwindef::DWORD, ntdef::INT};

use crate::{hook, utils::logging::debug_print};

const CRI_BINDER_GET_STATUS: usize = 0x14046260c;

static_detour! {
    static Cri_Binder_Get_Status: unsafe extern "system" fn(DWORD, *mut INT) -> CriBinderStatus;
}

type FnCriBinderGetStatus = unsafe extern "system" fn(DWORD, *mut INT) -> CriBinderStatus;

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

impl From<INT> for CriBinderStatus {
    fn from(value: INT) -> Self {
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

impl From<CriBinderStatus> for INT {
    fn from(err: CriBinderStatus) -> Self {
        err as INT
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

pub fn hook_impl(binder_id: DWORD, status: *mut INT) -> CriBinderStatus {
    let res = unsafe { Cri_Binder_Get_Status.call(binder_id, status) };

    debug_print!(
        "[CriBinderGetStatus] binder_id {binder_id:?}, status {}, call_result: {res:?}",
        unsafe { *status }
    );

    res
}

pub fn register_hook() -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        hook!(
            FnCriBinderGetStatus,
            Cri_Binder_Get_Status,
            CRI_BINDER_GET_STATUS,
            hook_impl
        );
    }

    Ok(())
}
