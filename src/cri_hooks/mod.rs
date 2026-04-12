pub mod binder {
    pub mod hook_bind_cpk;
    pub mod hook_bind_file;
    pub mod hook_bind_files;
    pub mod hook_find;
    pub mod hook_unbind;

    pub mod hook_get_size_for_bind_files;
    pub mod hook_get_status;
    pub mod hook_set_priority;
}

pub mod io {
    pub mod hook_exists;
    pub mod hook_open;
}

pub mod loader {
    pub mod hook_register_file;
}

pub use crate::cri_hooks::binder::hook_get_status::CriBinderStatus;

#[macro_export]
macro_rules! hook {
    ($fn_type:ty, $detour:ident, $addr:expr, $handler:ident) => {
        let fn_ptr: $fn_type = std::mem::transmute($addr);
        $detour.initialize(fn_ptr, $handler)?.enable()?;
        debug_print!(concat!("[P5R SML] ", stringify!($detour), " enabled"));
    };
}

#[repr(i32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CriError {
    /// Succeeded.
    Success = 0,

    /// General failure.
    Failure = -1,

    /// Invalid argument.
    InvalidParameter = -2,

    /// Failed to allocate memory.
    FailedToAllocateMemory = -3,

    /// Parallel execution of thread-unsafe function.
    UnsafeFunctionCall = -4,

    /// Function not implemented.
    FunctionNotImplemented = -5,

    /// Library not initialized.
    LibraryNotInitialized = -6,

    /// Invalid INT was passed as CriStatus
    Unknown = -7,
}

impl From<i32> for CriError {
    fn from(value: i32) -> Self {
        match value {
            0 => CriError::Success,
            -1 => CriError::Failure,
            -2 => CriError::InvalidParameter,
            -3 => CriError::FailedToAllocateMemory,
            -4 => CriError::UnsafeFunctionCall,
            -5 => CriError::FunctionNotImplemented,
            -6 => CriError::LibraryNotInitialized,
            _ => CriError::Unknown,
        }
    }
}

impl From<CriError> for i32 {
    fn from(err: CriError) -> Self {
        err as i32
    }
}
