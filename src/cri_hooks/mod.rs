use winapi::shared::ntdef::INT;

pub mod binder {
    pub mod hook_bind_cpk;
    pub mod hook_bind_file;
    pub mod hook_bind_files;
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

#[macro_export]
macro_rules! hook {
    ($fn_type:ty, $detour:ident, $addr:expr, $handler:ident) => {
        let fn_ptr: $fn_type = std::mem::transmute($addr);
        $detour.initialize(fn_ptr, $handler)?.enable()?;
        debug_print(concat!("[HOOK] ", stringify!($detour), " enabled"));
    };
}

#[repr(i32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CriStatus {
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

impl From<INT> for CriStatus {
    fn from(value: INT) -> Self {
        match value {
            0 => CriStatus::Success,
            -1 => CriStatus::Failure,
            -2 => CriStatus::InvalidParameter,
            -3 => CriStatus::FailedToAllocateMemory,
            -4 => CriStatus::UnsafeFunctionCall,
            -5 => CriStatus::FunctionNotImplemented,
            -6 => CriStatus::LibraryNotInitialized,
            _ => CriStatus::Unknown,
        }
    }
}

impl From<CriStatus> for INT {
    fn from(err: CriStatus) -> Self {
        err as INT
    }
}
