use std::ffi::CStr;
use std::sync::Mutex;
use std::{env, path::PathBuf};
use std::{ffi::OsStr, os::windows::ffi::OsStrExt};
use windows::{
    Win32::{
        Foundation::HWND,
        System::Diagnostics::Debug::OutputDebugStringW,
        UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW},
    },
    core::PCWSTR,
};

pub fn get_base_dir() -> PathBuf {
    env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .expect("Failed to get launcher directory")
}

#[macro_export]
#[cfg(debug_assertions)]
macro_rules! debug_print {
    ($($arg:tt)*) => {
            {
                $crate::utils::_debug_print_internal(&format!($($arg)*));
            }
        };
    }

#[macro_export]
#[cfg(not(debug_assertions))]
macro_rules! debug_print {
    ($($arg:tt)*) => {
        ()
    };
}

pub fn _debug_print_internal(msg: &str) {
    let wide: Vec<u16> = std::ffi::OsStr::new(msg)
        .encode_wide()
        .chain(Some(0))
        .collect();
    unsafe {
        OutputDebugStringW(PCWSTR(wide.as_ptr()));
    }
}

/// Shows a MessageBoxW with an error message
pub fn error_message_box(msg: &str, title: &str) {
    let wide_msg: Vec<u16> = OsStr::new(&msg).encode_wide().chain(Some(0)).collect();
    let wide_title: Vec<u16> = OsStr::new(title).encode_wide().chain(Some(0)).collect();

    unsafe {
        MessageBoxW(
            Some(HWND(std::ptr::null_mut())),
            PCWSTR(wide_msg.as_ptr()),
            PCWSTR(wide_title.as_ptr()),
            MB_OK | MB_ICONERROR,
        );
    }
}

pub trait AsRawI8Ptr {
    fn as_raw_i8_ptr(&self) -> *const i8;
}

impl AsRawI8Ptr for windows::core::PSTR {
    fn as_raw_i8_ptr(&self) -> *const i8 {
        self.as_ptr() as _
    }
}

impl AsRawI8Ptr for windows::core::PCSTR {
    fn as_raw_i8_ptr(&self) -> *const i8 {
        self.as_ptr() as _
    }
}

impl AsRawI8Ptr for *const i8 {
    fn as_raw_i8_ptr(&self) -> *const i8 {
        *self
    }
}

impl AsRawI8Ptr for *mut i8 {
    fn as_raw_i8_ptr(&self) -> *const i8 {
        *self as _
    }
}

impl AsRawI8Ptr for *mut u8 {
    fn as_raw_i8_ptr(&self) -> *const i8 {
        *self as _
    }
}

pub unsafe fn pstr_to_string<T: AsRawI8Ptr>(ptr: T) -> String {
    let raw_ptr = ptr.as_raw_i8_ptr();
    if raw_ptr.is_null() {
        return String::new();
    }

    unsafe { CStr::from_ptr(raw_ptr).to_string_lossy().into_owned() }
}

pub fn lock_or_log<'a, T>(mutex: &'a Mutex<T>, context: &str) -> std::sync::MutexGuard<'a, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            crate::debug_print!("[MUTEX POISONED] {context} mutex was poisoned");
            poisoned.into_inner()
        }
    }
}
