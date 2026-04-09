use std::{env, path::PathBuf};

use winapi::{
    shared::ntdef::HANDLE,
    um::{
        memoryapi::{VirtualAlloc, VirtualFree},
        winnt::{MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE},
    },
};

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SafeHandle(pub HANDLE);

// SAFETY: According to Windows API docs, HANDLEs are thread-safe to send and share.
unsafe impl Send for SafeHandle {}
unsafe impl Sync for SafeHandle {}

pub fn get_base_dir() -> PathBuf {
    env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .expect("Failed to get launcher directory")
}

pub struct RawAllocator {
    ptr: SafeHandle,
}

unsafe impl Send for RawAllocator {}
unsafe impl Sync for RawAllocator {}

impl RawAllocator {
    pub fn new(size: usize) -> Option<Self> {
        unsafe {
            let ptr = VirtualAlloc(
                std::ptr::null_mut(),
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            );

            if ptr.is_null() {
                None
            } else {
                Some(Self {
                    ptr: SafeHandle(ptr),
                })
            }
        }
    }

    pub fn as_ptr(&self) -> SafeHandle {
        self.ptr
    }

    pub fn dispose(&mut self) {
        unsafe {
            if !self.ptr.0.is_null() {
                VirtualFree(self.ptr.0, 0, MEM_RELEASE);
                self.ptr = SafeHandle(std::ptr::null_mut());
            }
        }
    }
}

impl Drop for RawAllocator {
    fn drop(&mut self) {
        self.dispose();
    }
}

pub mod logging {
    use std::{ffi::OsStr, os::windows::ffi::OsStrExt};

    use windows::{
        Win32::{
            Foundation::HWND,
            System::Diagnostics::Debug::OutputDebugStringW,
            UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW},
        },
        core::PCWSTR,
    };

    /// Prints to DebugView (OutputDebugStringW)
    pub fn debug_print(msg: &str) {
        let wide: Vec<u16> = OsStr::new(msg).encode_wide().chain(Some(0)).collect();
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
}
