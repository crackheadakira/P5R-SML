use std::os::windows::raw::HANDLE;

use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc, VirtualFree,
};

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SafeHandle(pub HANDLE);

// SAFETY: According to Windows API docs, HANDLEs are thread-safe to send and share.
unsafe impl Send for SafeHandle {}
unsafe impl Sync for SafeHandle {}

pub struct RawAllocator {
    ptr: SafeHandle,
}

unsafe impl Send for RawAllocator {}
unsafe impl Sync for RawAllocator {}

impl RawAllocator {
    pub fn new(size: usize) -> Option<Self> {
        unsafe {
            let ptr = VirtualAlloc(None, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

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
                let _ = VirtualFree(self.ptr.0, 0, MEM_RELEASE);
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
