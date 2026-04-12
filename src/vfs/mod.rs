use once_cell::sync::Lazy;
use std::{
    collections::HashMap,
    sync::{
        Mutex, RwLock,
        atomic::{AtomicUsize, Ordering},
    },
};
use windows::{Win32::System::LibraryLoader::GetModuleHandleA, core::PCSTR};

mod allocator;
mod binder;
mod pac;
mod patcher;
mod spd;

pub use allocator::{RawAllocator, SafeHandle};
pub use binder::{BinderCollection, ModFile};
pub use pac::PAC_MODS;
pub use patcher::apply_vfs_patches;
pub use spd::SPD_MODS;

type FnGameAlloc = unsafe extern "system" fn(usize) -> *mut u8;

pub static GAME_ALLOC_PTR: AtomicUsize = AtomicUsize::new(0);

pub static ORIGINAL_CALLBACKS: Lazy<RwLock<HashMap<usize, usize>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

pub static CURRENT_GAME: Lazy<TargetGame> = Lazy::new(|| unsafe {
    if GetModuleHandleA(PCSTR(c"P5R.exe".as_ptr() as *const u8)).is_ok() {
        TargetGame::P5R
    } else if GetModuleHandleA(PCSTR(c"P4G.exe".as_ptr() as *const u8)).is_ok() {
        TargetGame::P4G
    } else {
        TargetGame::Unknown
    }
});

pub static BINDER_COLLECTION: Lazy<Mutex<BinderCollection>> =
    Lazy::new(|| Mutex::new(BinderCollection::new()));

unsafe extern "C" {
    fn _aligned_malloc(size: usize, alignment: usize) -> *mut u8;
}

pub fn game_alloc(size: usize) -> *mut u8 {
    let addr = GAME_ALLOC_PTR.load(Ordering::SeqCst);

    if addr != 0 {
        unsafe {
            let f: FnGameAlloc = std::mem::transmute(addr);
            return f(size);
        }
    }

    unsafe {
        let ptr = _aligned_malloc(size, 16);

        if ptr.is_null() {
            crate::debug_print!(
                "[CRITICAL] _aligned_malloc failed to allocate {} bytes",
                size
            );
        }

        ptr
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetGame {
    P5R,
    P4G,
    Unknown,
}
